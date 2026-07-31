//! Idle inhibitor with native D-Bus + systemd-inhibit.
//!
//! A helper process keeps the target user's D-Bus connection alive for the
//! full inhibition lifetime. systemd-inhibit provides independent coverage.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const otter_utils = @import("otter_utils");
const Screensaver = @import("otter_desktop").Screensaver;
const scanner = @import("scanner.zig");
const log = std.log.scoped(.inhibitor);

const Self = @This();
pub const helper_arg = "--screensaver-inhibit-helper";

allocator: std.mem.Allocator,
dbus_process: ?std.process.Child = null,
target_uid: ?u32 = null,
systemd_pid: ?posix.pid_t = null,

pub fn init(allocator: std.mem.Allocator) Self {
    return .{ .allocator = allocator };
}

pub fn deinit(self: *Self) void {
    self.uninhibit();
}

pub fn inhibit(self: *Self, app_name: []const u8, reason: []const u8, pid: u32) void {
    var any_success = false;

    if (self.target_uid == null and pid != 0) {
        self.target_uid = scanner.findUserForProcess(pid);
    }

    if (self.dbus_process == null) {
        if (self.inhibitDBus(app_name, reason)) |child| {
            self.dbus_process = child;
            any_success = true;
        } else |err| {
            log.warn("D-Bus screensaver inhibit failed: {}", .{err});
        }
    } else {
        any_success = true;
    }

    if (self.systemd_pid == null) {
        self.inhibitLogin1(app_name, reason) catch |err| {
            log.warn("systemd-inhibit failed: {}", .{err});
        };
        if (self.systemd_pid != null) {
            any_success = true;
        }
    }

    if (!any_success) {
        log.warn("all inhibit methods failed", .{});
    }
}

pub fn uninhibit(self: *Self) void {
    if (self.dbus_process) |*child| {
        if (child.id) |pid| {
            posix.kill(pid, posix.SIG.TERM) catch |err| {
                if (err != error.ProcessNotFound) {
                    log.warn("failed to stop D-Bus inhibit helper {d}: {}", .{ pid, err });
                }
            };
        }
        _ = child.wait(otter_utils.io.get()) catch |err| {
            log.warn("failed to reap D-Bus inhibit helper: {}", .{err});
        };
        self.dbus_process = null;
    }

    if (self.systemd_pid) |pid| {
        // SIGKILL because SIGTERM is blocked (inherited from signalfd mask)
        posix.kill(pid, posix.SIG.KILL) catch |err| {
            if (err != error.ProcessNotFound) {
                log.warn("failed to kill systemd-inhibit pid {d}: {}", .{ pid, err });
            }
        };
        var status: c_int = 0;
        _ = std.posix.system.waitpid(pid, &status, 0);
        self.systemd_pid = null;
    }

    self.target_uid = null;
}

pub fn isInhibited(self: *const Self) bool {
    return self.dbus_process != null or self.systemd_pid != null;
}

// ── D-Bus ───────────────────────────────────────────────────────────────

fn inhibitDBus(self: *Self, app_name: []const u8, reason: []const u8) !std.process.Child {
    var arena = std.heap.ArenaAllocator.init(self.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const io = otter_utils.io.get();

    var argv: std.ArrayListUnmanaged([]const u8) = .empty;

    if (posix.system.geteuid() == 0) {
        const uid = self.target_uid orelse return error.NoTargetUser;
        try argv.append(alloc, "sudo");
        try argv.append(alloc, "-u");
        try argv.append(alloc, try std.fmt.allocPrint(alloc, "#{d}", .{uid}));
        try argv.append(alloc, "env");
        try argv.append(alloc, try std.fmt.allocPrint(
            alloc,
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{d}/bus",
            .{uid},
        ));
        try argv.append(alloc, try std.fmt.allocPrint(alloc, "XDG_RUNTIME_DIR=/run/user/{d}", .{uid}));
    }

    var exe_buf: [std.fs.max_path_bytes]u8 = undefined;
    const exe_len = try std.Io.Dir.cwd().readLink(io, "/proc/self/exe", &exe_buf);
    try argv.appendSlice(alloc, &.{ exe_buf[0..exe_len], helper_arg, app_name, reason });

    var child = try std.process.spawn(io, .{
        .argv = argv.items,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .inherit,
    });
    errdefer child.kill(io);

    const stdout = child.stdout orelse return error.HelperFailed;
    var ready: [1]u8 = undefined;
    const n = stdout.readStreaming(io, &.{&ready}) catch 0;
    stdout.close(io);
    child.stdout = null;
    if (n != 1 or ready[0] != 1) {
        _ = try child.wait(io);
        return error.HelperFailed;
    }

    log.info("screensaver inhibited (helper={?d}, uid={?})", .{ child.id, self.target_uid });
    return child;
}

pub fn runHelper(allocator: std.mem.Allocator, app_name: [:0]const u8, reason: [:0]const u8) !void {
    var mask = posix.sigemptyset();
    posix.sigaddset(&mask, posix.SIG.TERM);
    posix.sigaddset(&mask, posix.SIG.INT);
    posix.sigaddset(&mask, posix.SIG.HUP);
    posix.sigprocmask(posix.SIG.BLOCK, &mask, null);

    const parent = posix.getppid();
    _ = try posix.prctl(.SET_PDEATHSIG, .{@as(usize, @intFromEnum(posix.SIG.TERM))});
    if (posix.getppid() != parent) return;

    const signal_fd = try posix.signalfd(-1, &mask, linux.SFD.CLOEXEC);
    defer _ = posix.system.close(signal_fd);

    var screensaver = try Screensaver.init(allocator);
    defer screensaver.deinit();
    _ = try screensaver.inhibit(app_name, reason);
    try std.Io.File.stdout().writeStreamingAll(otter_utils.io.get(), &.{1});

    var info: linux.signalfd_siginfo = undefined;
    const n = try posix.read(signal_fd, std.mem.asBytes(&info));
    if (n != @sizeOf(linux.signalfd_siginfo)) return error.ShortRead;
}

// ── systemd-inhibit ─────────────────────────────────────────────────────

fn inhibitLogin1(self: *Self, app_name: []const u8, reason: []const u8) !void {
    const who_arg = try std.fmt.allocPrint(self.allocator, "--who={s}", .{app_name});
    defer self.allocator.free(who_arg);

    const why_arg = try std.fmt.allocPrint(self.allocator, "--why={s}", .{reason});
    defer self.allocator.free(why_arg);

    const argv = [_][]const u8{
        "systemd-inhibit",
        "--what=idle",
        who_arg,
        why_arg,
        "--mode=block",
        "sleep",
        "infinity",
    };

    const child = try std.process.spawn(otter_utils.io.get(), .{
        .argv = &argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    self.systemd_pid = child.id;
    log.info("started systemd-inhibit (pid {?d})", .{child.id});
}
