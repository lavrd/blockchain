const std = @import("std");
const builtin = @import("builtin");

const logger = @import("logger.zig");

const log = std.log.scoped(.main);

// Init our custom logger handler.
pub const std_options = .{
    .log_level = .debug,
    .logFn = logger.logFn,
};

// We use it to wait until os signal will be received.
// Note: in case of using two variable to wait: separate bool variable and a mutex, for example,
// you need to for this bool variable in main in the separate thread otherwise deadlock, because
// mutex will be acquired in the same thread.
var wait_signal = std.atomic.Value(bool).init(true);

fn handle_signal(
    signal: i32,
    _: *const std.posix.siginfo_t,
    _: ?*anyopaque,
) callconv(.C) void {
    log.debug("os signal received: {d}", .{signal});
    wait_signal.store(false, std.builtin.AtomicOrder.monotonic);
}

pub fn main() !void {
    switch (builtin.os.tag) {
        .macos => {},
        else => {
            log.err("at the moment software is not working on any system except macOS", .{});
            return;
        },
    }

    const http_server_thread = try std.Thread.spawn(.{}, http_server, .{});
    const tcp_server_thread = try std.Thread.spawn(.{}, tcp_server, .{});
    const mining_loop_thread = try std.Thread.spawn(.{}, mining_loop, .{});
    const broadcast_loop_thread = try std.Thread.spawn(.{}, broadcast_loop, .{});

    var act = std.posix.Sigaction{
        .handler = .{ .sigaction = handle_signal },
        .mask = std.posix.empty_sigset,
        .flags = (std.posix.SA.SIGINFO),
    };
    var oact: std.posix.Sigaction = undefined;
    try std.posix.sigaction(std.posix.SIG.INT, &act, &oact);

    wait_signal_loop();

    // Waiting for other threads to be stopped.
    http_server_thread.join();
    tcp_server_thread.join();
    mining_loop_thread.join();
    broadcast_loop_thread.join();

    log.info("final successfully exiting...", .{});
}

fn wait_signal_loop() void {
    log.info("starting to wait for os signal", .{});
    while (should_wait()) {}
    log.info("exiting os signal waiting loop", .{});
}

fn http_server() void {
    log.info("starting http server", .{});
    while (should_wait()) {}
    log.info("http server stopped", .{});
}

fn tcp_server() void {
    log.info("starting tcp server", .{});
    while (should_wait()) {}
    log.info("tcp server stopped", .{});
}

fn mining_loop() void {
    log.info("starting mining loop", .{});
    while (should_wait()) {}
    log.info("mining loop stopped", .{});
}

fn broadcast_loop() void {
    log.info("starting broadcast loop", .{});
    while (should_wait()) {}
    log.info("broadcast loop stopped", .{});
}

fn should_wait() bool {
    return wait_signal.load(std.builtin.AtomicOrder.monotonic);
}
