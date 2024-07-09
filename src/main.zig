const std = @import("std");
const builtin = @import("builtin");

const logger = @import("logger.zig");

// Init scoped logger.
const log = std.log.scoped(.main);

// Init our custom logger handler.
pub const std_options = .{
    .log_level = .debug,
    .logFn = logger.logFn,
};

const block_hash_length = std.crypto.hash.sha2.Sha256.digest_length;
const nonce_length: usize = 256;

// We use it to wait in threads loops until os signal will be received.
// Note: in case of using two variables to wait for os signal: for example we are using separate bool variable and a mutex,
// so we need to wait for this bool variable changes in main function (thread) in the separate thread,
// otherwise deadlock, because mutex will be acquired in the same thread.
var wait_signal = std.atomic.Value(bool).init(true);

fn handle_signal(
    signal: i32,
    _: *const std.posix.siginfo_t,
    _: ?*anyopaque,
) callconv(.C) void {
    log.debug("os signal received: {d}", .{signal});
    wait_signal.store(false, std.builtin.AtomicOrder.monotonic);
}

const State = struct {
    blocks: std.ArrayList(Block),
};

const Block = struct {
    index: u128,
    hash: [block_hash_length]u8,
    prev_hash: [block_hash_length]u8,
    timestamp: i64,
    complexity: u8,
    nonce: [nonce_length]u8,
};

pub fn main() !void {
    switch (builtin.os.tag) {
        .macos => {},
        else => {
            log.err("at the moment software is not working on any system except macOS", .{});
            return;
        },
    }

    var rnd = std.rand.DefaultPrng.init(0);

    const http_server_thread = try std.Thread.spawn(.{}, http_server, .{});
    const tcp_server_thread = try std.Thread.spawn(.{}, tcp_server, .{});
    const mining_loop_thread = try std.Thread.spawn(.{}, mining_loop, .{@as(*std.rand.Xoshiro256, &rnd)});
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

fn mining_loop(rnd: *std.rand.Xoshiro256) !void {
    log.info("starting mining loop", .{});
    const allocator = std.heap.page_allocator;
    const nonce = try allocator.alloc(u8, nonce_length);
    defer allocator.free(nonce);
    while (should_wait()) {
        fill_buf(rnd, nonce);
        log.debug("new nonce generated {any}", .{nonce});
    }
    log.info("mining loop stopped", .{});
}

fn broadcast_loop() void {
    log.info("starting broadcast loop", .{});
    while (should_wait()) {}
    log.info("broadcast loop stopped", .{});
}

fn should_wait() bool {
    const wait_signal_state = wait_signal.load(std.builtin.AtomicOrder.monotonic);
    if (wait_signal_state) {
        // To not overload cpu.
        std.time.sleep(1_000_000_000); // 1s
    }
    return wait_signal_state;
}

fn fill_buf(rand: *std.rand.Xoshiro256, buf: []u8) void {
    rand.random().bytes(buf);
}
