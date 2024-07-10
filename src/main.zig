const std = @import("std");
const builtin = @import("builtin");

const Sha256 = std.crypto.hash.sha2.Sha256;
// Init scoped logger.
const log = std.log.scoped(.main);

// Init our custom logger handler.
pub const std_options = .{
    .log_level = .debug,
    .logFn = logFn,
};

const hash_length = Sha256.digest_length;
const nonce_length: usize = 256;

const complexity_type = u8;
const min_complexity: complexity_type = 1;

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
    hash: [hash_length]u8,
    prev_hash: [hash_length]u8,
    timestamp: i64,
    complexity: complexity_type,
    nonce: [nonce_length]u8,

    fn fields_size() comptime_int {
        return comptime @sizeOf(u128) +
            hash_length +
            hash_length +
            @sizeOf(i64) +
            @sizeOf(complexity_type) +
            nonce_length;
    }

    fn to_bytes(self: Block) [fields_size()]u8 {
        var buf = [_]u8{0} ** fields_size();

        const self_index_fr = 0;
        const self_index_to = self_index_fr + @sizeOf(u128);
        std.mem.writeInt(u128, buf[self_index_fr..self_index_to], self.index, .little);

        const self_hash_fr = self_index_to;
        const self_hash_to = self_hash_fr + hash_length;
        @memcpy(buf[self_hash_fr..self_hash_to], &self.hash);

        const self_prev_hash_fr = self_hash_to;
        const self_prev_hash_to = self_prev_hash_fr + hash_length;
        @memcpy(buf[self_prev_hash_fr..self_prev_hash_to], &self.prev_hash);

        const self_timestamp_fr = self_prev_hash_to;
        const self_timestamp_to = self_timestamp_fr + @sizeOf(i64);
        std.mem.writeInt(i64, buf[self_timestamp_fr..self_timestamp_to], self.timestamp, .little);

        const self_complexity_fr = self_timestamp_to;
        const self_complexity_to = self_complexity_fr + @sizeOf(complexity_type);
        std.mem.writeInt(complexity_type, buf[self_complexity_fr..self_complexity_to], self.complexity, .little);

        const self_nonce_fr = self_complexity_to;
        const self_nonce_to = self_nonce_fr + nonce_length;
        @memcpy(buf[self_nonce_fr..self_nonce_to], &self.nonce);

        return buf;
    }

    fn to_hash(self: *Block) [Sha256.digest_length]u8 {
        var hasher = Sha256.init(.{});
        const block_bytes = self.to_bytes();
        hasher.update(&block_bytes);
        const hash = hasher.finalResult();
        self.hash = hash;
        return hash;
    }

    fn verify(self: *Block, prev_block: Block) error{HashesNotEqual}!void {
        const hash = self.to_hash();
        if (!std.mem.eql(u8, &self.hash, &hash)) return error.HashesNotEqual;
        if (!std.mem.eql(u8, &self.prev_hash, &prev_block.hash)) return error.HashesNotEqual;
        if (self.index - 1 != prev_block.index) return error.HashesNotEqual;
    }

    fn is_hash_empty(self: Block) bool {
        return std.mem.eql(u8, &[_]u8{0} ** hash_length, &self.hash);
    }
};

pub fn main() !void {
    switch (builtin.os.tag) {
        .macos => {},
        else => {
            log.err("at the moment software is not working on any system except macOS", .{});
            return;
        },
    }

    const allocator = std.heap.page_allocator;

    var rnd = std.rand.DefaultPrng.init(0);

    var blocks = std.ArrayList(Block).init(allocator);
    defer blocks.deinit();
    // Init genesis block.
    var genesis = Block{
        .index = 0,
        .hash = [_]u8{0} ** hash_length,
        .prev_hash = [_]u8{0} ** hash_length,
        .timestamp = std.time.milliTimestamp(),
        .complexity = 0,
        .nonce = [_]u8{0} ** nonce_length,
    };
    // To set genesis.hash.
    _ = genesis.to_hash();
    try blocks.append(genesis);

    var state = State{ .blocks = blocks };

    const http_server_thread = try std.Thread.spawn(.{}, http_server, .{});
    const tcp_server_thread = try std.Thread.spawn(.{}, tcp_server, .{});
    const mining_loop_thread = try std.Thread.spawn(.{}, mining_loop, .{
        @as(*std.rand.Xoshiro256, &rnd),
        @as(*State, &state),
    });
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

    log.debug("current blocks length is {d} and last index is {d}", .{
        state.blocks.items.len,
        state.blocks.getLast().index,
    });
    std.debug.assert(state.blocks.items.len - 1 == state.blocks.getLast().index);

    log.info("finally successfully exiting...", .{});
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

fn mining_loop(rnd: *std.rand.Xoshiro256, state: *State) !void {
    log.info("starting mining loop", .{});
    var nonce: [nonce_length]u8 = [_]u8{0} ** nonce_length;
    while (should_wait()) {
        // Indicate that we found new hash with required complexity.
        var new_hash_found = false;
        var new_block: Block = undefined;
        while (should_wait()) {
            std.time.sleep(10_000_000); // 10ms
            fill_buf_random(rnd, &nonce);
            const prev_block = state.blocks.getLast();
            new_block = Block{
                .index = prev_block.index + 1,
                .hash = [_]u8{0} ** hash_length,
                .prev_hash = prev_block.hash,
                .timestamp = std.time.milliTimestamp(),
                .complexity = min_complexity,
                .nonce = nonce,
            };
            // To set new_block.hash.
            const new_hash = new_block.to_hash();
            var hash_zeros_count: complexity_type = 0;
            for (new_hash, 0..) |byte, i| {
                if (byte == 0) {
                    hash_zeros_count = @as(complexity_type, @intCast(i + 1));
                    continue;
                }
                break;
            }
            if (hash_zeros_count == new_block.complexity) {
                new_hash_found = true;
                break;
            }
            try new_block.verify(prev_block);
        }
        // We need additional check there,
        // because if SIGTERM received we exit loop with new block mining.
        if (new_hash_found) {
            log.debug("new block is found\n{any}", .{new_block});
            try state.blocks.append(new_block);
        }
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
        std.time.sleep(5_000_000); // 5ms
    }
    return wait_signal_state;
}

fn fill_buf_random(rnd: *std.rand.Xoshiro256, nonce: *[nonce_length]u8) void {
    for (0..nonce_length) |i| {
        nonce[i] = rnd.random().int(u8);
    }
}

fn logFn(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    // Print the message to stderr, silently ignoring any errors.
    std.debug.lockStdErr();
    defer std.debug.unlockStdErr();
    const stderr = std.io.getStdErr().writer();
    nosuspend stderr.print(
        "{d} " ++ "[" ++ comptime level.asText() ++ "] " ++ "(" ++ @tagName(scope) ++ ") " ++ format ++ "\n",
        .{std.time.milliTimestamp()} ++ args,
    ) catch return;
}

test "test_block_encoding" {
    const index = 102_000_882_000_511;
    const block = Block{
        .index = index,
        .hash = [_]u8{1} ** hash_length,
        .prev_hash = [_]u8{2} ** hash_length,
        .timestamp = std.time.milliTimestamp(),
        .complexity = 243,
        .nonce = [_]u8{3} ** nonce_length,
    };
    const block_bytes = block.to_bytes();
    try std.testing.expect(std.mem.eql(
        u8,
        block_bytes[0..16],
        &[16]u8{ 127, 162, 86, 238, 196, 92, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    ));
    try std.testing.expect(std.mem.readInt(u128, block_bytes[0..16], .little) == index);
}

test "test_block_hash" {
    const index = 102_000_882_000_511;
    var block = Block{
        .index = index,
        .hash = [_]u8{1} ** hash_length,
        .prev_hash = [_]u8{2} ** hash_length,
        .timestamp = std.time.milliTimestamp(),
        .complexity = 243,
        .nonce = [_]u8{3} ** nonce_length,
    };
    try std.testing.expect(!block.is_hash_empty());
    block.hash = [_]u8{0} ** hash_length;
    // Execute it to have block.hash is not default but calculated.
    const hash_1 = block.to_hash();
    try std.testing.expect(!std.mem.eql(u8, &[_]u8{1} ** hash_length, &block.hash));
    // Reset hash to not use calculated hash in a new calculation.
    block.hash = [_]u8{0} ** hash_length;
    try std.testing.expect(block.is_hash_empty());
    // Hashes should be equal every time.
    const hash_2 = block.to_hash();
    try std.testing.expect(std.mem.eql(u8, &hash_1, &hash_2));
}
