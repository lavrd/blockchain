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

const complexity = u8;
const min_complexity: complexity = 1;

// We use it to wait in threads loops until os signal will be received.
// Note: in case of using two variables to wait for os signal: for example we are using separate bool variable and a mutex,
// so we need to wait for this bool variable changes in main function (thread) in the separate thread,
// otherwise deadlock, because mutex will be acquired in the same thread.
var wait_signal = std.atomic.Value(bool).init(true);

fn handleSignal(
    signal: i32,
    _: *const std.posix.siginfo_t,
    _: ?*anyopaque,
) callconv(.C) void {
    log.debug("os signal received: {d}", .{signal});
    wait_signal.store(false, std.builtin.AtomicOrder.monotonic);
}

const State = struct {
    blocks: std.ArrayList(Block),
    mining_enabled: bool,
    new_block_ch: Channel(Block),
    // Currently our cluster can contain up to 7 nodes.
    // So current node + 6 peers.
    nodes: [6]std.net.Ip4Address,
};

const Block = struct {
    index: u128,
    hash: [hash_length]u8,
    prev_hash: [hash_length]u8,
    timestamp: i64,
    complexity: complexity,
    nonce: [nonce_length]u8,

    fn size() comptime_int {
        return comptime @sizeOf(u128) +
            hash_length +
            hash_length +
            @sizeOf(i64) +
            @sizeOf(complexity) +
            nonce_length;
    }

    fn toBytes(self: Block) [size()]u8 {
        var buf = [_]u8{0} ** size();

        const index_from = 0;
        const index_to = index_from + @sizeOf(u128);
        std.mem.writeInt(u128, buf[index_from..index_to], self.index, .little);

        const hash_from = index_to;
        const hash_to = hash_from + hash_length;
        @memcpy(buf[hash_from..hash_to], &self.hash);

        const prev_hash_from = hash_to;
        const prev_hash_to = prev_hash_from + hash_length;
        @memcpy(buf[prev_hash_from..prev_hash_to], &self.prev_hash);

        const timestamp_from = prev_hash_to;
        const timestamp_to = timestamp_from + @sizeOf(i64);
        std.mem.writeInt(i64, buf[timestamp_from..timestamp_to], self.timestamp, .little);

        const complexity_from = timestamp_to;
        const complexity_to = complexity_from + @sizeOf(complexity);
        std.mem.writeInt(complexity, buf[complexity_from..complexity_to], self.complexity, .little);

        const nonce_from = complexity_to;
        const nonce_to = nonce_from + nonce_length;
        @memcpy(buf[nonce_from..nonce_to], &self.nonce);

        return buf;
    }

    fn toHash(self: *Block) [Sha256.digest_length]u8 {
        var hasher = Sha256.init(.{});
        const block_bytes = self.toBytes();
        hasher.update(&block_bytes);
        const hash = hasher.finalResult();
        self.hash = hash;
        return hash;
    }

    fn verify(self: *Block, prev_block: Block, current_complexity: complexity) error{
        HashesNotEqual,
        ComplexityMismatch,
        TimestampTooEarly,
    }!void {
        const hash = self.toHash();
        if (!std.mem.eql(u8, &self.hash, &hash)) return error.HashesNotEqual;
        if (!std.mem.eql(u8, &self.prev_hash, &prev_block.hash)) return error.HashesNotEqual;
        if (self.index - 1 != prev_block.index) return error.HashesNotEqual;
        if (self.complexity != current_complexity) return error.ComplexityMismatch;
        if (self.timestamp <= prev_block.timestamp) return error.TimestampTooEarly;
    }

    fn isHashEmpty(self: Block) bool {
        return std.mem.eql(u8, &[_]u8{0} ** hash_length, &self.hash);
    }
};

fn Channel(comptime T: type) type {
    return struct {
        const Self = @This();

        raw: ?T,
        mutex: std.Thread.Mutex,

        fn Init(value: ?T) Self {
            return .{
                .raw = value,
                .mutex = .{},
            };
        }

        fn send(self: *Self, data: T) void {
            self.mutex.lock();
            self.raw = data;
            self.mutex.unlock();
        }

        fn receive(
            self: *Self,
        ) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.raw) |raw| {
                self.raw = null;
                return raw;
            }
            return null;
        }
    };
}

pub fn main() !void {
    switch (builtin.os.tag) {
        .macos, .linux => {},
        else => {
            log.err("at the moment software is not working on any system except macOS or Linux", .{});
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
    _ = genesis.toHash();
    try blocks.append(genesis);

    var envs = try std.process.getEnvMap(allocator);
    var mining_enabled = false;
    if (envs.get("MINING")) |val| {
        if (std.mem.eql(u8, val, "1")) mining_enabled = true;
    }
    var nodes: [6]std.net.Ip4Address = [_]std.net.Ip4Address{undefined} ** 6;
    if (envs.get("NODES")) |val| {
        var node_index: usize = 0;
        var nodes_iter = std.mem.split(u8, val, ",");
        while (nodes_iter.next()) |node| {
            var node_iter = std.mem.split(u8, node, ":");
            const raw_ip = node_iter.next().?;
            const raw_port = node_iter.next().?;
            const port: u16 = std.fmt.parseInt(u16, raw_port, 10) catch |err| {
                log.err("failed to parse node port: {s}: {any}", .{ raw_port, err });
                continue;
            };
            if (node_iter.rest().len != 0) {
                log.err(
                    "failed to parse node address; some data left after split: {s}:{s}",
                    .{ raw_ip, raw_port },
                );
                continue;
            }
            const address = std.net.Ip4Address.parse(raw_ip, port) catch |err| {
                log.err("failed to parse node address: {s}:{d}: {any}", .{ raw_ip, port, err });
                continue;
            };
            nodes[node_index] = address;
            log.debug("load {any} node address to communicate", .{address});
            node_index += 1;
        }
    }
    envs.deinit();

    var state = State{
        .blocks = blocks,
        .mining_enabled = mining_enabled,
        .new_block_ch = Channel(Block).Init(null),
        .nodes = nodes,
    };

    const http_server_thread = try std.Thread.spawn(.{}, httpServer, .{});
    const udp_server_thread = try std.Thread.spawn(.{}, udpServer, .{});
    const mining_loop_thread = try std.Thread.spawn(.{}, miningLoop, .{
        @as(*std.rand.Xoshiro256, &rnd),
        @as(*State, &state),
    });
    const broadcast_loop_thread = try std.Thread.spawn(.{}, broadcastLoop, .{
        @as(*State, &state),
    });

    var act = std.posix.Sigaction{
        .handler = .{ .sigaction = handleSignal },
        .mask = std.posix.empty_sigset,
        .flags = (std.posix.SA.SIGINFO),
    };
    var oact: std.posix.Sigaction = undefined;
    try std.posix.sigaction(std.posix.SIG.INT, &act, &oact);
    waitSignalLoop();

    // Waiting for other threads to be stopped.
    http_server_thread.join();
    udp_server_thread.join();
    mining_loop_thread.join();
    broadcast_loop_thread.join();

    log.debug("current blocks length is {d}", .{state.blocks.items.len});
    std.debug.assert(state.blocks.items.len - 1 == state.blocks.getLast().index);

    log.info("finally successfully exiting...", .{});
}

fn waitSignalLoop() void {
    log.info("starting to wait for os signal", .{});
    while (shouldWait()) {}
    log.info("exiting os signal waiting loop", .{});
}

fn httpServer() void {
    log.info("starting http server", .{});
    while (shouldWait()) {}
    log.info("http server stopped", .{});
}

fn udpServer() !void {
    log.info("starting udp server", .{});

    // Initialize UDP server socket and bind an address.
    const socket = try std.posix.socket(
        std.posix.AF.INET,
        std.posix.SOCK.DGRAM | std.posix.SOCK.NONBLOCK,
        std.posix.IPPROTO.UDP,
    );
    defer std.posix.close(socket);
    const port: u16 = 44600;
    const addr = try std.net.Address.parseIp("127.0.0.1", port);
    try std.posix.bind(socket, &addr.any, addr.getOsSockLen());

    log.debug("udp server initialized; wait for new data on {d}", .{port});

    var buffer: [1024]u8 = undefined;
    var from_addr: std.posix.sockaddr = undefined;
    var from_addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
    while (shouldWait()) {
        const n = std.posix.recvfrom(
            socket,
            buffer[0..],
            0,
            &from_addr,
            &from_addr_len,
        ) catch |e| switch (e) {
            error.WouldBlock => continue,
            else => return e,
        };
        const buf = buffer[0..n];
        log.debug("received new data from {any}: {any}", .{ from_addr, buf });
        _ = try std.posix.sendto(
            socket,
            buf,
            0,
            &from_addr,
            from_addr_len,
        );
    }

    log.info("udp server stopped", .{});
}

fn miningLoop(rnd: *std.rand.Xoshiro256, state: *State) !void {
    if (!state.mining_enabled) {
        log.info("mining loop is not started as mining is not enabled", .{});
        return;
    }
    log.info("starting mining loop", .{});
    var nonce: [nonce_length]u8 = [_]u8{0} ** nonce_length;
    while (shouldWait()) {
        // Indicate that we found new hash with required complexity.
        var hash_found = false;
        var block: Block = undefined;
        while (shouldWait()) {
            std.time.sleep(std.time.ns_per_ms * 10); // 10ms
            fillBufRandom(rnd, &nonce);
            const prev_block = state.blocks.getLast();
            block = Block{
                .index = prev_block.index + 1,
                .hash = [_]u8{0} ** hash_length,
                .prev_hash = prev_block.hash,
                .timestamp = std.time.milliTimestamp(),
                .complexity = min_complexity,
                .nonce = nonce,
            };
            // To set new_block.hash.
            const hash = block.toHash();
            var hash_leading_zeros: complexity = 0;
            for (hash, 0..) |byte, i| {
                if (byte == 0) {
                    hash_leading_zeros = @as(complexity, @intCast(i + 1));
                    continue;
                }
                break;
            }
            if (hash_leading_zeros == block.complexity) {
                hash_found = true;
                break;
            }
            try block.verify(prev_block, min_complexity);
        }
        // We need additional check there,
        // because if SIGTERM received we exit loop with new block mining.
        if (hash_found) {
            try state.blocks.append(block);
            state.new_block_ch.send(block);
        }
    }
    log.info("mining loop stopped", .{});
}

fn broadcastLoop(state: *State) void {
    log.info("starting broadcast loop", .{});
    while (shouldWait()) {
        if (state.new_block_ch.receive()) |block| {
            log.debug("new block is found\n{any}", .{block});
        }
    }
    log.info("broadcast loop stopped", .{});
}

fn shouldWait() bool {
    const wait_signal_state = wait_signal.load(std.builtin.AtomicOrder.monotonic);
    if (wait_signal_state) {
        // To not overload cpu.
        std.time.sleep(std.time.ns_per_ms * 5); // 5ms
    }
    return wait_signal_state;
}

fn fillBufRandom(rnd: *std.rand.Xoshiro256, nonce: *[nonce_length]u8) void {
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
    const block_bytes = block.toBytes();
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
    try std.testing.expect(!block.isHashEmpty());
    block.hash = [_]u8{0} ** hash_length;
    // Execute it to have block.hash is not default but calculated.
    const hash_1 = block.toHash();
    try std.testing.expect(!std.mem.eql(u8, &[_]u8{1} ** hash_length, &block.hash));
    // Reset hash to not use calculated hash in a new calculation.
    block.hash = [_]u8{0} ** hash_length;
    try std.testing.expect(block.isHashEmpty());
    // Hashes should be equal every time.
    const hash_2 = block.toHash();
    try std.testing.expect(std.mem.eql(u8, &hash_1, &hash_2));
}
