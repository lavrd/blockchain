const std = @import("std");
const builtin = @import("builtin");
const time = @cImport(@cInclude("time.h"));

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

const rpc_packet_event_type = u8;

const RpcPacketEvent = enum(rpc_packet_event_type) {
    NewBlock = 1,
    BlockApproved = 2,
};

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
    blocks: TSArrayList(Block),
    mining_enabled: bool,
    mined_block_ch: Channel(Block),
    rpc_packet_ch: Channel(RpcPacketExt),
    // Currently our cluster can contain up to 7 nodes.
    // So current node + 6 peers.
    nodes: [6]std.net.Address,
};

const Block = struct {
    const Self = @This();

    index: u128,
    hash: [hash_length]u8,
    prev_hash: [hash_length]u8,
    timestamp: i64,
    complexity: complexity_type,
    nonce: [nonce_length]u8,

    fn size() comptime_int {
        return comptime @sizeOf(u128) +
            hash_length +
            hash_length +
            @sizeOf(i64) +
            @sizeOf(complexity_type) +
            nonce_length;
    }

    fn encode(self: *const Self) [size()]u8 {
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
        const complexity_to = complexity_from + @sizeOf(complexity_type);
        std.mem.writeInt(complexity_type, buf[complexity_from..complexity_to], self.complexity, .little);

        const nonce_from = complexity_to;
        const nonce_to = nonce_from + nonce_length;
        @memcpy(buf[nonce_from..nonce_to], &self.nonce);

        return buf;
    }

    fn decode(buf: *const [size()]u8) Self {
        const index_from = 0;
        const index_to = index_from + @sizeOf(u128);
        const index = std.mem.readInt(u128, buf[index_from..index_to], .little);

        const hash_from = index_to;
        const hash_to = hash_from + hash_length;
        var hash: [hash_length]u8 = [_]u8{0} ** hash_length;
        @memcpy(&hash, buf[hash_from..hash_to]);

        const prev_hash_from = hash_to;
        const prev_hash_to = prev_hash_from + hash_length;
        var prev_hash = [_]u8{0} ** hash_length;
        @memcpy(&prev_hash, buf[prev_hash_from..prev_hash_to]);

        const timestamp_from = prev_hash_to;
        const timestamp_to = timestamp_from + @sizeOf(i64);
        const timestamp = std.mem.readInt(i64, buf[timestamp_from..timestamp_to], .little);

        const complexity_from = timestamp_to;
        const complexity_to = complexity_from + @sizeOf(complexity_type);
        const complexity = std.mem.readInt(complexity_type, buf[complexity_from..complexity_to], .little);

        const nonce_from = complexity_to;
        const nonce_to = nonce_from + nonce_length;
        var nonce = [_]u8{0} ** nonce_length;
        @memcpy(&nonce, buf[nonce_from..nonce_to]);

        return Self{
            .index = index,
            .hash = hash,
            .prev_hash = prev_hash,
            .timestamp = timestamp,
            .complexity = complexity,
            .nonce = nonce,
        };
    }

    fn toHashNoUpate(self: *const Self) [hash_length]u8 {
        var hasher = Sha256.init(.{});
        var buf = self.encode();
        // We need to omit already existing hash to calculate every time the same hash
        // and do not use hash from previous function call or already existing.
        for (@sizeOf(u128)..@sizeOf(u128) + hash_length) |i| {
            buf[i] = 0;
        }
        hasher.update(&buf);
        const hash = hasher.finalResult();
        return hash;
    }

    fn toHash(self: *Self) [hash_length]u8 {
        self.hash = self.toHashNoUpate();
        return self.hash;
    }

    fn verify(self: *const Self, prev_block: *const Self, current_complexity: complexity_type) error{
        HashesNotEqual,
        ComplexityMismatch,
        TimestampTooEarly,
    }!void {
        const hash = self.toHashNoUpate();
        if (!std.mem.eql(u8, &self.hash, &hash)) return error.HashesNotEqual;
        if (!std.mem.eql(u8, &self.prev_hash, &prev_block.hash)) return error.HashesNotEqual;
        if (self.index - 1 != prev_block.index) return error.HashesNotEqual;
        if (self.complexity != current_complexity) return error.ComplexityMismatch;
        if (self.timestamp <= prev_block.timestamp) return error.TimestampTooEarly;
    }

    fn isHashEmpty(self: *const Self) bool {
        return std.mem.eql(u8, &[_]u8{0} ** hash_length, &self.hash);
    }
};

// Thread safe array list.
fn TSArrayList(comptime T: type) type {
    return struct {
        const Self = @This();

        _inner: std.ArrayList(T),
        mutex: std.Thread.Mutex,

        fn Init(value: std.ArrayList(T)) Self {
            return .{
                ._inner = value,
                .mutex = .{},
            };
        }

        fn lock(self: *Self) LockedTSArrayList(T) {
            self.mutex.lock();
            return LockedTSArrayList(T).Init(&self._inner, &self.mutex);
        }
    };
}

fn LockedTSArrayList(comptime T: type) type {
    return struct {
        const Self = @This();

        inner: *std.ArrayList(T),
        _mutex: *std.Thread.Mutex,

        fn Init(value: *std.ArrayList(T), mutex: *std.Thread.Mutex) Self {
            return .{
                .inner = value,
                ._mutex = mutex,
            };
        }

        fn unlock(self: *Self) void {
            self._mutex.unlock();
        }
    };
}

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

const RpcPacket = struct {
    const Self = @This();

    event: RpcPacketEvent,
    block: Block,

    fn size() comptime_int {
        return comptime @sizeOf(RpcPacketEvent) + Block.size();
    }

    fn encode(self: *const Self) [size()]u8 {
        var buf = [_]u8{0} ** size();
        std.mem.writeInt(
            rpc_packet_event_type,
            buf[0..@sizeOf(rpc_packet_event_type)],
            @intFromEnum(self.event),
            .little,
        );
        const block = self.block.encode();
        @memcpy(buf[@sizeOf(rpc_packet_event_type)..], &block);
        return buf;
    }

    fn decode(buf: *const [size()]u8) Self {
        const event: RpcPacketEvent = @enumFromInt(
            std.mem.readInt(
                rpc_packet_event_type,
                buf[0..@sizeOf(rpc_packet_event_type)],
                .little,
            ),
        );
        const rest: *const [Block.size()]u8 = buf[@sizeOf(rpc_packet_event_type)..];
        const block = Block.decode(rest);
        return Self{
            .event = event,
            .block = block,
        };
    }
};

const RpcPacketExt = struct {
    addr: std.net.Address,
    inner: RpcPacket,
};

pub fn main() !void {
    switch (builtin.os.tag) {
        .macos, .linux => {},
        else => {
            log.err("at the moment software is not working on any system except macOS or Linux", .{});
            return;
        },
    }

    var gpa = std.heap.GeneralPurposeAllocator(.{
        .safety = true,
        .thread_safe = true,
        .verbose_log = true,
    }){};
    const allocator = gpa.allocator();
    defer std.debug.assert(gpa.deinit() == .ok);

    var rnd = std.rand.DefaultPrng.init(0);

    var envs = try std.process.getEnvMap(allocator);
    var mining_enabled = false;
    if (envs.get("MINING")) |val| {
        if (std.mem.eql(u8, val, "1")) mining_enabled = true;
    }
    var port: u16 = 46400;
    if (envs.get("PORT")) |val| {
        port = try std.fmt.parseInt(u16, val, 10);
    }
    const nodes = try parseEnvNodes(envs);
    var genesis: Block = undefined;
    if (envs.get("GENESIS")) |val| {
        var buf: [Block.size()]u8 = [_]u8{0} ** Block.size();
        _ = try std.fmt.hexToBytes(&buf, val);
        genesis = Block.decode(&buf);
        log.debug("configured genesis block:\n{any}", .{genesis});
    } else {
        // Init genesis block.
        genesis = Block{
            .index = 0,
            .hash = [_]u8{0} ** hash_length,
            .prev_hash = [_]u8{0} ** hash_length,
            .timestamp = std.time.milliTimestamp(),
            .complexity = 0,
            .nonce = [_]u8{0} ** nonce_length,
        };
        // To calculate and set genesis.hash.
        _ = genesis.toHash();
        const genesis_hex = std.fmt.bytesToHex(genesis.encode(), .lower);
        log.info("newly generated genesis block: {s}\n{any}", .{ genesis_hex, genesis });
    }
    envs.deinit();

    var inner_blocks = std.ArrayList(Block).init(allocator);
    // Do not make defer blocks.deinit() here
    // because in state.blocks memory pointer will be updated
    // when array with blocks grows.
    try inner_blocks.append(genesis);

    var state = State{
        .blocks = TSArrayList(Block).Init(inner_blocks),
        .mining_enabled = mining_enabled,
        .mined_block_ch = Channel(Block).Init(null),
        .rpc_packet_ch = Channel(RpcPacketExt).Init(null),
        .nodes = nodes,
    };
    defer {
        var blocks = state.blocks.lock();
        blocks.inner.deinit();
        blocks.unlock();
    }

    const http_server_thread = try std.Thread.spawn(.{}, httpServer, .{});
    const udp_server_thread = try std.Thread.spawn(.{}, udpServer, .{
        @as(*State, &state),
        @as(u16, port),
    });
    const mining_loop_thread = try std.Thread.spawn(.{}, miningLoop, .{
        @as(*State, &state),
        @as(*std.rand.Xoshiro256, &rnd),
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

    var blocks = state.blocks.lock();
    log.debug("current blocks length is {d}", .{blocks.inner.items.len});
    std.debug.assert(blocks.inner.items.len - 1 == blocks.inner.getLast().index);
    blocks.unlock();

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

fn udpServer(state: *State, port: u16) !void {
    log.info("starting udp server", .{});

    // Initialize UDP server socket and bind an address.
    const socket = try std.posix.socket(
        std.posix.AF.INET,
        std.posix.SOCK.DGRAM | std.posix.SOCK.NONBLOCK,
        std.posix.IPPROTO.UDP,
    );
    defer std.posix.close(socket);
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
            error.WouldBlock => {
                if (state.rpc_packet_ch.receive()) |rpc_packet| {
                    log.debug("send rpc packet {any}", .{rpc_packet});
                    const buf = rpc_packet.inner.encode();
                    const n = std.posix.sendto(
                        socket,
                        &buf,
                        0,
                        &rpc_packet.addr.any,
                        rpc_packet.addr.getOsSockLen(),
                    ) catch |err| {
                        log.err("failed to send udp packet to {any}: {any}", .{ rpc_packet.addr, err });
                        continue;
                    };
                    if (n != buf.len) {
                        log.err("not enough data was written to the socket: {d}\n", .{n});
                        continue;
                    }
                }
                continue;
            },
            else => return e,
        };
        const buf = buffer[0..n];
        if (buf.len != RpcPacket.size()) {
            log.debug("received invalid rpc packaet from {any}: {any}", .{ from_addr, buf });
            continue;
        }
        const rpc_packet = RpcPacket.decode(buf[0..RpcPacket.size()]);
        log.debug("received new rpc packet from {any}: {any}", .{ from_addr, rpc_packet });
        try handle_rpc_packet(state, RpcPacketExt{
            .addr = std.net.Address.initPosix(@as(*align(4) std.posix.sockaddr, @alignCast(&from_addr))),
            .inner = rpc_packet,
        });
    }

    log.info("udp server stopped", .{});
}

fn miningLoop(state: *State, rnd: *std.rand.Xoshiro256) !void {
    if (!state.mining_enabled) {
        log.info("mining loop is not started as mining is not enabled", .{});
        return;
    }
    log.info("starting mining loop", .{});
    var nonce: [nonce_length]u8 = [_]u8{0} ** nonce_length;
    var block: Block = undefined;
    while (shouldWait()) {
        while (shouldWait()) {
            std.time.sleep(std.time.ns_per_ms * 10); // 10ms
            try mineBlock(state, rnd, &nonce, &block);
        }
    }
    log.info("mining loop stopped", .{});
}

fn broadcastLoop(state: *State) void {
    log.info("starting broadcast loop", .{});
    while (shouldWait()) {
        if (state.mined_block_ch.receive()) |block| {
            log.debug("new block is found\n{any}", .{block});
            for (state.nodes) |node| {
                // Some of the nodes can be undefined, so it is a check.
                if (node.in.sa.port == 0) continue;
                log.debug("block can be send to {any} node", .{node});
                state.rpc_packet_ch.send(RpcPacketExt{ .addr = node, .inner = RpcPacket{
                    .event = RpcPacketEvent.NewBlock,
                    .block = block,
                } });
            }
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

fn mineBlock(state: *State, rnd: *std.rand.Xoshiro256, nonce: *[nonce_length]u8, block: *Block) !void {
    fillBufRandom(rnd, nonce);
    var blocks = state.blocks.lock();
    defer blocks.unlock();
    const prev_block = blocks.inner.getLast();
    block.* = Block{
        .index = prev_block.index + 1,
        .hash = [_]u8{0} ** hash_length,
        .prev_hash = prev_block.hash,
        .timestamp = std.time.milliTimestamp(),
        .complexity = min_complexity,
        .nonce = nonce.*,
    };
    // To set block.hash.
    const hash = block.toHash();
    var hash_leading_zeros: complexity_type = 0;
    for (hash, 0..) |byte, i| {
        if (byte == 0) {
            hash_leading_zeros = @as(complexity_type, @intCast(i + 1));
            continue;
        }
        break;
    }
    if (hash_leading_zeros == block.complexity) {
        try block.verify(&prev_block, min_complexity);
        state.mined_block_ch.send(block.*);
    }
}

fn parseEnvNodes(envs: std.process.EnvMap) ![6]std.net.Address {
    var nodes: [6]std.net.Address = [_]std.net.Address{undefined} ** 6;
    if (envs.get("NODES")) |val| {
        var node_index: usize = 0;
        var nodes_iter = std.mem.split(u8, val, ",");
        while (nodes_iter.next()) |node| {
            var node_iter = std.mem.split(u8, node, ":");
            const raw_ip_ = node_iter.next();
            const raw_port_ = node_iter.next();
            if (raw_ip_ == null or raw_port_ == null) {
                log.err("failed to parse ip and port for node: {s}", .{node});
                continue;
            }
            const raw_ip = raw_ip_.?;
            const raw_port = raw_port_.?;
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
            const address = try std.net.Address.parseIp4(raw_ip, port);
            nodes[node_index] = address;
            log.debug("load {any} node address to communicate", .{address});
            node_index += 1;
        }
    }
    return nodes;
}

fn handle_rpc_packet(state: *State, rpc_packet: RpcPacketExt) !void {
    var blocks = state.blocks.lock();
    defer blocks.unlock();
    const prev_block = blocks.inner.getLast();
    try rpc_packet.inner.block.verify(&prev_block, min_complexity);
    switch (rpc_packet.inner.event) {
        .NewBlock => {
            try blocks.inner.append(rpc_packet.inner.block);
            state.rpc_packet_ch.send(RpcPacketExt{ .addr = rpc_packet.addr, .inner = RpcPacket{
                .event = RpcPacketEvent.BlockApproved,
                .block = rpc_packet.inner.block,
            } });
        },
        .BlockApproved => {
            try blocks.inner.append(rpc_packet.inner.block);
        },
    }
}

fn logFn(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    std.debug.lockStdErr();
    defer std.debug.unlockStdErr();
    const stderr = std.io.getStdErr().writer();

    var buf: [20]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const allocator = fba.allocator();
    const time_str: []u8 = allocator.alloc(u8, buf.len) catch {
        nosuspend stderr.print(
            "failed to allocate memory to convert timestamp to string\n",
            .{},
        ) catch return;
        return;
    };
    defer allocator.free(time_str);

    const timestamp = time.time(null);
    if (timestamp == -1) {
        nosuspend stderr.print("failed to retrieve current time from time.h\n", .{}) catch return;
        return;
    }
    const tm_info = time.localtime(&timestamp);
    const n = time.strftime(
        time_str[0..buf.len],
        buf.len,
        "%Y-%m-%d %H:%M:%S",
        tm_info,
    );
    // We need to compare with buf length - 1 because returning length
    // doesn't contain terminating null character.
    if (n != buf.len - 1) {
        nosuspend stderr.print("failed to format current timestamp using time.h: {d}\n", .{n}) catch return;
        return;
    }

    const scoped_level = comptime switch (scope) {
        .gpa => std.log.Level.debug,
        else => level,
    };
    nosuspend stderr.print(
        "{s} " ++ "[" ++ comptime scoped_level.asText() ++ "] " ++ "(" ++ @tagName(scope) ++ ") " ++ format ++ "\n",
        .{time_str} ++ args,
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
    const buf = block.encode();
    try std.testing.expect(std.mem.eql(
        u8,
        buf[0..16],
        &[16]u8{ 127, 162, 86, 238, 196, 92, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    ));
    try std.testing.expect(std.mem.readInt(u128, buf[0..16], .little) == index);
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

test "test_rpc_packet_encode_decode" {
    const index = 102_000_882_000_511;
    const block = Block{
        .index = index,
        .hash = [_]u8{1} ** hash_length,
        .prev_hash = [_]u8{2} ** hash_length,
        .timestamp = std.time.milliTimestamp(),
        .complexity = 243,
        .nonce = [_]u8{3} ** nonce_length,
    };
    var rpc_packet = RpcPacket{
        .event = RpcPacketEvent.NewBlock,
        .block = block,
    };
    const buf = rpc_packet.encode();
    rpc_packet = RpcPacket.decode(&buf);
    try std.testing.expect(RpcPacketEvent.NewBlock == rpc_packet.event);
    try std.testing.expect(index == rpc_packet.block.index);
    try std.testing.expect(std.mem.eql(u8, &[_]u8{1} ** hash_length, &rpc_packet.block.hash));
    try std.testing.expect(std.mem.eql(u8, &[_]u8{2} ** hash_length, &rpc_packet.block.prev_hash));
    try std.testing.expect(std.mem.eql(u8, &[_]u8{3} ** nonce_length, &rpc_packet.block.nonce));
}
