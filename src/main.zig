const std = @import("std");

const logger = @import("logger.zig");

const log = std.log.scoped(.main);

pub const std_options = .{
    .log_level = .debug,
    .logFn = logger.logFn,
};

pub fn main() !void {
    std.log.debug("this is a debug log: {s}={s}", .{ "additional_data", "asd_dsa" });
    log.err("this is an error log", .{});
}
