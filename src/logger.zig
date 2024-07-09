const std = @import("std");

pub fn logFn(
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
