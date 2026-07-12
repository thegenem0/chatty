const std = @import("std");

const Command = union(enum) {
    users,
    rooms,
    join: []const u8,
    leave,
    whisper: []const u8,
    kick: []const u8,
    ban: []const u8,
    quit,
    unknown: []const u8,
};

pub fn parseCommand(line: []const u8) ?Command {
    if (!std.mem.startsWith(u8, line, "/")) return null;
    const space = std.mem.indexOfScalar(u8, line, ' ');
    const verb = if (space) |i| line[1..i] else line[1..];
    const args = if (space) |i| line[i + 1 ..] else "";

    if (std.mem.eql(u8, verb, "users")) return .users;
    if (std.mem.eql(u8, verb, "rooms")) return .rooms;
    if (std.mem.eql(u8, verb, "join")) return .{ .join = args };
    if (std.mem.eql(u8, verb, "leave")) return .leave;
    if (std.mem.eql(u8, verb, "whisper")) return .{ .whisper = args };
    if (std.mem.eql(u8, verb, "kick")) return .{ .kick = args };
    if (std.mem.eql(u8, verb, "ban")) return .{ .ban = args };
    if (std.mem.eql(u8, verb, "quit")) return .quit;

    return .{ .unknown = verb };
}
