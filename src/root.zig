const std = @import("std");
const net = std.Io.net;
const tls = @import("tls.zig");

pub const StatefulClient = struct {
    ssl_stream: tls.Stream,
    username: []const u8,
    room: []const u8,
    role: Role,
    tags: []const []const u8,
};

pub const Role = enum { admin, mod, user };

pub const Action = union(enum) {
    kick,
    ban,
    createChannel,
    manageTags,
    joinChannel: struct {
        user_tags: []const []const u8,
        channel_tags: []const []const u8,
    },
};

pub fn can(role: Role, action: Action) bool {
    return switch (action) {
        .kick => role == .admin or role == .mod,
        .ban => role == .admin,
        .createChannel => role == .admin or role == .mod,
        .manageTags => role == .admin,
        .joinChannel => |j| blk: {
            if (role == .admin or j.channel_tags.len == 0) break :blk true;
            for (j.user_tags) |ut| {
                for (j.channel_tags) |ct| {
                    if (std.mem.eql(u8, ut, ct)) break :blk true;
                }
            }
            break :blk false;
        },
    };
}

const Command = union(enum) {
    users,
    rooms,
    join: []const u8,
    leave,
    whisper: []const u8,
    kick: []const u8,
    ban: []const u8,
    createChannel: []const u8,
    addTag: []const u8,
    removeTag: []const u8,
    setMod: []const u8,
    demote: []const u8,
    tags,
    channelInfo: []const u8,
    help,
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
    if (std.mem.eql(u8, verb, "createchannel")) return .{ .createChannel = args };
    if (std.mem.eql(u8, verb, "addtag")) return .{ .addTag = args };
    if (std.mem.eql(u8, verb, "removetag")) return .{ .removeTag = args };
    if (std.mem.eql(u8, verb, "setmod")) return .{ .setMod = args };
    if (std.mem.eql(u8, verb, "demote")) return .{ .demote = args };
    if (std.mem.eql(u8, verb, "tags")) return .tags;
    if (std.mem.eql(u8, verb, "channelinfo")) return .{ .channelInfo = args };
    if (std.mem.eql(u8, verb, "help")) return .help;
    if (std.mem.eql(u8, verb, "quit")) return .quit;

    return .{ .unknown = verb };
}
