const std = @import("std");
const net = std.Io.net;
const tls = @import("tls.zig");

pub const Role = enum { admin, mod, user };

pub const StatefulClient = struct {
    ssl_stream: tls.Stream,
    username: []const u8,
    room: []const u8,
    role: Role,
    tags: []const []const u8,
};
