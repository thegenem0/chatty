const std = @import("std");
const Io = std.Io;
const Server = @import("server.zig").Server;

pub fn main(init: std.process.Init) !void {
    var server: Server = .{};
    try server.run(.{}, init.io, init.gpa);
}
