const std = @import("std");
const Io = std.Io;
const Server = @import("server.zig").Server;
const db = @import("db.zig");

pub fn main(init: std.process.Init) !void {
    // try testDb(init.gpa);
    var server: Server = .{};
    try server.run(.{}, init.io, init.gpa);
}

// fn testDb(gpa: std.mem.Allocator) !void {
//     var database = try db.Db.open(":memory:");
//     defer database.close();
//
//     try database.migrate();
//     std.debug.print("migrate: ok\n", .{});
//
//     try database.createUser("alice", "hash_abc", "admin");
//     std.debug.print("createUser: ok\n", .{});
//
//     const alice = (try database.findUser("alice", gpa)) orelse return error.ExpectedUser;
//     defer alice.deinit(gpa);
//     std.debug.print("findUser alice: id={d} role={s}\n", .{ alice.id, alice.role });
//
//     const ghost = try database.findUser("ghost", gpa);
//     std.debug.assert(ghost == null);
//     std.debug.print("findUser ghost: null ok\n", .{});
//
//     try database.setUserRole("alice", "mod");
//     const alice2 = (try database.findUser("alice", gpa)) orelse return error.ExpectedUser;
//     defer alice2.deinit(gpa);
//     std.debug.print("setUserRole alice→mod: role={s}\n", .{alice2.role});
//
//     try database.addUserTag("alice", "vip");
//     try database.addUserTag("alice", "staff");
//     const tags1 = try database.getUserTags(alice.id, gpa);
//     defer {
//         for (tags1) |t| gpa.free(t);
//         gpa.free(tags1);
//     }
//     std.debug.print("getUserTags: {d} tags\n", .{tags1.len});
//     for (tags1) |t| std.debug.print("  {s}\n", .{t});
//
//     try database.removeUserTag("alice", "staff");
//     const tags2 = try database.getUserTags(alice.id, gpa);
//     defer {
//         for (tags2) |t| gpa.free(t);
//         gpa.free(tags2);
//     }
//     std.debug.assert(tags2.len == 1);
//     std.debug.print("removeUserTag staff: {d} remaining\n", .{tags2.len});
//
//     try database.createChannel("general", alice.id, &.{});
//     std.debug.print("createChannel general: ok\n", .{});
//
//     try database.createChannel("vip-lounge", alice.id, &.{"vip"});
//     std.debug.print("createChannel vip-lounge: ok\n", .{});
//
//     std.debug.assert(try database.channelExists("general"));
//     std.debug.assert(!try database.channelExists("nonexistent"));
//     std.debug.print("channelExists: ok\n", .{});
//
//     const ctags = try database.getChannelTags("vip-lounge", gpa);
//     defer {
//         for (ctags) |t| gpa.free(t);
//         gpa.free(ctags);
//     }
//     std.debug.assert(ctags.len == 1);
//     std.debug.print("getChannelTags vip-lounge: {s}\n", .{ctags[0]});
//
//     const ctags2 = try database.getChannelTags("general", gpa);
//     defer {
//         for (ctags2) |t| gpa.free(t);
//         gpa.free(ctags2);
//     }
//     std.debug.assert(ctags2.len == 0);
//     std.debug.print("getChannelTags general: 0 tags ok\n", .{});
// }
