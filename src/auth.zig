const std = @import("std");
const argon2 = std.crypto.pwhash.argon2;
const db = @import("db.zig");

pub const hash_buf_len = 128;

pub const LoginResult = struct {
    user: db.UserRow,
    tags: [][]const u8,

    pub fn deinit(self: LoginResult, gpa: std.mem.Allocator) void {
        self.user.deinit(gpa);
        for (self.tags) |t| gpa.free(t);
        gpa.free(self.tags);
    }
};

const params: argon2.Params = .{ .t = 2, .m = 56636, .p = 1 };

pub fn hashPassword(password: []const u8, io: std.Io, gpa: std.mem.Allocator, buf: []u8) ![]const u8 {
    return argon2.strHash(password, .{ .allocator = gpa, .params = params }, buf, io);
}

pub fn verifyPassword(hash: []const u8, password: []const u8, io: std.Io, gpa: std.mem.Allocator) !void {
    argon2.strVerify(hash, password, .{ .allocator = gpa }, io) catch return error.WrongPassword;
}

pub fn register(database: *db.Db, username: []const u8, password: []const u8, io: std.Io, gpa: std.mem.Allocator) !void {
    var buf: [hash_buf_len]u8 = undefined;
    const hash = try hashPassword(password, io, gpa, &buf);
    try database.createUser(username, hash, "user");
}

pub fn login(database: *db.Db, username: []const u8, password: []const u8, io: std.Io, gpa: std.mem.Allocator) !LoginResult {
    const user = (try database.findUser(username, gpa)) orelse return error.UserNotFound;
    errdefer user.deinit(gpa);

    try verifyPassword(user.pass_hash, password, io, gpa);

    const tags = try database.getUserTags(user.id, gpa);
    return .{ .user = user, .tags = tags };
}
