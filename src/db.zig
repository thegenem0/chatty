const std = @import("std");
const c = @cImport({
    @cInclude("sqlite3.h");
});

const SQLITE_STATIC: c.sqlite3_destructor_type = null;

pub const UserRow = struct {
    id: i64,
    username: []const u8,
    pass_hash: []const u8,
    role: []const u8,

    pub fn deinit(self: UserRow, gpa: std.mem.Allocator) void {
        gpa.free(self.username);
        gpa.free(self.pass_hash);
        gpa.free(self.role);
    }
};

pub const Db = struct {
    handle: *c.sqlite3,

    pub fn open(path: [*:0]const u8) !Db {
        var handle: ?*c.sqlite3 = null;
        if (c.sqlite3_open(path, &handle) != c.SQLITE_OK) return error.DbOpenFailed;
        return .{ .handle = handle.? };
    }

    pub fn close(self: *Db) void {
        _ = c.sqlite3_close(self.handle);
    }

    pub fn migrate(self: *Db) !void {
        const schema =
            \\CREATE TABLE IF NOT EXISTS users (
            \\    id        INTEGER PRIMARY KEY,
            \\    username  TEXT UNIQUE NOT NULL,
            \\    pass_hash TEXT NOT NULL,
            \\    role      TEXT NOT NULL DEFAULT 'user'
            \\);
            \\CREATE TABLE IF NOT EXISTS user_tags (
            \\    user_id  INTEGER REFERENCES users(id) ON DELETE CASCADE,
            \\    tag      TEXT NOT NULL,
            \\    PRIMARY KEY (user_id, tag)
            \\);
            \\CREATE TABLE IF NOT EXISTS channels (
            \\    id         INTEGER PRIMARY KEY,
            \\    name       TEXT UNIQUE NOT NULL,
            \\    created_by INTEGER REFERENCES users(id)
            \\);
            \\CREATE TABLE IF NOT EXISTS channel_tags (
            \\    channel_id INTEGER REFERENCES channels(id) ON DELETE CASCADE,
            \\    tag        TEXT NOT NULL,
            \\    PRIMARY KEY (channel_id, tag)
            \\);
        ;
        if (c.sqlite3_exec(self.handle, schema, null, null, null) != c.SQLITE_OK) return error.MigrationFailed;
    }

    pub fn createUser(self: *Db, username: []const u8, pass_hash: []const u8, role: []const u8) !void {
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(
            self.handle,
            "INSERT INTO users (username, pass_hash, role) VALUES (?, ?, ?)",
            -1,
            &stmt,
            null,
        ) != c.SQLITE_OK) return error.PrepareError;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, username.ptr, @intCast(username.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 2, pass_hash.ptr, @intCast(pass_hash.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 3, role.ptr, @intCast(role.len), SQLITE_STATIC);

        if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.InsertFailed;
    }

    pub fn findUser(self: *Db, username: []const u8, gpa: std.mem.Allocator) !?UserRow {
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(
            self.handle,
            "SELECT id, username, pass_hash, role FROM users WHERE username = ?",
            -1,
            &stmt,
            null,
        ) != c.SQLITE_OK) return error.PrepareError;

        _ = c.sqlite3_bind_text(stmt, 1, username.ptr, @intCast(username.len), SQLITE_STATIC);

        switch (c.sqlite3_step(stmt)) {
            c.SQLITE_ROW => {
                const id = c.sqlite3_column_int64(stmt, 0);
                const uname = columnText(stmt, 1);
                const hash = columnText(stmt, 2);
                const role = columnText(stmt, 3);
                return .{
                    .id = id,
                    .username = try gpa.dupe(u8, uname),
                    .pass_hash = try gpa.dupe(u8, hash),
                    .role = try gpa.dupe(u8, role),
                };
            },
            c.SQLITE_DONE => return null,
            else => return error.QueryFailed,
        }
    }

    pub fn setUserRole(self: *Db, username: []const u8, role: []const u8) !void {
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(
            self.handle,
            "UPDATE users SET role = ? WHERE username = ?",
            -1,
            &stmt,
            null,
        ) != c.SQLITE_OK) return error.PrepareError;

        _ = c.sqlite3_bind_text(stmt, 1, role.ptr, @intCast(role.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 2, username.ptr, @intCast(username.len), SQLITE_STATIC);

        if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.UpdateFailed;
        if (c.sqlite3_changes(self.handle) == 0) return error.UserNotFound;
    }

    pub fn getUserTags(self: *Db, user_id: i64, gpa: std.mem.Allocator) ![][]const u8 {
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(
            self.handle,
            "SELECT tag FROM user_tags WHERE user_id = ?",
            -1,
            &stmt,
            null,
        ) != c.SQLITE_OK) return error.PrepareError;

        _ = c.sqlite3_bind_int64(stmt, 1, user_id);

        var tags: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (tags.items) |t| {
                gpa.free(t);
                tags.deinit(gpa);
            }
        }

        while (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
            try tags.append(gpa, try gpa.dupe(u8, columnText(stmt, 0)));
        }

        return try tags.toOwnedSlice(gpa);
    }

    pub fn addUserTag(self: *Db, username: []const u8, tag: []const u8) !void {
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(
            self.handle,
            "INSERT OR IGNORE INTO user_tags (user_id, tag) SELECT id, ? FROM users WHERE username = ?",
            -1,
            &stmt,
            null,
        ) != c.SQLITE_OK) return error.PrepareError;

        _ = c.sqlite3_bind_text(stmt, 1, tag.ptr, @intCast(tag.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 2, username.ptr, @intCast(username.len), SQLITE_STATIC);

        if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.InsertFailed;
        if (c.sqlite3_changes(self.handle) == 0) return error.UserNotFound;
    }

    pub fn removeUserTag(self: *Db, username: []const u8, tag: []const u8) !void {
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(
            self.handle,
            "DELETE FROM user_tags WHERE tag = ? AND user_id = (SELECT id FROM users WHERE username = ?)",
            -1,
            &stmt,
            null,
        ) != c.SQLITE_OK) return error.PrepareError;

        _ = c.sqlite3_bind_text(stmt, 1, tag.ptr, @intCast(tag.len), SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 2, username.ptr, @intCast(username.len), SQLITE_STATIC);

        if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.InsertFailed;
    }

    pub fn channelExists(self: *Db, name: []const u8) !bool {
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(
            self.handle,
            "SELECT 1 FROM channels WHERE name = ?",
            -1,
            &stmt,
            null,
        ) != c.SQLITE_OK) return error.PrepareError;

        _ = c.sqlite3_bind_text(stmt, 1, name.ptr, @intCast(name.len), SQLITE_STATIC);
        return c.sqlite3_step(stmt) == c.SQLITE_ROW;
    }

    pub fn createChannel(self: *Db, name: []const u8, created_by: i64, tags: []const []const u8) !void {
        {
            var stmt: ?*c.sqlite3_stmt = null;
            if (c.sqlite3_prepare_v2(
                self.handle,
                "INSERT INTO channels (name, created_by) VALUES (?, ?)",
                -1,
                &stmt,
                null,
            ) != c.SQLITE_OK) return error.PrepareError;
            defer _ = c.sqlite3_finalize(stmt);

            _ = c.sqlite3_bind_text(stmt, 1, name.ptr, @intCast(name.len), SQLITE_STATIC);
            _ = c.sqlite3_bind_int64(stmt, 2, created_by);

            if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.InsertFailed;
        }

        const channel_id = c.sqlite3_last_insert_rowid(self.handle);

        for (tags) |tag| {
            var stmt: ?*c.sqlite3_stmt = null;
            if (c.sqlite3_prepare_v2(
                self.handle,
                "INSERT INTO channel_tags (channel_id, tag) VALUES (?, ?)",
                -1,
                &stmt,
                null,
            ) != c.SQLITE_OK) return error.PrepareError;
            defer _ = c.sqlite3_finalize(stmt);

            _ = c.sqlite3_bind_int64(stmt, 1, channel_id);
            _ = c.sqlite3_bind_text(stmt, 2, tag.ptr, @intCast(tag.len), SQLITE_STATIC);

            if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.InsertFailed;
        }
    }

    pub fn getChannelTags(self: *Db, name: []const u8, gpa: std.mem.Allocator) ![][]const u8 {
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(
            self.handle,
            \\SELECT ct.tag FROM channel_tags ct
            \\JOIN channels ch ON ch.id = ct.channel_id
            \\WHERE ch.name = ?
        ,
            -1,
            &stmt,
            null,
        ) != c.SQLITE_OK) return error.PrepareError;
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, name.ptr, @intCast(name.len), SQLITE_STATIC);

        var tags: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (tags.items) |t| {
                gpa.free(t);
                tags.deinit(gpa);
            }
        }

        while (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
            try tags.append(gpa, try gpa.dupe(u8, columnText(stmt, 0)));
        }

        return try tags.toOwnedSlice(gpa);
    }
};

fn columnText(stmt: ?*c.sqlite3_stmt, col: c_int) []const u8 {
    const ptr = c.sqlite3_column_text(stmt, col);
    const len: usize = @intCast(c.sqlite3_column_bytes(stmt, col));
    return if (ptr) |p| p[0..len] else "";
}
