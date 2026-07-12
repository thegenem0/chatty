const net = std.Io.net;

const client = @import("client.zig");
const StatefulClient = @import("root.zig").StatefulClient;
const tls = @import("tls.zig");

const std = @import("std");
const log = std.log.scoped(.server);

pub const Config = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 7070,
};

pub const DEAFULT_ROOM: []const u8 = "general";

pub const Server = struct {
    mu: std.Io.Mutex = .init,
    clients: std.ArrayList(StatefulClient) = .empty,
    banned: std.ArrayList([]const u8) = .empty,

    pub fn run(self: *Server, config: Config, io: std.Io, gpa: std.mem.Allocator) !void {
        const addr = try net.IpAddress.parseIp4(config.host, config.port);
        var server = try addr.listen(io, .{ .reuse_address = true });
        defer server.deinit(io);
        defer self.clients.deinit(gpa);

        const ctx = try tls.initContext();

        var group: std.Io.Group = .init;
        defer group.cancel(io);

        log.info("Listening on {s}:{d}", .{ config.host, config.port });

        while (true) {
            const stream = try server.accept(io);
            group.async(io, client.handle, .{ self, stream, ctx, io, gpa });
        }
    }

    pub fn addClient(self: *Server, ssl_stream: tls.Stream, uname: []const u8, io: std.Io, gpa: std.mem.Allocator) !void {
        try self.mu.lock(io);
        defer self.mu.unlock(io);
        for (self.clients.items) |c| {
            if (std.mem.eql(u8, c.username, uname)) return error.UsernameTaken;
        }
        try self.clients.append(gpa, .{
            .ssl_stream = ssl_stream,
            .username = uname,
            .room = try gpa.dupe(u8, DEAFULT_ROOM),
        });
    }

    pub fn removeClient(self: *Server, fd: std.c.fd_t, io: std.Io, gpa: std.mem.Allocator) void {
        self.mu.lock(io) catch return;
        defer self.mu.unlock(io);
        for (self.clients.items, 0..) |c, i| {
            if (c.ssl_stream.fd() == fd) {
                gpa.free(c.username);
                gpa.free(c.room);
                _ = self.clients.swapRemove(i);
                return;
            }
        }
    }

    pub fn broadcastToRoom(self: *Server, msg: []const u8, room: []const u8, exclude_fd: std.c.fd_t, io: std.Io) !void {
        try self.mu.lock(io);
        defer self.mu.unlock(io);
        for (self.clients.items) |*c| {
            if (c.ssl_stream.fd() == exclude_fd) continue;
            if (!std.mem.eql(u8, c.room, room)) continue;

            c.ssl_stream.writeAll("\r\x1b[2K") catch {};
            c.ssl_stream.writeAll(msg) catch {};

            var p: [64]u8 = undefined;
            const prompt = std.fmt.bufPrint(&p, "[{s}] > ", .{c.username}) catch continue;
            c.ssl_stream.writeAll(prompt) catch {};
        }
    }

    pub fn listUsers(self: *Server, requester: *tls.Stream, room: []const u8, io: std.Io) !void {
        try self.mu.lock(io);
        defer self.mu.unlock(io);

        var header_buf: [128]u8 = undefined;
        const header = std.fmt.bufPrint(&header_buf, "Users in #{s}:\n", .{room}) catch unreachable;
        requester.writeAll(header) catch return;

        for (self.clients.items) |c| {
            if (!std.mem.eql(u8, c.room, room)) continue;
            var line_buf: [256]u8 = undefined;
            const line = std.fmt.bufPrint(&line_buf, "  {s}\n", .{c.username}) catch unreachable;
            requester.writeAll(line) catch return;
        }
    }

    pub fn listRooms(self: *Server, requester: *tls.Stream, io: std.Io) !void {
        try self.mu.lock(io);
        defer self.mu.unlock(io);

        const RoomEntry = struct { name: []const u8, count: usize };
        var rooms: [64]RoomEntry = undefined;
        var rooms_len: usize = 0;

        for (self.clients.items) |c| {
            var found = false;
            for (rooms[0..rooms_len]) |*r| {
                if (std.mem.eql(u8, r.name, c.room)) {
                    r.count += 1;
                    found = true;
                    break;
                }
            }
            if (!found and rooms_len < rooms.len) {
                rooms[rooms_len] = .{ .name = c.room, .count = 1 };
                rooms_len += 1;
            }
        }

        requester.writeAll("Active rooms:\n") catch return;
        for (rooms[0..rooms_len]) |r| {
            var buf: [128]u8 = undefined;
            const line = std.fmt.bufPrint(&buf, "  #{s} ({d} user{s})\n", .{
                r.name, r.count, if (r.count == 1) @as([]const u8, "") else "s",
            }) catch unreachable;
            requester.writeAll(line) catch return;
        }
    }

    pub fn kick(self: *Server, target: []const u8, io: std.Io) !void {
        try self.mu.lock(io);
        defer self.mu.unlock(io);
        for (self.clients.items) |*c| {
            if (std.mem.eql(u8, c.username, target)) {
                c.ssl_stream.writeAll("You have been kicked.\n") catch {};
                _ = std.c.shutdown(c.ssl_stream.fd(), std.c.SHUT.RDWR);
                return;
            }
        }
        return error.UserNotFound;
    }

    pub fn ban(self: *Server, target: []const u8, io: std.Io, gpa: std.mem.Allocator) !void {
        const duped = try gpa.dupe(u8, target);
        try self.mu.lock(io);
        defer self.mu.unlock(io);
        try self.banned.append(gpa, duped);
        for (self.clients.items) |*c| {
            if (std.mem.eql(u8, c.username, target)) {
                c.ssl_stream.writeAll("You have been banned.\n") catch {};
                _ = std.c.shutdown(c.ssl_stream.fd(), std.c.SHUT.RDWR);
                return;
            }
        }
    }

    pub fn joinRoom(
        self: *Server,
        username: []const u8,
        new_room: []const u8,
        io: std.Io,
        gpa: std.mem.Allocator,
    ) !void {
        const duped = try gpa.dupe(u8, new_room);
        errdefer gpa.free(duped);

        var old_room_buf: [64]u8 = undefined;
        var old_room: []u8 = undefined;
        var client_fd: std.c.fd_t = undefined;

        {
            try self.mu.lock(io);
            defer self.mu.unlock(io);
            for (self.clients.items) |*c| {
                if (std.mem.eql(u8, c.username, username)) {
                    const len = @min(c.room.len, old_room_buf.len);
                    @memcpy(old_room_buf[0..len], c.room[0..len]);
                    old_room = old_room_buf[0..len];
                    client_fd = c.ssl_stream.fd();
                    gpa.free(c.room);
                    c.room = duped;
                    break;
                }
            } else {
                return error.UserNotFound;
            }
        }

        var buf: [256]u8 = undefined;
        const leave_msg = std.fmt.bufPrint(&buf, "{s} has left #{s}\n", .{ username, old_room }) catch unreachable;
        self.broadcastToRoom(leave_msg, old_room, client_fd, io) catch {};

        const join_msg = std.fmt.bufPrint(&buf, "{s} has joined #{s}\n", .{ username, new_room }) catch unreachable;
        self.broadcastToRoom(join_msg, new_room, client_fd, io) catch {};
    }

    pub fn whisper(self: *Server, from: []const u8, to: []const u8, msg: []const u8, io: std.Io) !void {
        try self.mu.lock(io);
        defer self.mu.unlock(io);

        var fmt_buf: [4096]u8 = undefined;
        const formatted = std.fmt.bufPrint(&fmt_buf, "[whisper from {s}]: {s}\n", .{ from, msg }) catch unreachable;
        for (self.clients.items) |*c| {
            if (std.mem.eql(u8, c.username, to)) {
                c.ssl_stream.writeAll("\r\x1b[2K") catch {};
                c.ssl_stream.writeAll(formatted) catch {};

                var p: [64]u8 = undefined;
                const prompt = std.fmt.bufPrint(&p, "[{s}] > ", .{c.username}) catch continue;
                c.ssl_stream.writeAll(prompt) catch {};
            }
        }
        return error.UserNotFound;
    }
};
