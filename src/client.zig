const net = std.Io.net;

const cmd = @import("command.zig");
const Server = @import("server.zig").Server;
const DEFAULT_ROOM = @import("server.zig").DEAFULT_ROOM;
const tls = @import("tls.zig");

const std = @import("std");
const log = std.log.scoped(.client);

pub fn handle(server: *Server, stream: net.Stream, ctx: tls.Context, io: std.Io, gpa: std.mem.Allocator) std.Io.Cancelable!void {
    defer {
        var s = stream;
        s.close(io);
    }

    var ssl_stream = tls.accept(ctx, stream.socket.handle) catch |err| {
        log.err("TLS handshake failed: {}", .{err});
        return;
    };
    defer ssl_stream.deinit();

    defer server.removeClient(ssl_stream.fd(), io, gpa);

    var recv_buf: [4096]u8 = undefined;

    var room_buf: [64]u8 = undefined;
    @memcpy(room_buf[0..DEFAULT_ROOM.len], DEFAULT_ROOM);
    var current_room: []u8 = room_buf[0..DEFAULT_ROOM.len];

    ssl_stream.writeAll("Enter username: ") catch return;

    const raw = readLine(&ssl_stream, &recv_buf) catch return orelse return;
    const username = std.mem.trimEnd(u8, raw, "\r");

    if (username.len == 0 or std.mem.indexOfScalar(u8, username, ' ') != null) {
        ssl_stream.writeAll("Invalid username.\n") catch {};
        return;
    }

    const owned = gpa.dupe(u8, username) catch return;

    server.addClient(ssl_stream, owned, io, gpa) catch |err| {
        gpa.free(owned);
        return switch (err) {
            error.UsernameTaken => ssl_stream.writeAll("Username already taken.\n") catch {},
            else => log.err("addClient failed: {}", .{err}),
        };
    };

    var prompt_buf: [64]u8 = undefined;
    const prompt = std.fmt.bufPrint(&prompt_buf, "[{s}] > ", .{owned}) catch unreachable;
    ssl_stream.writeAll(prompt) catch return;

    while (true) {
        const line = readLine(&ssl_stream, &recv_buf) catch |err| switch (err) {
            error.LineTooLong => return,
            else => {
                log.err("read error: {}", .{err});
                return;
            },
        } orelse return;
        const msg = std.mem.trimEnd(u8, line, "\r");

        if (cmd.parseCommand(msg)) |c| {
            switch (c) {
                .users => server.listUsers(&ssl_stream, current_room, io) catch {},

                .rooms => server.listRooms(&ssl_stream, io) catch {},

                .join => |args| {
                    const name = if (args.len > 0 and args[0] == '#') args[1..] else args;
                    if (name.len > room_buf.len) {
                        ssl_stream.writeAll("Room name too long.\n") catch {};
                        continue;
                    }
                    @memcpy(room_buf[0..name.len], name);
                    current_room = room_buf[0..name.len];
                    server.joinRoom(owned, current_room, io, gpa) catch {};
                },

                .leave => server.joinRoom(owned, DEFAULT_ROOM, io, gpa) catch {},

                .whisper => |args| {
                    const sep = std.mem.indexOfScalar(u8, args, ' ') orelse {
                        ssl_stream.writeAll("Usage: /whisper <username> <message>\n") catch {};
                        continue;
                    };
                    const target = args[0..sep];
                    const dm = args[sep + 1 ..];
                    server.whisper(owned, target, dm, io) catch {
                        ssl_stream.writeAll("User not found.\n") catch {};
                    };
                },

                .kick => |target| server.kick(target, io) catch {
                    ssl_stream.writeAll("User not found.\n") catch {};
                },

                .ban => |target| server.ban(target, io, gpa) catch {
                    ssl_stream.writeAll("User not found.\n") catch {};
                },

                .quit => return,

                .unknown => |verb| {
                    var err_buf: [256]u8 = undefined;
                    const err_msg = std.fmt.bufPrint(&err_buf, "Unknown command: /{s}\n", .{verb}) catch unreachable;
                    ssl_stream.writeAll(err_msg) catch {};
                },
            }
        } else {
            var msg_buf: [4096]u8 = undefined;
            const padded = std.fmt.bufPrint(&msg_buf, "[{s}]: {s}\n", .{ owned, msg }) catch unreachable;
            server.broadcastToRoom(padded, current_room, ssl_stream.fd(), io) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
            };
        }

        ssl_stream.writeAll(prompt) catch return;
    }
}

fn readLine(ssl: *tls.Stream, buf: []u8) !?[]u8 {
    var len: usize = 0;
    while (len < buf.len) {
        const n = try ssl.read(buf[len .. len + 1]);
        if (n == 0) return if (len == 0) null else buf[0..len];
        if (buf[len] == '\n') return buf[0..len];
        len += 1;
    }
    return error.LineTooLong;
}
