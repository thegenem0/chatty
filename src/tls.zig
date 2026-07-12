const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
});
const std = @import("std");
const log = std.log.scoped(.tls);

pub const Context = struct {
    inner: *c.SSL_CTX,

    pub fn deinit(self: Context) void {
        c.SSL_CTX_free(self.inner);
    }
};

pub fn initContext() !Context {
    const method = c.TLS_server_method();
    const ctx = c.SSL_CTX_new(method) orelse return error.SslCtxFailed;
    _ = c.SSL_CTX_use_certificate_file(ctx, "cert.pem", c.SSL_FILETYPE_PEM);
    _ = c.SSL_CTX_use_PrivateKey_file(ctx, "key.pem", c.SSL_FILETYPE_PEM);
    return .{ .inner = ctx };
}

pub fn accept(ctx: Context, fd: std.c.fd_t) !Stream {
    const ssl = c.SSL_new(ctx.inner) orelse return error.SslNewFailed;
    errdefer c.SSL_free(ssl);
    if (c.SSL_set_fd(ssl, fd) != 1) return error.SslSetFdFailed;
    if (c.SSL_accept(ssl) != 1) return error.SslAcceptFailed;
    return .{ .ssl = ssl };
}

pub const Stream = struct {
    ssl: *c.SSL,

    pub fn deinit(self: *Stream) void {
        _ = c.SSL_shutdown(self.ssl);
        c.SSL_free(self.ssl);
    }

    pub fn fd(self: Stream) std.c.fd_t {
        return c.SSL_get_fd(self.ssl);
    }

    pub fn read(self: *Stream, buf: []u8) !usize {
        const n = c.SSL_read(self.ssl, buf.ptr, @intCast(buf.len));
        if (n <= 0) {
            const ssl_err = c.SSL_get_error(self.ssl, n);
            var e = c.ERR_get_error();
            while (e != 0) : (e = c.ERR_get_error()) {
                var err_buf: [256]u8 = undefined;
                _ = c.ERR_error_string_n(e, &err_buf, err_buf.len);
                log.err("SSL_read failed with code: {d}: {s}\n", .{ ssl_err, std.mem.sliceTo(&err_buf, 0) });
            }

            return error.SslReadFailed;
        }
        return @intCast(n);
    }

    pub fn writeAll(self: *Stream, buf: []const u8) !void {
        var sent: usize = 0;
        while (sent < buf.len) {
            const n = c.SSL_write(self.ssl, buf[sent..].ptr, @intCast(buf.len - sent));
            if (n <= 0) return error.SslWriteFailed;
            sent += @intCast(n);
        }
    }
};
