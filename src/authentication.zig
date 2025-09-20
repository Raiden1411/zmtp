const conn = @import("connection.zig");
const std = @import("std");
const utils = @import("utils.zig");

const Connection = @import("connection.zig").Connection;
const GreetingsError = @import("Client.zig").GreetingsError;

/// Map of precedence levels of auth.
///
/// Auth handshakes will always use the highest available.
pub const auth_precedence = std.enums.EnumMap(Auth, u8).init(.{
    .PLAIN = 1,
    .LOGIN = 2,
    .XOAUTH2 = 3,
});

/// Credentials used for a authentication handshake.
pub const Credentials = struct {
    username: []const u8,
    password: []const u8,

    pub const Error = GreetingsError || error{NoSpaceLeft};

    /// Encodes these credentials based of the auth offerings from the server.
    ///
    /// This writes to the connection directly.
    pub fn encode(self: Credentials, auth: Auth, connection: *Connection) Error!void {
        const reader = connection.reader();
        const writer = connection.writer();

        switch (auth) {
            .XOAUTH2 => {
                try writer.writeAll("AUTH XOAUTH2 ");

                // TODO: Rework this later.
                var buffer: [512]u8 = undefined;
                const plain = try std.fmt.bufPrint(&buffer, "user={s}\x01auth=Bearer {s}\x01\x01", .{ self.username, self.password });

                const writable = writer.writableSliceGreedy(std.base64.standard.Encoder.calcSize(plain.len));

                const encoded = std.base64.standard.Encoder.encode(writable, plain);
                writer.advance(encoded.len);

                try writer.writeAll("\r\n");
                try connection.flush();

                try reader.fill(1);
                const response = try utils.parseServerResponse(try reader.takeDelimiterInclusive('\n'));
                if (response.code != 235)
                    return utils.parseResponseCode(response.code);
            },
            .PLAIN => {
                try writer.writeAll("AUTH PLAIN ");

                // TODO: Rework this later.
                var buffer: [512]u8 = undefined;
                const plain = try std.fmt.bufPrint(&buffer, "\x00{s}\x00{s}", .{ self.username, self.password });

                std.debug.assert(writer.buffer.len > std.base64.standard.Encoder.calcSize(plain.len)); // Cannot fit into writers buffer

                const encoded = std.base64.standard.Encoder.encode(writer.buffer[writer.end..], plain);
                writer.advance(encoded.len);

                try writer.writeAll("\r\n");
                try connection.flush();

                try reader.fill(1);
                const response = try utils.parseServerResponse(try reader.takeDelimiterInclusive('\n'));
                if (response.code != 235)
                    return utils.parseResponseCode(response.code);
            },
            .LOGIN => {
                try writer.writeAll("AUTH LOGIN\r\n");
                try connection.flush();

                try reader.fill(1);
                const response_user = try utils.parseServerResponse(try reader.takeDelimiterInclusive('\n'));
                if (response_user.code != 334)
                    return utils.parseResponseCode(response_user.code);

                if (!std.mem.eql(u8, std.mem.trimEnd(u8, response_user.data, &std.ascii.whitespace), "VXNlcm5hbWU6"))
                    return error.UnexpectedServerResponse;

                try writer.print("{b64}\r\n", .{self.username});
                try connection.flush();

                try reader.fillMore();
                const response_pass = try utils.parseServerResponse(try reader.takeDelimiterInclusive('\n'));
                if (response_pass.code != 334)
                    return utils.parseResponseCode(response_pass.code);

                if (!std.mem.eql(u8, std.mem.trimEnd(u8, response_pass.data, &std.ascii.whitespace), "UGFzc3dvcmQ6"))
                    return error.UnexpectedServerResponse;

                try writer.print("{b64}\r\n", .{self.password});
                try connection.flush();

                try reader.fillMore();
                const response_auth = try utils.parseServerResponse(try reader.takeDelimiterInclusive('\n'));
                if (response_auth.code != 235)
                    return utils.parseResponseCode(response_pass.code);
            },
        }
    }
};

/// Set of authentication methods supported by this client.
pub const Auth = enum {
    PLAIN,
    LOGIN,
    XOAUTH2,
};

/// Parses the `AUTH` server offerings.
///
/// The returned auth offering will be based on the most secure
/// that the server supports.
pub fn parseAuthOfferings(slice: []const u8) ?Auth {
    var iter = std.mem.tokenizeScalar(u8, slice, ' ');

    var precedence: u8 = 0;
    var auth: ?Auth = null;

    while (iter.next()) |offering| {
        const parsed_auth = std.meta.stringToEnum(Auth, offering) orelse continue;

        if (auth_precedence.get(parsed_auth)) |assigned_precedence| {
            if (assigned_precedence > precedence) {
                precedence = assigned_precedence;
                auth = parsed_auth;
            }
        }
    }

    return auth;
}
