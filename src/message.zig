const datetime = @import("datetime.zig");
const std = @import("std");

const Datetime = datetime.Datetime;
const Writer = std.Io.Writer;

/// Data structure that represents an email message.
pub const EmailAddress = struct {
    name: ?[]const u8 = null,
    address: []const u8,

    /// Formats the email address into the expected header value.
    pub fn format(
        self: EmailAddress,
        writer: *Writer,
    ) Writer.Error!void {
        if (self.name) |name|
            try writer.print("{s} ", .{name});

        try writer.writeByte('<');
        try writer.writeAll(self.address);
        try writer.writeByte('>');
    }
};

/// Data structure that represents and email message.
pub const Message = struct {
    from: EmailAddress,
    to: ?[]const EmailAddress = null,
    cc: ?[]const EmailAddress = null,
    bcc: ?[]const EmailAddress = null,
    subject: ?[]const u8 = null,
    text_body: ?[]const u8 = null,
    html_body: ?[]const u8 = null,
    data: ?[]const u8 = null,
    timestamp: ?Datetime = null,

    /// Formats the email message with the expected headers.
    pub fn format(
        self: Message,
        writer: *Writer,
    ) Writer.Error!void {
        try writer.print("From: {f}\r\n", .{self.from});

        if (self.to) |to| {
            try writer.writeAll("To: ");

            for (to, 0..) |address, i| {
                try writer.print("{f}", .{address});

                if (i < to.len - 1)
                    try writer.writeAll(", ");
            }

            try writer.writeAll("\r\n");
        }

        if (self.cc) |cc| {
            try writer.writeAll("Cc:");

            for (cc, 0..) |address, i| {
                try writer.print("{f}", .{address});

                if (i < cc.len - 1)
                    try writer.writeAll(", ");
            }

            try writer.writeAll("\r\n");
        }

        if (self.bcc) |bcc| {
            try writer.writeAll("Bcc:");

            for (bcc, 0..) |address, i| {
                try writer.print("{f}", .{address});

                if (i < bcc.len - 1)
                    try writer.writeAll(", ");
            }

            try writer.writeAll("\r\n");
        }

        if (self.subject) |subject| {
            // TODO: Handle non ascii.
            try writer.writeAll("Subject: ");
            try writer.print("{s}\r\n", .{subject});
        }

        const date = self.timestamp orelse datetime.fromUnixTimeStamp(std.time.timestamp());
        try writer.print("Date: {f}\r\n", .{date});

        try writer.writeAll("MIME-Version: 1.0\r\n");
        try writer.writeAll("Message-ID: <");

        const index = std.mem.indexOfScalar(u8, self.from.address, '@');
        const domain: []const u8 = blk: {
            const i = index orelse break :blk "localhost";
            break :blk self.from.address[i + 1 ..];
        };

        var buffer: [16]u8 = undefined;
        std.crypto.random.bytes(&buffer);
        try writer.print("{x}@{s}>\r\n", .{ &buffer, domain });

        if (self.html_body) |html_body| {
            if (self.text_body) |text_body| {
                try writer.print("Content-Type: multipart/alternative; boundary=\"{x}\"\r\n\r\n", .{&buffer});

                try writer.print("--{x}\r\n", .{&buffer});
                try writer.writeAll("Content-Type: text/plain; charset=utf-8\r\n");
                try writer.writeAll("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
                try quotable_printable.encodeWriter(writer, text_body);
                try writer.writeAll("\r\n");

                try writer.print("--{x}\r\n", .{&buffer});
                try writer.writeAll("Content-Type: text/html; charset=utf-8\r\n");
                try writer.writeAll("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
                try quotable_printable.encodeWriter(writer, html_body);
                try writer.writeAll("\r\n");

                return writer.print("--{x}--\r\n", .{&buffer});
            }

            try writer.writeAll("Content-Type: text/html; charset=utf-8\r\n");
            try writer.writeAll("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
            try quotable_printable.encodeWriter(writer, html_body);

            return writer.writeAll("\r\n");
        }

        try writer.writeAll("Content-Type: text/plain; charset=utf-8\r\n");
        try writer.writeAll("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
        if (self.text_body) |text_body| {
            try quotable_printable.encodeWriter(writer, text_body);

            return writer.writeAll("\r\n");
        }
    }
};

/// Quotable printable encoding implementation.
pub const quotable_printable = struct {
    // Start at 0...75 = 76 for the RFC Max line length.
    const MAX_LINE_LENGTH = 75;

    const State = enum {
        seen_space,
        seen_r,
        seen_r_space,
        seen_n_space,
        seen_rn_space,
        seen_rn,
        start,
    };

    pub fn encodeWriter(out: *Writer, slice: []const u8) Writer.Error!void {
        var current_len: usize = 0;
        var index: usize = 0;
        var state: State = .start;
        const trimmed = std.mem.trimEnd(u8, slice, &std.ascii.whitespace);

        while (trimmed.len > index) {
            switch (state) {
                .start => switch (trimmed[index]) {
                    '\r' => {
                        state = .seen_r;
                        continue;
                    },
                    ' ' => {
                        state = .seen_space;
                        continue;
                    },
                    '\t' => {
                        state = .seen_space;
                        continue;
                    },
                    '=' => {
                        const available = MAX_LINE_LENGTH - current_len;
                        if (available > 3) {
                            current_len += 2;
                        } else {
                            try out.writeAll("=\r\n");
                            current_len = 2;
                        }

                        try out.print("={X:02}", .{trimmed[index]});
                        index += 1;
                    },
                    else => {
                        if (std.ascii.isPrint(trimmed[index])) {
                            @branchHint(.likely);

                            if (current_len != MAX_LINE_LENGTH) {
                                current_len += 1;
                            } else {
                                try out.writeAll("=\r\n");
                                current_len = 0;
                            }

                            try out.writeByte(trimmed[index]);
                            index += 1;

                            continue;
                        }

                        const available = MAX_LINE_LENGTH - current_len;
                        if (available > 3) {
                            current_len += 2;
                        } else {
                            try out.writeAll("=\r\n");
                            current_len = 2;
                        }

                        try out.print("={X:02}", .{trimmed[index]});
                        index += 1;
                    },
                },
                .seen_r => {
                    if (index + 1 == trimmed.len) {
                        try out.print("={X:02}", .{trimmed[index]});
                        state = .start;
                        index += 1;

                        continue;
                    }

                    switch (trimmed[index + 1]) {
                        '\n' => {
                            state = .seen_rn;
                            continue;
                        },
                        else => {
                            const available = MAX_LINE_LENGTH - current_len;
                            if (available > 3) {
                                current_len += 2;
                            } else {
                                try out.writeAll("=\r\n");
                                current_len = 2;
                            }

                            try out.print("={X:02}", .{trimmed[index]});
                            state = .start;
                            index += 1;
                        },
                    }
                },
                .seen_rn => {
                    if (current_len != MAX_LINE_LENGTH) {
                        current_len += 2;
                    } else {
                        try out.writeAll("=\r\n");
                        current_len = 0;
                    }

                    try out.writeAll("\r\n");
                    state = .start;
                    index += 2;
                },
                .seen_space => {
                    if (index + 1 == trimmed.len) {
                        try out.print("={X:02}", .{trimmed[index]});
                        state = .start;
                        index += 1;

                        continue;
                    }

                    switch (trimmed[index + 1]) {
                        '\r' => {
                            state = .seen_r_space;
                            continue;
                        },
                        '\n' => {
                            state = .seen_n_space;
                            continue;
                        },
                        else => {
                            if (current_len != MAX_LINE_LENGTH) {
                                current_len += 1;
                            } else {
                                try out.writeAll("=\r\n");
                                current_len = 0;
                            }

                            try out.writeByte(trimmed[index]);
                            state = .start;
                            index += 1;
                        },
                    }
                },
                .seen_r_space => {
                    if (index + 2 == trimmed.len) {
                        try out.print("={X:02}={X:02}", .{ trimmed[index], trimmed[index + 1] });
                        state = .start;
                        index += 2;

                        continue;
                    }
                    switch (trimmed[index + 2]) {
                        '\n' => {
                            state = .seen_rn_space;
                            continue;
                        },
                        else => {
                            if (current_len != MAX_LINE_LENGTH) {
                                current_len += 5;
                            } else {
                                try out.writeAll("=\r\n");
                                current_len = 0;
                            }

                            try out.print("={X:02}={X:02}", .{ trimmed[index], trimmed[index + 1] });
                            state = .start;
                            index += 2;
                        },
                    }
                },
                .seen_n_space => {
                    if (current_len != MAX_LINE_LENGTH) {
                        current_len += 3;
                    } else {
                        try out.writeAll("=\r\n");
                        current_len = 0;
                    }

                    try out.print("={X:02}={X:02}", .{ trimmed[index], trimmed[index + 1] });
                    state = .start;
                    index += 2;
                },
                .seen_rn_space => {
                    if (current_len != MAX_LINE_LENGTH) {
                        current_len += 4;
                    } else {
                        try out.writeAll("=\r\n");
                        current_len = 0;
                    }

                    try out.print("={X:02}\r\n", .{trimmed[index]});
                    state = .start;
                    index += 3;
                },
            }
        }

        for (slice[trimmed.len..]) |byte| {
            const available = MAX_LINE_LENGTH - current_len;
            if (available > 3) {
                current_len += 2;
            } else {
                try out.writeAll("=\r\n");
                current_len = 2;
            }

            try out.print("={X:02}", .{byte});
        }
    }
};

test quotable_printable {
    var buffer: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try quotable_printable.encodeWriter(&writer, "= spaced\t\t\r\nendé\r\nodd\rline  ");
    try std.testing.expectEqualStrings("=3D spaced\t=09\r\nend=C3=A9\r\nodd=0Dline=20=20", writer.buffered());
}
