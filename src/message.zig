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

pub const quotable_printable = struct {
    const MAX_LINE_LENGTH = 76;

    //TODO: Rework this as it is not fully compliant
    pub fn encodeWriter(out: *Writer, slice: []const u8) Writer.Error!void {
        var current_len: usize = 1;
        const trimmed = std.mem.trimEnd(u8, slice, &std.ascii.whitespace);

        for (trimmed) |byte| {
            switch (byte) {
                '\t' => {
                    if (current_len == MAX_LINE_LENGTH) {
                        try out.writeAll("=\r\n");
                        current_len = 1;
                    } else current_len += 1;

                    try out.writeByte(byte);
                },
                '=' => {
                    const available = MAX_LINE_LENGTH - current_len;
                    if (available < 4) {
                        try out.writeAll("=\r\n");
                        current_len = 3;
                    } else current_len += 3;

                    try out.print("={X:02}", .{byte});
                },
                else => {
                    if (std.ascii.isPrint(byte)) {
                        @branchHint(.likely);

                        if (current_len == MAX_LINE_LENGTH) {
                            try out.writeAll("=\r\n");
                            current_len = 1;
                        } else current_len += 1;

                        try out.writeByte(byte);
                    } else {
                        const available = MAX_LINE_LENGTH - current_len;
                        if (available < 4) {
                            try out.writeAll("=\r\n");
                            current_len = 3;
                        } else current_len += 3;

                        try out.print("={X:02}", .{byte});
                    }
                },
            }
        }

        for (slice[trimmed.len..]) |byte| {
            const available = MAX_LINE_LENGTH - current_len;
            if (available < 4) {
                try out.writeAll("=\r\n");
                current_len = 3;
            } else current_len += 3;

            try out.print("={X:02}", .{byte});
        }
    }
};

test quotable_printable {
    var buffer: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try quotable_printable.encodeWriter(&writer, "foooooó");
    std.debug.print("Fooo: {s}\n", .{writer.buffered()});
}
