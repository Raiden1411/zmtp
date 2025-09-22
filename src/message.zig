const datetime = @import("datetime.zig");
const std = @import("std");
const utils = @import("utils.zig");

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

/// Sends a email body without any multipart content headers.
///
/// Supports html, plain text and attachment.
pub const SingleMessageBody = union(enum) {
    /// Writes the Content-Type as "text/plain".
    text: []const u8,
    /// Writes the Content-Type as "text/html".
    html: []const u8,
    /// Data structure that represents as email attachment.
    attachment: Attachment,

    /// Formats the email message body into the expected header and content values.
    pub fn format(
        self: SingleMessageBody,
        writer: *Writer,
    ) Writer.Error!void {
        switch (self) {
            .text => |slice| {
                try writer.writeAll("Content-Type: text/plain; charset=utf-8\r\n");
                try writer.writeAll("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
                try quotable_printable.encodeWriter(writer, slice);

                return writer.writeAll("\r\n");
            },
            .html => |slice| {
                try writer.writeAll("Content-Type: text/html; charset=utf-8\r\n");
                try writer.writeAll("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
                try quotable_printable.encodeWriter(writer, slice);

                return writer.writeAll("\r\n");
            },
            .attachment => |file| {
                std.debug.assert(file == .attached); // Cannot send inlined email attachment as single message.

                return writer.print("{f}", .{file});
            },
        }
    }
};

/// Sends a email body MIME multipart content headers.
///
/// Supports html, plain text and attachment.
pub const MultipartMessageBody = union(enum) {
    /// Representation of a "multipart/alternative" header.
    alternative: struct {
        text: []const u8,
        html: []const u8,
    },
    /// Representation of a "multipart/mixed" header.
    mixed: struct {
        text: ?[]const u8 = null,
        html: ?[]const u8 = null,
        attachments: []const Attachment,
    },
    /// Representation of a "multipart/related" header.
    related: struct {
        text: ?[]const u8 = null,
        html: []const u8,
        attachments: []const Attachment,
    },

    /// Formats the email message body into the expected header and content values.
    pub fn format(
        self: MultipartMessageBody,
        writer: *Writer,
    ) Writer.Error!void {
        switch (self) {
            .alternative => |body| {
                const boundary = generateMessageBoundary();
                try writer.print("Content-Type: multipart/alternative; boundary=\"{x}\"\r\n\r\n", .{&boundary});

                try writer.print("--{x}\r\n", .{&boundary});
                try writer.writeAll("Content-Type: text/plain; charset=utf-8\r\n");
                try writer.writeAll("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
                try quotable_printable.encodeWriter(writer, body.text);
                try writer.writeAll("\r\n");

                try writer.print("--{x}\r\n", .{&boundary});
                try writer.writeAll("Content-Type: text/html; charset=utf-8\r\n");
                try writer.writeAll("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
                try quotable_printable.encodeWriter(writer, body.html);
                try writer.writeAll("\r\n");

                return writer.print("--{x}--\r\n", .{&boundary});
            },
            .mixed => |body| {
                const boundary = generateMessageBoundary();
                try writer.print("Content-Type: multipart/mixed; boundary=\"{x}\"\r\n\r\n", .{&boundary});

                try writer.print("--{x}\r\n", .{&boundary});
                if (body.html) |html_body| {
                    if (body.text) |text_body| {
                        const boundary_alternative = generateMessageBoundary();
                        try writer.print("Content-Type: multipart/alternative; boundary=\"{x}\"\r\n\r\n", .{&boundary_alternative});

                        try writer.print("--{x}\r\n", .{&boundary_alternative});
                        try writer.writeAll("Content-Type: text/plain; charset=utf-8\r\n");
                        try writer.writeAll("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
                        try quotable_printable.encodeWriter(writer, text_body);
                        try writer.writeAll("\r\n");

                        try writer.print("--{x}\r\n", .{&boundary_alternative});
                        try writer.writeAll("Content-Type: text/html; charset=utf-8\r\n");
                        try writer.writeAll("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
                        try quotable_printable.encodeWriter(writer, html_body);
                        try writer.writeAll("\r\n");

                        try writer.print("--{x}--\r\n\r\n", .{&boundary_alternative});
                    } else {
                        try writer.writeAll("Content-Type: text/html; charset=utf-8\r\n");
                        try writer.writeAll("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
                        try quotable_printable.encodeWriter(writer, html_body);

                        try writer.writeAll("\r\n");
                    }
                } else if (body.text) |text_body| {
                    try writer.writeAll("Content-Type: text/plain; charset=utf-8\r\n");
                    try writer.writeAll("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
                    try quotable_printable.encodeWriter(writer, text_body);

                    try writer.writeAll("\r\n");
                }

                for (body.attachments) |attachment| {
                    std.debug.assert(attachment == .attached); // Cannot send inlined email attachment in multipart/mixed
                    try writer.print("--{x}\r\n", .{&boundary});
                    try writer.print("{f}", .{attachment});
                }

                return writer.print("--{x}--\r\n", .{&boundary});
            },
            .related => |body| {
                const boundary = generateMessageBoundary();
                if (body.text) |text_body| {
                    const boundary_alternative = generateMessageBoundary();
                    try writer.print("Content-Type: multipart/alternative; boundary=\"{x}\"\r\n\r\n", .{&boundary_alternative});

                    try writer.print("--{x}\r\n", .{&boundary_alternative});
                    try writer.writeAll("Content-Type: text/plain; charset=utf-8\r\n");
                    try writer.writeAll("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
                    try quotable_printable.encodeWriter(writer, text_body);
                    try writer.writeAll("\r\n");
                    try writer.print("--{x}\r\n", .{&boundary_alternative});
                }

                try writer.print("Content-Type: multipart/related; boundary=\"{x}\"; type=\"text/html\"\r\n\r\n", .{&boundary});
                try writer.print("--{x}\r\n", .{&boundary});
                try writer.writeAll("Content-Type: text/html; charset=utf-8\r\n");
                try writer.writeAll("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
                try quotable_printable.encodeWriter(writer, body.html);
                try writer.writeAll("\r\n");

                for (body.attachments) |attachment| {
                    std.debug.assert(attachment == .inlined); // Cannot send non inlined email attachment in multipart/related
                    try writer.print("--{x}\r\n", .{&boundary});
                    try writer.print("{f}", .{attachment});
                }

                return writer.print("--{x}--\r\n", .{&boundary});
            },
        }
    }
};

/// Email message body representation.
///
/// Suports MIME multipart headers and "normal" headers.
pub const MessageBody = union(enum) {
    single: SingleMessageBody,
    multipart: MultipartMessageBody,

    /// Formats the email message body depending of the type of it.
    pub fn format(
        self: MessageBody,
        writer: *Writer,
    ) Writer.Error!void {
        return switch (self) {
            inline else => |val| writer.print("{f}", .{val}),
        };
    }
};

/// Data structure that represent an email attachment that
/// can either be inlined or sent just as the attachment.
pub const Attachment = union(enum) {
    /// The attachment can be inlined in the email body if
    /// the email body is a html body.
    ///
    /// Example:
    ///
    /// ```zig
    /// const content_id = try std.fmt.bufPrint(&buffer, "{x}@{s}", .{ message_id.id, message_id.domain });
    /// const html = try std.fmt.bufPrint(&buffer1, "<img src=\"cid:{s}\" alt=\"Fooo\" />", .{content_id});
    /// ```
    inlined: struct {
        content_id: MessageId,
        body_contents: []const u8,
        content_type: []const u8,
        name: ?[]const u8,
    },
    /// Or can be sent as the attachment.
    attached: struct {
        name: []const u8,
        content_type: []const u8,
        body_contents: []const u8,
    },

    /// Formats the email address into the expected header value.
    pub fn format(
        self: Attachment,
        writer: *Writer,
    ) Writer.Error!void {
        switch (self) {
            .attached => |content| {
                try writer.print("Content-Type: {s}; charset=utf-8\r\n", .{content.content_type});
                try writer.writeAll("Content-Transfer-Encoding: base64\r\n");
                try writer.print("Content-Disposition: attachment; filename={s}\r\n\r\n", .{content.name});
                try writer.print("{b64}\r\n", .{content.body_contents});
            },

            .inlined => |content| {
                if (content.name) |name| {
                    try writer.print("Content-Type: {s}; name={s}\r\n", .{ content.content_type, name });
                    try writer.writeAll("Content-Transfer-Encoding: base64\r\n");
                    try writer.print("Content-Disposition: inline; filename={s}\r\n", .{name});
                    try writer.print("Content-Location: {s};\r\n", .{name});
                    try writer.print("Content-Id: {f}\r\n\r\n", .{content.content_id});
                    try writer.print("{b64}\r\n", .{content.body_contents});
                } else {
                    try writer.print("Content-Type: {s};\r\n", .{content.content_type});
                    try writer.writeAll("Content-Transfer-Encoding: base64\r\n");
                    try writer.writeAll("Content-Disposition: inline;\r\n");
                    try writer.print("Content-Id: <{s}>\r\n\r\n", .{content.content_id});
                    try writer.print("{b64}\r\n", .{content.body_contents});
                }
            },
        }
    }
};

/// Data structure that represents and email message.
pub const Message = struct {
    from: EmailAddress,
    to: ?[]const EmailAddress = null,
    cc: ?[]const EmailAddress = null,
    bcc: ?[]const EmailAddress = null,
    subject: ?[]const u8 = null,
    timestamp: ?Datetime = null,
    body: MessageBody,

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
            try writer.writeAll("Subject: ");

            if (!utils.isNonAscii(subject)) {
                @branchHint(.likely);

                try writer.print("{s}\r\n", .{subject});
            } else {
                try writer.writeAll("=?UTF-8?Q?");
                try quotable_printable.encodeWriter(writer, subject);

                try writer.writeAll("?=\r\n");
            }
        }

        const date = self.timestamp orelse datetime.fromUnixTimeStamp(std.time.timestamp());
        try writer.print("Date: {f}\r\n", .{date});

        try writer.writeAll("MIME-Version: 1.0\r\n");

        const message_id = MessageId.generateMessageId(self.from) catch return error.WriteFailed;
        try writer.print("Message-ID: {f}\r\n", .{message_id});

        return writer.print("{f}", .{self.body});
    }
};

/// Generates a message boundary. Uses `std.crypto.random.bytes` for it.
pub fn generateMessageBoundary() [16]u8 {
    var buffer: [16]u8 = undefined;
    std.crypto.random.bytes(&buffer);

    return buffer;
}

/// Data structure that represents a email message id
///
/// Example: <01234567890123456@fooo>
pub const MessageId = struct {
    id: [16]u8,
    domain: []const u8,

    /// Generates a email message id.
    ///
    /// Example: <01234567890123456@fooo>
    pub fn generateMessageId(email: EmailAddress) error{ExpectedEmailDomain}!MessageId {
        const index = std.mem.indexOfScalar(u8, email.address, '@') orelse return error.ExpectedEmailDomain;
        const domain = email.address[index + 1 ..];

        var buffer: [16]u8 = undefined;
        std.crypto.random.bytes(&buffer);

        return .{
            .id = buffer,
            .domain = domain,
        };
    }

    /// Formats the message id to its header representation
    pub fn format(
        self: MessageId,
        writer: *Writer,
    ) Writer.Error!void {
        return writer.print("<{x}@{s}>", .{ &self.id, self.domain });
    }
};

/// Quotable printable encoding implementation.
pub const quotable_printable = struct {
    // Start at 0...75 = 76 for the RFC Max line length.
    const MAX_LINE_LENGTH = 75;

    /// States in the encoding process.
    const State = enum {
        seen_space,
        seen_r,
        seen_r_space,
        seen_n_space,
        seen_rn_space,
        seen_rn,
        start,
    };

    /// Uses the writer as the output to print the encoded slice.
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
                .seen_r => switch (trimmed[index + 1]) {
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
                .seen_space => switch (trimmed[index + 1]) {
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
