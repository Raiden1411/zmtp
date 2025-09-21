const auth = @import("authentication.zig");
const msg = @import("message.zig");
const conn = @import("connection.zig");
const std = @import("std");
const utils = @import("utils.zig");

const Allocator = std.mem.Allocator;
const Auth = auth.Auth;
const Connection = conn.Connection;
const ConnectionError = conn.ConnectionError;
const Credentials = auth.Credentials;
const Message = msg.Message;
const ParseIntError = std.fmt.ParseIntError;
const SmtpClient = @This();
const SmtpProtocol = conn.SmtpProtocol;
const Reader = std.Io.Reader;
const TlsInitError = conn.TlsInitError;
const TcpConnectToHostError = std.net.TcpConnectToHostError;
const Uri = std.Uri;
const Writer = std.Io.Writer;

/// Allocator used to create the socket connection.
allocator: Allocator,
/// SMTP or SMPTS connection to the socket.
connection: *Connection,

/// Errors that a smtp server can respond with.
pub const ServerError = error{
    InvalidTlsHandshake,
    ServiceNotAvailable,
    TemporaryAuthFailure,
    TemporaryMailboxNotAvailable,
    ErrorInProcessing,
    InsufficientStorage,
    UnableToAccomodateParameter,
    SyntaxErrorOrCommandNotFound,
    InvalidParameter,
    CommandNotImplemented,
    InvalidCommandSequence,
    ParameterNotImplemented,
    AuthenticationRequired,
    AuthMethodTooWeak,
    InvalidCredentials,
    EncryptionRequiredForAuthMethod,
    MailboxNotAvailable,
    UserNotLocal,
    ExceededStorageAllocation,
    MailboxNotAllowed,
    TransactionFailed,
    InvalidFromOrRecptParameter,
    UnknownServerResponse,
    UnexpectedServerResponse,
};

/// Set of errors path can happen when performing the greetings function.
pub const GreetingsError = Reader.Error || Writer.Error || ServerError ||
    ConnectionError || ParseIntError || error{InvalidServerGrettings};

/// Set of errors that can happen when reading the server extensions.
pub const ReadServerExtensionsError = error{HandshakeOversize} || GreetingsError;

/// Set of errors that can happen when performing the handshake.
pub const HandshakeError = ReadServerExtensionsError || error{ExpectToAddress};

/// Set of errors that can happen when performing the tls upgrade request.
pub const StartTlsError = TlsInitError || GreetingsError || error{InvalidTlsHandshakeResponse};

/// Set of errors that can happen when sending an email.
pub const SendEmailError = HandshakeError || StartTlsError;

/// Set of errors that can happen when sending and authenticated email.
pub const SendEmailAuthError = SendEmailError || error{ UnsupportedAuthHandshake, TlsRequiredForAuth };

/// Set of errors that can happen when performing the initial smtp server connection.
pub const ConnectError = Uri.ParseError || TlsInitError || TcpConnectToHostError ||
    ConnectionError || error{ InvalidSmptScheme, UriMissingHost, UriHostTooLong };

/// Data structure to represent a server response.
pub const Response = struct {
    code: u16,
    data: []const u8,
};

/// Set of supported client extensions.
pub const Extensions = enum {
    AUTH,
    SMTPUTF8,
    @"8BITMIME",
    STARTTLS,
};

/// Set of supported client extensions.
pub const ClientExtensions = struct {
    eigth_bit_mime: bool = false,
    smtp_utf8: bool = false,
    upgrade_tls: bool = false,
    auth: ?Auth = null,
};

/// Establishes a connection to the socket and doesn't perform
/// any other actions.
///
/// If no port is provided the client will use
/// 1025 for SMTP connections and 465 for SMPTS connections.
pub fn connect(
    gpa: Allocator,
    url: []const u8,
) ConnectError!SmtpClient {
    const uri = try Uri.parse(url);
    const scheme = SmtpProtocol.fromScheme(uri.scheme) orelse return error.InvalidSmptScheme;

    var buffer: [Uri.host_name_max]u8 = undefined;
    const host = try uri.getHost(&buffer);

    const port: u16 = uri.port orelse switch (scheme) {
        .smtp => 1025,
        .smtps => 465,
    };

    const stream = try std.net.tcpConnectToHost(gpa, host, port);
    const connection = switch (scheme) {
        .smtp => &(try Connection.Smtp.create(gpa, host, port, stream)).connection,
        .smtps => &(try Connection.Smtps.create(gpa, host, port, stream)).connection,
    };

    return .{
        .allocator = gpa,
        .connection = connection,
    };
}

/// Closes the connections and frees any allocated memory.
pub fn deinit(self: *SmtpClient) void {
    self.connection.close();
    self.connection.destroy(self.allocator);
}

/// Upgrades the connection to a TLS connection.
///
/// Email server must support `STARTTLS` exchange. Otherwise this might block or fail.
/// After establishing the connection it will send the `EHLO` exchange.
pub fn startTls(self: *SmtpClient) StartTlsError!void {
    std.debug.assert(self.connection.protocol == .smtp); // Connection already tls

    try self.connection.writer().writeAll("STARTTLS\r\n");
    try self.connection.flush();

    const tls_start = try self.connection.reader().takeDelimiterInclusive('\n');

    const response_start = try utils.parseServerResponse(tls_start);
    if (response_start.code != 220)
        return error.InvalidTlsHandshakeResponse;

    const tls = try Connection.Smtps.create(
        self.allocator,
        self.connection.hostname(),
        self.connection.port,
        self.connection.getStream(),
    );

    self.connection.destroy(self.allocator);
    self.connection = &tls.connection;
}

/// Starts the greetings exchange and send the `EHLO` exchange.
pub fn greetings(self: *SmtpClient) GreetingsError!void {
    // Server always responds first so we fill the buffer
    // The first read might not fill the buffered so we force it
    try self.connection.reader().fill(1);

    const hello = try self.connection.reader().takeDelimiterInclusive('\n');

    const response = try utils.parseServerResponse(hello);
    if (response.code != 220)
        return error.InvalidServerGrettings;

    try self.connection.writer().writeAll("EHLO\r\n");
    try self.connection.flush();
}

/// Reads the supported server extensions and parses them.
///
/// If this client doesn't support a server extensions it will not affect it.
pub fn readServerExtensions(self: *SmtpClient) ReadServerExtensionsError!ClientExtensions {
    const reader = self.connection.reader();

    var head_len: usize = 0;
    var client_extension: ClientExtensions = .{};

    // The first read might not fill the buffer so we force it
    try self.connection.reader().fill(1);

    while (true) {
        if (reader.buffer.len - head_len == 0)
            return error.HandshakeOversize;

        const remaining = reader.buffered()[head_len..];

        if (remaining.len == 0) {
            reader.toss(head_len);

            return client_extension;
        }

        if (std.mem.indexOfScalar(u8, remaining, '\n')) |index| {
            @branchHint(.likely);
            defer head_len += index + 1;

            // Removes \r\n from the response offering.
            const response = try utils.parseServerResponse(remaining[0 .. index - 1]);

            if (response.code != 250)
                return utils.parseResponseCode(response.code);

            var iter = std.mem.tokenizeScalar(u8, response.data, ' ');

            const extension = iter.next().?; // Always yields at least once.
            const parsed = std.meta.stringToEnum(Extensions, extension) orelse continue;

            switch (parsed) {
                // Auth extension response is 250-AUTH PLAIN LOGIN ...
                // So can take the rest of the string and parse it
                .AUTH => client_extension.auth = auth.parseAuthOfferings(iter.rest()),
                .SMTPUTF8 => client_extension.smtp_utf8 = true,
                .@"8BITMIME" => client_extension.eigth_bit_mime = true,
                .STARTTLS => client_extension.upgrade_tls = true,
            }

            continue;
        }

        reader.toss(head_len);

        return client_extension;
    }
}

/// Performs the handshake exchange where it sends the servers the information that it needs.
///
/// If SMTPUTF8 or 8BITMIME is supported it will append to the `MAIL FROM` exchange.
///
/// Example:
///
/// -> MAIL FROM:<foo@bar.com>
/// -> RCPT TO:<baz@bar.com>
/// -> DATA\r\n
pub fn handshake(
    self: *SmtpClient,
    message: Message,
    extensions: ClientExtensions,
) HandshakeError!void {
    const writer = self.connection.writer();
    const reader = self.connection.reader();

    try writer.print("MAIL FROM:{f}", .{message.from});
    if (extensions.eigth_bit_mime)
        try writer.writeAll(" BODY=8BITMIME");

    if (extensions.smtp_utf8)
        try writer.writeAll(" SMTPUTF8");
    try writer.writeAll("\r\n");
    try self.connection.flush();

    try reader.fillMore();
    const response = try utils.parseServerResponse(try reader.takeDelimiterInclusive('\n'));
    if (response.code != 250)
        return utils.parseResponseCode(response.code);

    const to = message.to orelse return error.ExpectToAddress;

    try writer.writeAll("RCPT TO:");
    for (to) |address|
        try writer.print("{f} ", .{address});
    try writer.writeAll("\r\n");
    try self.connection.flush();

    try reader.fillMore();
    const response_to = try utils.parseServerResponse(try reader.takeDelimiterInclusive('\n'));
    if (response_to.code != 250)
        return utils.parseResponseCode(response_to.code);

    try writer.writeAll("DATA\r\n");
    try self.connection.flush();

    try reader.fillMore();
    const response_data = try utils.parseServerResponse(try reader.takeDelimiterInclusive('\n'));
    if (response_data.code != 354)
        return utils.parseResponseCode(response_data.code);
}

/// Send the email body with the necessary headers.
///
/// The generated headers will depend on the message that will
/// be sent to the server.
///
/// Make sure that you have made the required handshakes before using this.
pub fn sendEmailBody(self: *SmtpClient, message: Message) GreetingsError!void {
    const reader = self.connection.reader();
    const writer = self.connection.writer();

    try writer.print("{f}", .{message});
    try writer.writeAll(".\r\n");
    try self.connection.flush();

    try reader.fillMore();
    const response = try utils.parseServerResponse(try reader.takeDelimiterInclusive('\n'));
    if (response.code != 250)
        return utils.parseResponseCode(response.code);
}

/// Sends unauthenticated email to the server.
/// This prefers tls connections when it is supported by the server.
///
/// Performs all of the necessary actions in order to send the email successfully.
///
/// This assumes that the greetings exchange has not been made and that
/// the server extensions have not been parsed.
pub fn sendEmail(
    self: *SmtpClient,
    message: Message,
) SendEmailError!void {
    try self.greetings();
    const extensions = try self.readServerExtensions();

    if (self.connection.protocol == .smtp and extensions.upgrade_tls)
        try self.startTls();

    try self.handshake(message, extensions);

    return self.sendEmailBody(message);
}

/// Sends the email to the server with the specified credentials.
///
/// This will upgrade the connection to tls. So the server must support this.
/// Performs all of the necessary actions in order to send the email successfully.
///
/// This assumes that the greetings exchange has not been made and that
/// the server extensions have not been parsed.
pub fn sendEmailWithCredentials(
    self: *SmtpClient,
    message: Message,
    cred: Credentials,
) SendEmailAuthError!void {
    try self.greetings();
    const extensions = try self.readServerExtensions();

    if (self.connection.protocol == .smtp) {
        if (!extensions.upgrade_tls)
            return error.TlsRequiredForAuth;

        try self.startTls();
    }

    std.debug.assert(self.connection.protocol == .smtps); // Auth must be done via tls connection

    const auth_type = extensions.auth orelse return error.UnsupportedAuthHandshake;
    try cred.encode(auth_type, self.connection);

    try self.handshake(message, extensions);

    return self.sendEmailBody(message);
}

/// Upgrades the connection to TLS and sends an unauthenticated email to the server.
///
/// Performs all of the necessary actions in order to send the email successfully.
///
/// This assumes that the greetings exchange has not been made and that
/// the server extensions have not been parsed.
pub fn upgradeAndSendEmail(
    self: *SmtpClient,
    message: Message,
) SendEmailError!void {
    std.debug.assert(self.connection.protocol == .smtp); // Connection must be smtp for upgrade

    try self.greetings();
    const extensions = try self.readServerExtensions();

    if (!extensions.upgrade_tls)
        return error.UnsupportedTlsUpgrade;

    try self.startTls();
    std.debug.assert(self.connection.protocol == .smtps); // Connection must be smtps after the upgrade

    try self.handshake(message, extensions);

    return self.sendEmailBody(message);
}

test "SendEmail" {
    var client = try SmtpClient.connect(std.testing.allocator, "smtp://localhost:1025");
    defer client.deinit();

    const cred: Credentials = .{
        .username = "foo",
        .password = "bar",
    };

    try client.sendEmailWithCredentials(.{
        .from = .{ .address = "fooo@exp.pt" },
        .to = &.{
            .{ .address = "fooo@exp.br" },
        },
        .subject = "THIS IS A TEST 🥱",
        .body = .{
            .multipart = .{
                .alternative = .{
                    .text = "HELLO FOÓ 🥱",
                    .html = "<p> THIS IS A TEST </p>",
                },
            },
        },
    }, cred);
}
