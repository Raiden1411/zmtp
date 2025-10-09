const auth = @import("authentication.zig");
const msg = @import("message.zig");
const conn = @import("connection.zig");
const std = @import("std");
const utils = @import("utils.zig");

const Allocator = std.mem.Allocator;
const Auth = auth.Auth;
const CertificateBundle = std.crypto.Certificate.Bundle;
const Connection = conn.Connection;
const ConnectionError = conn.ConnectionError;
const Credentials = auth.Credentials;
const Message = msg.Message;
const ParseIntError = std.fmt.ParseIntError;
const SmtpClient = @This();
const SmtpProtocol = conn.SmtpProtocol;
const Reader = std.Io.Reader;
const TlsClient = std.crypto.tls.Client;
const TlsInitError = conn.TlsInitError;
const TcpConnectToHostError = std.net.TcpConnectToHostError;
const Uri = std.Uri;
const Writer = std.Io.Writer;

/// Allocator used to create the socket connection.
allocator: Allocator,
/// SMTP or SMPTS connection to the socket.
///
/// Must call the `connect` function. If not all actions will cause UB.
///
/// You can also create a specific `Connection` and manually add it to the client.
///
/// See more:
///
/// * Connection.Smtp
/// * Connection.Smtps
connection: *Connection = undefined,
/// Certificate bundle used to perform the tls handshake.
///
/// This client will not rescan the root certificates so please make sure
/// that the provided bundle already has the correct certificates.
ca_bundle: if (conn.disable_tls) void else CertificateBundle = if (conn.disable_tls) {} else .{},
/// Used both for the reader and writer buffers.
tls_buffer_size: if (conn.disable_tls) u0 else usize = if (conn.disable_tls) 0 else TlsClient.min_buffer_len,
/// If non-null, ssl secrets are logged to a stream. Creating such a stream
/// allows other processes with access to that stream to decrypt all
/// traffic over connections created with this `Client`.
ssl_key_log: ?*TlsClient.SslKeyLog = null,
/// Each `Connection` allocates this amount for the reader buffer.
read_buffer_size: usize = 8192,
/// Each `Connection` allocates this amount for the writer buffer.
write_buffer_size: usize = 1024,
/// The negociated server extensions that this client supports.
///
/// If this is null it means this has not been negociated yet with the server.
/// This must happen when calling `serverHandshakeWithCredentials` or `serverHandshake`
server_extensions: ?ClientExtensions = null,

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
pub const SetTargetsError = ReadServerExtensionsError || error{ ExpectToAddress, NoServerHandshakeMade };

/// Set of errors that can happen when performing the tls upgrade request.
pub const StartTlsError = TlsInitError || GreetingsError || error{InvalidTlsHandshakeResponse};

/// Set of errors that can happen when sending an email.
pub const SendEmailError = SetTargetsError || StartTlsError;

/// Set of errors that can happen when sending and authenticated email.
pub const ServerAuthHandshake = StartTlsError || ReadServerExtensionsError || error{ UnsupportedAuthHandshake, TlsRequiredForAuth };

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
    self: *SmtpClient,
    url: []const u8,
) ConnectError!void {
    const gpa = self.allocator;

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
        .smtp => &(try Connection.Smtp.create(self, host, port, stream)).connection,
        .smtps => &(try Connection.Smtps.create(self, host, port, stream)).connection,
    };

    self.connection = connection;
}

/// Closes the connections and frees any allocated memory.
pub fn deinit(self: *SmtpClient) void {
    self.connection.close();
    self.connection.destroy();
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

/// Sends email to the server.
///
/// The server handshake must have been made beforehand in order to send emails.
/// If no handshake was made prior this will error.
pub fn sendEmail(
    self: *SmtpClient,
    message: Message,
) SendEmailError!void {
    try self.setEmailTargets(message);

    return self.sendEmailBody(message);
}

/// Sets the email targets for the email and prepares the email for DATA.
/// Assumes that the extensions negociation has already been made. Otherwise this will fail.
///
/// If SMTPUTF8 or 8BITMIME is supported it will append to the `MAIL FROM` exchange.
///
/// Example:
///
/// -> MAIL FROM:<foo@bar.com>
/// -> RCPT TO:<baz@bar.com>
/// -> DATA\r\n
///
/// See also:
///
/// * sendEmail
/// * sendEmailBody
pub fn setEmailTargets(
    self: *SmtpClient,
    message: Message,
) SetTargetsError!void {
    const extensions = self.server_extensions orelse return error.NoServerHandshakeMade;

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
///
/// See also:
///
/// * setEmailTargets
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

/// Performs the inital server handshake.
/// Upgrades the connection to tls if the server supports it.
///
/// This will not authenticate to the server if it is required!
///
/// See also:
///
/// * serverHandshakeWithCredentials
/// * readServerExtensions
/// * greetings
/// * startTls
pub fn serverHandshake(self: *SmtpClient) (StartTlsError || ReadServerExtensionsError)!void {
    try self.greetings();

    const extensions = blk: {
        if (self.server_extensions) |extensions|
            break :blk extensions;

        const extensions = try self.readServerExtensions();
        self.server_extensions = extensions;

        break :blk extensions;
    };

    if (self.connection.protocol == .smtp and extensions.upgrade_tls)
        try self.startTls();
}

/// Performs the inital server handshake. Upgrades the connection to tls and authenticates it.
/// If the server doesn't support the STARTTLS exchange this will fail.
///
/// See also:
///
/// * serverHandshake
/// * readServerExtensions
/// * greetings
/// * startTls
pub fn serverHandshakeWithCredentials(
    self: *SmtpClient,
    cred: Credentials,
) ServerAuthHandshake!void {
    try self.serverHandshake();

    if (self.connection.protocol == .smtp) {
        if (!self.server_extensions.?.upgrade_tls)
            return error.TlsRequiredForAuth;

        try self.startTls();
    }

    std.debug.assert(self.connection.protocol == .smtps); // Auth must be done via tls connection

    const auth_type = self.server_extensions.?.auth orelse return error.UnsupportedAuthHandshake;

    return cred.encode(auth_type, self.connection);
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
        self,
        self.connection.hostname(),
        self.connection.port,
        self.connection.getStream(),
    );

    self.connection.destroy();
    self.connection = &tls.connection;
}

test "SendEmail" {
    var bundle: CertificateBundle = .{};
    defer bundle.deinit(std.testing.allocator);

    try bundle.addCertsFromFilePathAbsolute(std.testing.allocator, "/home/raiden/cert.pem");

    var client: SmtpClient = .{
        .allocator = std.testing.allocator,
        .ca_bundle = bundle,
    };
    defer client.deinit();

    try client.connect("smtp://localhost:1025");

    const cred: Credentials = .{
        .username = "foo",
        .password = "bar",
    };

    try client.serverHandshakeWithCredentials(cred);

    try client.sendEmail(.{
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
    });
}
