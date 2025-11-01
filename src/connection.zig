const std = @import("std");

const Allocator = std.mem.Allocator;
const CertificateBundle = std.crypto.Certificate.Bundle;
const HostName = Io.net.HostName;
const Io = std.Io;
const NetStream = Io.net.Stream;
const Reader = Io.Reader;
const SmtpClient = @import("Client.zig");
const TlsClient = std.crypto.tls.Client;
const Writer = Io.Writer;
const Uri = std.Uri;

pub const disable_tls = std.options.http_disable_tls;

/// Protocols supported by the connection.
pub const SmtpProtocol = enum {
    smtp,
    smtps,

    pub fn fromScheme(scheme: []const u8) ?SmtpProtocol {
        const scheme_map = std.StaticStringMap(SmtpProtocol).initComptime(.{
            .{ "smtp", .smtp },
            .{ "smtps", .smtps },
        });

        return scheme_map.get(scheme);
    }
};

/// Present in zig but it's not public.
pub const TlsInitError = error{
    WriteFailed,
    ReadFailed,
    InsufficientEntropy,
    DiskQuota,
    LockViolation,
    NotOpenForWriting,
    /// The alert description will be stored in `alert`.
    TlsAlert,
    TlsUnexpectedMessage,
    TlsIllegalParameter,
    TlsDecryptFailure,
    TlsRecordOverflow,
    TlsBadRecordMac,
    CertificateFieldHasInvalidLength,
    CertificateHostMismatch,
    CertificatePublicKeyInvalid,
    CertificateExpired,
    CertificateFieldHasWrongDataType,
    CertificateIssuerMismatch,
    CertificateNotYetValid,
    CertificateSignatureAlgorithmMismatch,
    CertificateSignatureAlgorithmUnsupported,
    CertificateSignatureInvalid,
    CertificateSignatureInvalidLength,
    CertificateSignatureNamedCurveUnsupported,
    CertificateSignatureUnsupportedBitCount,
    TlsCertificateNotVerified,
    TlsBadSignatureScheme,
    TlsBadRsaSignatureBitCount,
    InvalidEncoding,
    IdentityElement,
    SignatureVerificationFailed,
    TlsDecryptError,
    TlsConnectionTruncated,
    TlsDecodeError,
    UnsupportedCertificateVersion,
    CertificateTimeInvalid,
    CertificateHasUnrecognizedObjectId,
    CertificateHasInvalidBitString,
    MessageTooLong,
    NegativeIntoUnsigned,
    TargetTooSmall,
    BufferTooSmall,
    InvalidSignature,
    NotSquare,
    NonCanonical,
    WeakPublicKey,
} || Allocator.Error || CertificateBundle.RescanError;

/// Connection reads and writes errors.
pub const ConnectionError = Reader.StreamError || Writer.FileError || error{StreamTooLong} || TlsClient.ReadError;

/// Data structure that represents a SMTP/SMTPs connection.
///
/// Reader and Writer will differ based on the type of the connection.
pub const Connection = struct {
    client: *SmtpClient,
    /// The writer that will be used to write to the stream connection.
    stream_writer: NetStream.Writer,
    /// The reader that will be used to read data from the socket.
    stream_reader: NetStream.Reader,
    /// The smtp protocol that this connection will use.
    protocol: SmtpProtocol,
    /// The hostname len associated with this connection
    host_len: u8,
    /// Port associated with this connection
    port: u16,

    /// Send the close handshake and closes the socket connection.
    pub fn close(self: *Connection, io: Io) void {
        const stream = self.getStream();
        defer stream.close(io);

        self.end() catch {};
    }

    /// Sends all of the close handshakes required.
    pub fn end(self: *Connection) Writer.Error!void {
        if (self.protocol == .smtps) {
            if (disable_tls) unreachable;

            const smtps: *Smtps = @alignCast(@fieldParentPtr("connection", self));
            try smtps.tls_client.end();
        }

        try self.stream_writer.interface.writeAll("QUIT\r\n");
        try self.stream_writer.interface.flush();
    }

    /// Gets the underlaying socket stream.
    pub fn getStream(self: *Connection) NetStream {
        return self.stream_reader.stream;
    }

    /// Hostname of the associated connection
    pub fn hostname(self: *Connection) HostName {
        switch (self.protocol) {
            .smtp => {
                const smtp: *Smtp = @alignCast(@fieldParentPtr("connection", self));
                return smtp.hostname();
            },
            .smtps => {
                if (disable_tls) unreachable;

                const smtps: *Smtps = @alignCast(@fieldParentPtr("connection", self));
                return smtps.hostname();
            },
        }
    }

    /// Destroys the pointer all frees all of the extra memory.
    pub fn destroy(self: *Connection) void {
        switch (self.protocol) {
            .smtp => {
                const smtp: *Smtp = @alignCast(@fieldParentPtr("connection", self));
                return smtp.destroy();
            },
            .smtps => {
                if (disable_tls) unreachable;

                const smtps: *Smtps = @alignCast(@fieldParentPtr("connection", self));
                return smtps.destroy();
            },
        }
    }

    /// Gets the reader based on the connection scheme.
    pub fn reader(self: *Connection) *Reader {
        switch (self.protocol) {
            .smtp => return &self.stream_reader.interface,
            .smtps => {
                if (disable_tls) unreachable;

                const smtps: *Smtps = @alignCast(@fieldParentPtr("connection", self));
                return &smtps.tls_client.reader;
            },
        }
    }

    /// Gets the writer based on the connection scheme.
    pub fn writer(self: *Connection) *Writer {
        switch (self.protocol) {
            .smtp => return &self.stream_writer.interface,
            .smtps => {
                if (disable_tls) unreachable;

                const smtps: *Smtps = @alignCast(@fieldParentPtr("connection", self));
                return &smtps.tls_client.writer;
            },
        }
    }

    /// Flushes the buffer and writes to the socket.
    pub fn flush(self: *Connection) Writer.Error!void {
        if (self.protocol == .smtps) {
            if (disable_tls) unreachable;

            const smtps: *Smtps = @alignCast(@fieldParentPtr("connection", self));
            try smtps.tls_client.writer.flush();
        }

        return self.stream_writer.interface.flush();
    }

    /// SMTP Connection representation
    pub const Smtp = struct {
        connection: Connection,

        /// Creates the connection and the required readers and writers.
        pub fn create(
            client: *SmtpClient,
            host: HostName,
            port: u16,
            stream: NetStream,
        ) Allocator.Error!*Smtp {
            const gpa = client.allocator;
            const allocation_size = getAllocationSize(client, host.bytes.len);

            const base = try gpa.alignedAlloc(u8, .of(Smtp), allocation_size);
            errdefer gpa.free(base);

            const host_buffer = base[@sizeOf(Smtp)..][0..host.bytes.len];
            const reader_buffer = host_buffer.ptr[host_buffer.len..][0..client.read_buffer_size];
            const writer_buffer = reader_buffer.ptr[reader_buffer.len..][0..client.write_buffer_size];

            std.debug.assert(base.ptr + allocation_size == writer_buffer.ptr + writer_buffer.len);
            @memcpy(host_buffer, host.bytes);

            const smtp: *Smtp = @ptrCast(base);

            smtp.* = .{
                .connection = .{
                    .client = client,
                    .host_len = @intCast(host.bytes.len),
                    .port = port,
                    .protocol = .smtp,
                    .stream_reader = stream.reader(client.io, reader_buffer),
                    .stream_writer = stream.writer(client.io, writer_buffer),
                },
            };

            return smtp;
        }

        /// Helper to get the total allocated memory upfront.
        fn getAllocationSize(client: *SmtpClient, host_len: usize) usize {
            return client.read_buffer_size + client.write_buffer_size + @sizeOf(Smtp) + host_len;
        }

        /// Destroys the pointer all frees all of the extra memory.
        fn destroy(self: *Smtp) void {
            const conn = &self.connection;

            const base: [*]align(@alignOf(Smtp)) u8 = @ptrCast(self);
            conn.client.allocator.free(base[0..getAllocationSize(conn.client, self.connection.host_len)]);
        }

        /// Hostname of the associated connection
        fn hostname(self: *Smtp) HostName {
            const base: [*]u8 = @ptrCast(self);
            return .{ .bytes = base[@sizeOf(Smtp)..][0..self.connection.host_len] };
        }
    };

    /// SMTP Connection representation
    pub const Smtps = struct {
        connection: Connection,
        tls_client: TlsClient,

        /// Estabilshes the tls handshake and creates the
        /// required readers and writers to interact with the socket.
        ///
        /// Leave the host empty if you wish to perform a no_verification check
        pub fn create(
            client: *SmtpClient,
            host: HostName,
            port: u16,
            stream: NetStream,
        ) TlsInitError!*Smtps {
            const gpa = client.allocator;
            const allocation_size = getAllocationSize(client, host.bytes.len);

            const base = try gpa.alignedAlloc(u8, .of(Smtps), allocation_size);
            errdefer gpa.free(base);

            const host_buffer = base[@sizeOf(Smtps)..][0..host.bytes.len];

            const smtps_reader_buffer = host_buffer.ptr[host_buffer.len..][0 .. client.tls_buffer_size + client.read_buffer_size];
            const smtps_writer_buffer = smtps_reader_buffer.ptr[smtps_reader_buffer.len..][0..client.tls_buffer_size];

            const writer_buffer = smtps_writer_buffer.ptr[smtps_writer_buffer.len..][0..client.write_buffer_size];
            const reader_buffer = writer_buffer.ptr[writer_buffer.len..][0..client.tls_buffer_size];

            std.debug.assert(base.ptr + allocation_size == reader_buffer.ptr + reader_buffer.len);
            @memcpy(host_buffer, host.bytes);

            var random_buffer: [176]u8 = undefined;
            std.crypto.random.bytes(&random_buffer);

            const smtps: *Smtps = @ptrCast(base);

            smtps.* = .{
                .connection = .{
                    .client = client,
                    .host_len = @intCast(host.bytes.len),
                    .port = port,
                    .protocol = .smtps,
                    .stream_reader = stream.reader(client.io, smtps_reader_buffer),
                    .stream_writer = stream.writer(client.io, smtps_writer_buffer),
                },

                .tls_client = try TlsClient.init(
                    &smtps.connection.stream_reader.interface,
                    &smtps.connection.stream_writer.interface,
                    .{
                        .host = if (host.bytes.len != 0) .{ .explicit = host.bytes } else .no_verification,
                        .ca = .{ .bundle = client.ca_bundle },
                        .ssl_key_log = null,
                        .read_buffer = reader_buffer,
                        .write_buffer = writer_buffer,
                        // This is appropriate for HTTPS because the HTTP headers contain
                        // the content length which is used to detect truncation attacks.
                        .allow_truncation_attacks = true,
                        .entropy = &random_buffer,
                        .realtime_now_seconds = (try Io.Clock.real.now(client.io)).toSeconds(),
                    },
                ),
            };

            return smtps;
        }

        /// Helper to get the total allocated memory upfront.
        fn getAllocationSize(client: *SmtpClient, host_len: usize) usize {
            return client.read_buffer_size + client.write_buffer_size + @sizeOf(Smtps) + host_len + (client.tls_buffer_size * 3);
        }

        /// Destroys the pointer all frees all of the extra memory.
        fn destroy(self: *Smtps) void {
            const conn = &self.connection;

            const base: [*]align(@alignOf(Smtps)) u8 = @ptrCast(self);
            conn.client.allocator.free(base[0..getAllocationSize(conn.client, conn.host_len)]);
        }

        /// Hostname of the associated connection
        fn hostname(self: *Smtps) HostName {
            const base: [*]u8 = @ptrCast(self);
            return .{ .bytes = base[@sizeOf(Smtps)..][0..self.connection.host_len] };
        }
    };
};
