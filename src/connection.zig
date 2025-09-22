const std = @import("std");

const Allocator = std.mem.Allocator;
const CertificateBundle = std.crypto.Certificate.Bundle;
const NetStream = std.net.Stream;
const Reader = std.Io.Reader;
const TlsClient = std.crypto.tls.Client;
const Writer = std.Io.Writer;

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
pub const ConnectionError = NetStream.ReadError || NetStream.WriteError || error{StreamTooLong} || TlsClient.ReadError;

/// Data structure that represents a SMTP/SMTPs connection.
///
/// Reader and Writer will differ based on the type of the connection.
pub const Connection = struct {
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
    pub fn close(self: *Connection) void {
        const stream = self.getStream();
        defer stream.close();

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
        return self.stream_reader.getStream();
    }

    /// Hostname of the associated connection
    pub fn hostname(self: *Connection) []const u8 {
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
    pub fn destroy(self: *Connection, gpa: Allocator) void {
        switch (self.protocol) {
            .smtp => {
                const smtp: *Smtp = @alignCast(@fieldParentPtr("connection", self));
                return smtp.destroy(gpa);
            },
            .smtps => {
                if (disable_tls) unreachable;

                const smtps: *Smtps = @alignCast(@fieldParentPtr("connection", self));
                return smtps.destroy(gpa);
            },
        }
    }

    /// Gets the reader based on the connection scheme.
    pub fn reader(self: *Connection) *Reader {
        switch (self.protocol) {
            .smtp => return self.stream_reader.interface(),
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
        const reader_buffer_size = 8192;
        const writer_buffer_size = 1024;

        connection: Connection,

        /// Creates the connection and the required readers and writers.
        pub fn create(
            gpa: Allocator,
            host: []const u8,
            port: u16,
            stream: NetStream,
        ) Allocator.Error!*Smtp {
            const allocation_size = getAllocationSize(host.len);

            const base = try gpa.alignedAlloc(u8, .of(Smtp), allocation_size);
            errdefer gpa.free(base);

            const host_buffer = base[@sizeOf(Smtp)..][0..host.len];
            const reader_buffer = host_buffer.ptr[host_buffer.len..][0..reader_buffer_size];
            const writer_buffer = reader_buffer.ptr[reader_buffer.len..][0..writer_buffer_size];

            std.debug.assert(base.ptr + allocation_size == writer_buffer.ptr + writer_buffer.len);
            @memcpy(host_buffer, host);

            const smtp: *Smtp = @ptrCast(base);

            smtp.* = .{
                .connection = .{
                    .host_len = @intCast(host.len),
                    .port = port,
                    .protocol = .smtp,
                    .stream_reader = stream.reader(reader_buffer),
                    .stream_writer = stream.writer(writer_buffer),
                },
            };

            return smtp;
        }

        /// Helper to get the total allocated memory upfront.
        fn getAllocationSize(host_len: usize) usize {
            return reader_buffer_size + writer_buffer_size + @sizeOf(Smtp) + host_len;
        }

        /// Destroys the pointer all frees all of the extra memory.
        fn destroy(self: *Smtp, gpa: Allocator) void {
            const base: [*]align(@alignOf(Smtp)) u8 = @ptrCast(self);
            gpa.free(base[0..getAllocationSize(self.connection.host_len)]);
        }

        /// Hostname of the associated connection
        fn hostname(self: *Smtp) []u8 {
            const base: [*]u8 = @ptrCast(self);
            return base[@sizeOf(Smtp)..][0..self.connection.host_len];
        }
    };

    /// SMTP Connection representation
    pub const Smtps = struct {
        const tls_buffer_size = if (disable_tls) 0 else TlsClient.min_buffer_len;
        const reader_buffer_size = 8192;
        const writer_buffer_size = 1024;

        connection: Connection,
        tls_client: TlsClient,

        /// Estabilshes the tls handshake and creates the
        /// required readers and writers to interact with the socket.
        pub fn create(
            gpa: Allocator,
            host: []const u8,
            port: u16,
            stream: NetStream,
        ) TlsInitError!*Smtps {
            const allocation_size = getAllocationSize(host.len);

            const base = try gpa.alignedAlloc(u8, .of(Smtps), allocation_size);
            errdefer gpa.free(base);

            const host_buffer = base[@sizeOf(Smtps)..][0..host.len];

            const smtps_reader_buffer = host_buffer.ptr[host_buffer.len..][0 .. tls_buffer_size + reader_buffer_size];
            const smtps_writer_buffer = smtps_reader_buffer.ptr[smtps_reader_buffer.len..][0..tls_buffer_size];

            const writer_buffer = smtps_writer_buffer.ptr[smtps_writer_buffer.len..][0..writer_buffer_size];
            const reader_buffer = writer_buffer.ptr[writer_buffer.len..][0..tls_buffer_size];

            std.debug.assert(base.ptr + allocation_size == reader_buffer.ptr + reader_buffer.len);
            @memcpy(host_buffer, host);

            const smtps: *Smtps = @ptrCast(base);

            var bundle: CertificateBundle = .{};
            defer bundle.deinit(gpa);

            try bundle.rescan(gpa);

            smtps.* = .{
                .connection = .{
                    .host_len = @intCast(host.len),
                    .port = port,
                    .protocol = .smtps,
                    .stream_reader = stream.reader(smtps_reader_buffer),
                    .stream_writer = stream.writer(smtps_writer_buffer),
                },

                .tls_client = try TlsClient.init(
                    smtps.connection.stream_reader.interface(),
                    &smtps.connection.stream_writer.interface,
                    .{
                        .host = .{ .explicit = host },
                        .ca = .{ .bundle = bundle },
                        .ssl_key_log = null,
                        .read_buffer = reader_buffer,
                        .write_buffer = writer_buffer,
                        // This is appropriate for HTTPS because the HTTP headers contain
                        // the content length which is used to detect truncation attacks.
                        .allow_truncation_attacks = true,
                    },
                ),
            };

            return smtps;
        }

        /// Helper to get the total allocated memory upfront.
        fn getAllocationSize(host_len: usize) usize {
            return reader_buffer_size + writer_buffer_size + @sizeOf(Smtps) + host_len + (tls_buffer_size * 3);
        }

        /// Destroys the pointer all frees all of the extra memory.
        fn destroy(self: *Smtps, gpa: Allocator) void {
            const conn = &self.connection;

            const base: [*]align(@alignOf(Smtps)) u8 = @ptrCast(self);
            gpa.free(base[0..getAllocationSize(conn.host_len)]);
        }

        /// Hostname of the associated connection
        fn hostname(self: *Smtps) []u8 {
            const base: [*]u8 = @ptrCast(self);
            return base[@sizeOf(Smtps)..][0..self.connection.host_len];
        }
    };
};
