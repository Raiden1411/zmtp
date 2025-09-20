const std = @import("std");

const Client = @import("Client.zig");
const Response = Client.Response;
const ServerError = Client.ServerError;

/// Parses the response codes that the server responds with.
pub fn parseResponseCode(code: u16) ServerError {
    return switch (code) {
        403 => error.InvalidTlsHandshake,
        421 => error.ServiceNotAvailable,
        454 => error.TemporaryAuthFailure,
        450 => error.TemporaryMailboxNotAvailable,
        451 => error.ErrorInProcessing,
        452 => error.InsufficientStorage,
        455 => error.UnableToAccomodateParameter,
        500 => error.SyntaxErrorOrCommandNotFound,
        501 => error.InvalidParameter,
        502 => error.CommandNotImplemented,
        503 => error.InvalidCommandSequence,
        504 => error.ParameterNotImplemented,
        530 => error.AuthenticationRequired,
        534 => error.AuthMethodTooWeak,
        535 => error.InvalidCredentials,
        538 => error.EncryptionRequiredForAuthMethod,
        550 => error.MailboxNotAvailable,
        551 => error.UserNotLocal,
        552 => error.ExceededStorageAllocation,
        553 => error.MailboxNotAllowed,
        554 => error.TransactionFailed,
        555 => error.InvalidFromOrRecptParameter,
        else => if (code < 400) error.UnexpectedServerResponse else error.UnknownServerResponse,
    };
}

/// Parses the response that the server sends.
pub fn parseServerResponse(slice: []const u8) !Response {
    std.debug.assert(slice.len > 3); // Invalid response
    const response_code = slice[0..3];

    switch (slice[3]) {
        '-', ' ' => return .{
            .code = try std.fmt.parseInt(u16, response_code, 10),
            .data = slice[4..],
        },
        else => return .{
            .code = try std.fmt.parseInt(u16, response_code, 10),
            .data = slice[3..],
        },
    }
}

/// Traverses the slice and finds if it contains non ascii values.
pub fn isNonAscii(slice: []const u8) bool {
    var remaining = slice;
    const vector_len = std.simd.suggestVectorLength(u8) orelse @sizeOf(usize);
    const Vector = @Vector(vector_len, u8);

    while (slice.len >= vector_len) {
        const chunk: Vector = remaining[0..vector_len].*;
        const mask: Vector = @splat(0x80);
        if (@reduce(.Or, chunk & mask == mask)) {
            // found a non ASCII byte
            break;
        }
        remaining = remaining[vector_len..];
    } else for (remaining) |byte| {
        if (!std.ascii.isAscii(byte))
            return true;
    }

    return false;
}
