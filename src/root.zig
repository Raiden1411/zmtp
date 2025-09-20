/// Credentials and supported authentication by this library.
pub const authentication = @import("authentication.zig");

/// Datetime data structure. Support for RFC 822 formatting.
pub const datetime = @import("datetime.zig");

/// Email message data structure.
///
/// This is where the quotable printable encoder also resides.
pub const message = @import("message.zig");

/// SMTP/SMTPS connection data structure.
pub const connection = @import("connection.zig");

/// Set of utilities used in zmtp
pub const utils = @import("utils.zig");

/// SMTP Email client. Supports tls and non tls connections.
pub const EmailClient = @import("Client.zig");

test {
    _ = authentication;
    _ = datetime;
    _ = message;
    _ = connection;
    _ = utils;

    _ = EmailClient;
}
