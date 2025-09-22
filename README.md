### Overview
ZMTP is a smtp client library used to interact with email smtp servers.


### Installing Zig
You can install the latest version of zig [here](https://ziglang.org/download/) or you can also use a version manager like [zvm](https://www.zvm.app/guides/install-zvm/) to manage your zig version.


### Integration
In the `build.zig.zon` file, add the following to the dependencies object.

```zig
.zmtp = .{
    .url = "https://github.com/Raiden1411/zmtp/archive/VERSION_NUMBER.tar.gz",
}
```

The compiler will produce a hash mismatch error, add the `.hash` field to `build.zig.zon` with the hash the compiler tells you it found.
You can also use `zig fetch` to automatically do the above steps.

```bash
zig fetch --save https://github.com/Raiden1411/zmtp/archive/VERSION_NUMBER.tar.gz 
zig fetch --save git+https://github.com/Raiden1411/zmtp.git#LATEST_COMMIT
```

Then in your `build.zig` file add the following to the `exe` section for the executable where you wish to have `zmtp` available.

```zig
const module = b.dependency("zmtp", .{}).module("zmtp");
// for exe, lib, tests, etc.
exe.root_module.addImport("zmtp", module);
```

Now in the code, you can import components like this:

```zig
const zmtp = @import("zmtp");

const EmailClient = zmtp.EmailClient;
```

### Example Usage
You can check of the examples in the example/ folder but for a simple introduction you can checkout the bellow example.

```zig
const std = @import("std");
const zmtp = @import("zmtp");

const CertificateBundle = std.crypto.Certificate.Bundle;
const EmailClient = zmtp.EmailClient;
const Credentials = zmtp.authentication.Credentials;

pub fn main() !void {
    var bundle: CertificateBundle = .{};
    defer bundle.deinit(std.testing.allocator);

    try bundle.rescan(std.testing.allocator);

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
```


### Features

- Multiple supported schemes.
- Secure email delivery via TLS and authentication.
- Unicode Support for email content.
