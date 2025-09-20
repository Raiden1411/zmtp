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
const zmtp = @import("zmtp");

const EmailClient = zmtp.EmailClient;

pub fn main() !void {
    var client = try EmailClient.connect(std.testing.allocator, "smtp://localhost:1025");
    defer client.deinit();

    const cred: Credentials = .{
        .username = "foo",
        .password = "bar",
    };

    // This will upgrade the connection to tls via STARTTLS
    try client.sendEmailWithCredentials(.{
        .from = .{ .address = "fooo@bar.sh" },
        .to = &.{
            .{ .address = "fooo@bar.io" },
        },
        .subject = "THIS IS A TEST 🥱",
        .text_body = "HELLO WORLD! 🥱",
        .html_body = "<p> THIS IS A TEST </p>",
    }, cred);
}
```


### Features

- Multiple supported schemes.
- Secure email delivery via TLS and authentication.
- Unicode Support for email content.
