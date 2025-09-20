const std = @import("std");

const Writer = std.Io.Writer;

// Constants
const LEAP_EPOCH = 946684800 + 86400 * (31 + 29);
const DAYS_PER_400Y = 365 * 400 + 97;
const DAYS_PER_100Y = 365 * 100 + 24;
const DAYS_PER_4Y = 365 * 4 + 1;
const MONTH_DAYS = [_]u8{ 31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 31, 29 };
const MONTH_NAMES = [_][]const u8{ "", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

pub const Datetime = struct {
    year: i16,
    month: u8,
    day: u8,
    hours: u8,
    minutes: u8,
    seconds: u8,

    /// Formats the datetime into a RFC 822 compliant date time.
    pub fn format(
        self: Datetime,
        writer: *Writer,
    ) Writer.Error!void {
        return writer.print("{d:02} {s} {d} {d:02}:{d:02}:{d:02} +0000", .{ self.day, MONTH_NAMES[self.month], self.year, self.hours, self.minutes, self.seconds });
    }
};

/// Given a UTC timestamp converts it into a `Datetime`
pub fn fromUnixTimeStamp(timestamp: i64) Datetime {
    const seconds = timestamp - LEAP_EPOCH;

    var rem_seconds = @rem(seconds, 86400);
    var days = @divTrunc(seconds, 86400);

    if (@rem(seconds, 86400) < 0) {
        rem_seconds += 86400;
        days -= 1;
    }

    var qc_cycles = @divTrunc(days, DAYS_PER_400Y);
    var rem_days = @rem(days, DAYS_PER_400Y);
    if (rem_days < 0) {
        rem_days += DAYS_PER_400Y;
        qc_cycles -= 1;
    }

    var c_cycles = @divTrunc(rem_days, DAYS_PER_100Y);
    if (c_cycles == 4)
        c_cycles -= 1;

    rem_days -= c_cycles * DAYS_PER_100Y;

    var q_cycles = @divTrunc(rem_days, DAYS_PER_4Y);
    if (q_cycles == 25)
        q_cycles -= 1;

    rem_days -= q_cycles * DAYS_PER_4Y;

    var rem_years = @divTrunc(rem_days, 365);
    if (rem_years == 4) {
        rem_years -= 1;
    }
    rem_days -= rem_years * 365;

    var year = rem_years + 4 * q_cycles + 100 * c_cycles + 400 * qc_cycles + 2000;

    var month: u8 = 0;
    while (MONTH_DAYS[month] <= rem_days) : (month += 1)
        rem_days -= MONTH_DAYS[month];

    month += 2;
    if (month >= 12) {
        year += 1;
        month -= 12;
    }

    return .{
        .year = @intCast(year),
        .month = month + 1,
        .day = @intCast(rem_days + 1),
        .hours = @intCast(@divTrunc(rem_seconds, 3600)),
        .minutes = @intCast(@rem(@divTrunc(rem_seconds, 60), 60)),
        .seconds = @intCast(@rem(rem_seconds, 60)),
    };
}
