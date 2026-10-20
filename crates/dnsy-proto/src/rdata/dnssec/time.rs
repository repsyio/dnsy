//! RRSIG timestamps (`YYYYMMDDHHmmSS`, RFC 4034 3.2) and RFC 1982 serial arithmetic.

const HALF: u32 = 1 << 31;

/// RFC 1982 `a < b` for 32-bit serial numbers. A distance of exactly 2^31 is
/// undefined by the RFC and compares as neither less nor greater.
pub fn serial_lt(a: u32, b: u32) -> bool {
    (a < b && b - a < HALF) || (a > b && a - b > HALF)
}

/// RFC 1982 `a > b`.
pub fn serial_gt(a: u32, b: u32) -> bool {
    serial_lt(b, a)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// Formats seconds since the epoch as `YYYYMMDDHHmmSS` (UTC).
pub fn format_timestamp(t: u32) -> String {
    let secs = i64::from(t);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!(
        "{y:04}{m:02}{d:02}{:02}{:02}{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Parses `YYYYMMDDHHmmSS` or a decimal count of seconds (RFC 4034 3.2).
pub fn parse_timestamp(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if s.len() != 14 {
        return s.parse().ok();
    }
    let field = |a: usize, b: usize| s[a..b].parse::<i64>().ok();
    let (y, mo, d) = (field(0, 4)?, field(4, 6)?, field(6, 8)?);
    let (h, mi, sec) = (field(8, 10)?, field(10, 12)?, field(12, 14)?);
    if !(1..=12).contains(&mo) || h > 23 || mi > 59 || sec > 59 || d < 1 {
        return None;
    }
    let days = days_from_civil(y, mo, d);
    // Reject days past the end of the month (for example 31 April).
    if civil_from_days(days) != (y, mo, d) {
        return None;
    }
    u32::try_from(days * 86_400 + h * 3600 + mi * 60 + sec).ok()
}
