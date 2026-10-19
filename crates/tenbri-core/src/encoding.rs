//! The one spelling of each value format v1 stores (spec/format-v1.md, section 2).

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

/// Decodes exactly `N` bytes of lowercase hex; uppercase is not an alternative spelling.
pub fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.as_bytes();
    if s.len() != N * 2 {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (nibble(s[2 * i])? << 4) | nibble(s[2 * i + 1])?;
    }
    Some(out)
}

/// `prefix` followed by exactly `N` bytes of lowercase hex.
pub fn prefixed<const N: usize>(s: &str, prefix: &str) -> Option<[u8; N]> {
    unhex(s.strip_prefix(prefix)?)
}

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A ULID's 26 characters for 128 bits: 48 bits of milliseconds, then 80 random bits.
pub fn ulid(value: u128) -> String {
    (0..26)
        .map(|i| CROCKFORD[((value >> (125 - 5 * i)) & 31) as usize] as char)
        .collect()
}

/// Decodes a ULID in its one canonical spelling: 26 uppercase Crockford characters, first `0`-`7`.
pub fn parse_ulid(s: &str) -> Option<u128> {
    let s = s.as_bytes();
    if s.len() != 26 || s[0] > b'7' {
        return None;
    }
    s.iter().try_fold(0u128, |acc, c| {
        let d = CROCKFORD.iter().position(|x| x == c)?;
        Some((acc << 5) | d as u128)
    })
}

/// Formats milliseconds since the Unix epoch as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn format_ts(ms: i64) -> String {
    let (days, ms_of_day) = (ms.div_euclid(86_400_000), ms.rem_euclid(86_400_000));
    let (y, m, d) = civil_from_days(days);
    let s = ms_of_day / 1000;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        s / 3600,
        s / 60 % 60,
        s % 60,
        ms_of_day % 1000
    )
}

/// Parses `YYYY-MM-DDTHH:MM:SS.mmmZ` (years 0000 to 9999) to milliseconds since the Unix epoch.
pub fn parse_ts(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 24 || b[23] != b'Z' {
        return None;
    }
    for (i, sep) in [
        (4, b'-'),
        (7, b'-'),
        (10, b'T'),
        (13, b':'),
        (16, b':'),
        (19, b'.'),
    ] {
        if b[i] != sep {
            return None;
        }
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        b[r].iter().try_fold(0i64, |acc, c| {
            c.is_ascii_digit().then(|| acc * 10 + (c - b'0') as i64)
        })
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec, ms) = (num(11..13)?, num(14..16)?, num(17..19)?, num(20..23)?);
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&mo) || d < 1 || d > month_days[mo as usize - 1] {
        return None;
    }
    if h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    Some(days_from_civil(y, mo, d) * 86_400_000 + ((h * 60 + mi) * 60 + sec) * 1000 + ms)
}

// Howard Hinnant's algorithms, http://howardhinnant.github.io/date_algorithms.html
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
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// A key id: 1 to 128 characters from `A-Z a-z 0-9 . _ : -`.
pub fn is_key_id(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for ms in [
            0,
            1_792_444_710_318,
            253_402_300_799_999,
            -62_167_219_200_000,
        ] {
            assert_eq!(parse_ts(&format_ts(ms)), Some(ms));
        }
        assert_eq!(format_ts(1_792_444_710_318), "2026-10-19T21:18:30.318Z");
        assert_eq!(parse_ts("2026-02-29T00:00:00.000Z"), None);
        assert!(parse_ts("2024-02-29T23:59:59.999Z").is_some());
        assert_eq!(parse_ts("2026-10-19T00:38:30Z"), None);
        let id = 0x0193_4e1f_2a3b_4c5d_6e7f_8091_a2b3_c4d5u128;
        assert_eq!(parse_ulid(&ulid(id)), Some(id));
        assert_eq!(parse_ulid("01m4xbgynr7q9w3mzk2h6tb8ca"), None);
        assert_eq!(parse_ulid("81M4XBGYNR7Q9W3MZK2H6TB8CA"), None);
        assert_eq!(unhex::<2>("abCD"), None);
        assert_eq!(unhex::<2>("abcd"), Some([0xab, 0xcd]));
    }
}
