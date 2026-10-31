//! Strict RFC3339/Unix timestamp parsing without a runtime or extra dependency.

pub fn timestamp(value: &serde_json::Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        return Some(if n < 10_000_000_000 {
            n.checked_mul(1000)?
        } else {
            n
        });
    }
    if let Some(n) = value.as_f64() {
        return (n.is_finite() && n >= 0.0 && n < 10_000_000_000.0).then_some((n * 1000.0) as u64);
    }
    iso(value.as_str()?)
}

pub fn iso(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b' ')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let n = |a, b| text.get(a..b)?.parse::<i64>().ok();
    let (year, month, day, hour, minute, second) = (
        n(0, 4)?,
        n(5, 7)?,
        n(8, 10)?,
        n(11, 13)?,
        n(14, 16)?,
        n(17, 19)?,
    );
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = [
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
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day < 1
        || day > days[(month - 1) as usize]
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
    {
        return None;
    }
    let mut pos = 19;
    let mut millis = 0;
    if bytes.get(pos) == Some(&b'.') {
        pos += 1;
        let start = pos;
        while bytes.get(pos).is_some_and(u8::is_ascii_digit) {
            pos += 1;
        }
        if start == pos {
            return None;
        }
        for index in 0..3 {
            millis = millis * 10
                + bytes
                    .get(start + index)
                    .filter(|_| start + index < pos)
                    .map(|b| (b - b'0') as i64)
                    .unwrap_or(0);
        }
    }
    let offset = match bytes.get(pos) {
        Some(b'Z') if pos + 1 == bytes.len() => 0,
        Some(sign @ (b'+' | b'-')) => {
            let (hours, mins) = if bytes.len() == pos + 6 && bytes.get(pos + 3) == Some(&b':') {
                (n(pos + 1, pos + 3)?, n(pos + 4, pos + 6)?)
            } else if bytes.len() == pos + 5 {
                (n(pos + 1, pos + 3)?, n(pos + 3, pos + 5)?)
            } else {
                return None;
            };
            if !(0..=23).contains(&hours) || !(0..=59).contains(&mins) {
                return None;
            }
            (if *sign == b'+' { 1 } else { -1 }) * (hours * 3600 + mins * 60)
        }
        _ => return None,
    };
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let civil = era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
    u64::try_from((civil * 86400 + hour * 3600 + minute * 60 + second - offset) * 1000 + millis)
        .ok()
}
