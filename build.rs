fn main() {
    let date = build_date();
    println!("cargo:rustc-env=BUILD_DATE={date}");
}

fn build_date() -> String {
    let secs = if let Ok(epoch) = std::env::var("SOURCE_DATE_EPOCH") {
        epoch.parse::<u64>().expect("invalid SOURCE_DATE_EPOCH")
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before Unix epoch")
            .as_secs()
    };
    epoch_to_date(secs)
}

/// Convert Unix epoch seconds to YYYY-MM-DD string.
/// Uses the civil_from_days algorithm by Howard Hinnant.
fn epoch_to_date(epoch_secs: u64) -> String {
    let z = (epoch_secs / 86400) as i64 + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_to_date() {
        assert_eq!(epoch_to_date(0), "1970-01-01");
        assert_eq!(epoch_to_date(1_000_000_000), "2001-09-09");
        assert_eq!(epoch_to_date(1_700_000_000), "2023-11-14");
    }
}
