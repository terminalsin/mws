//! Prices: On-Demand rates (us-east-1 Linux list prices), the Spot market
//! MWS simulates from them, and Dedicated Host sizes.
//!
//! Spot prices are deterministic: each instance type, zone and product has
//! a price that moves every six hours between 25% and 45% of the On-Demand
//! rate, so the same clock always shows the same market.

use chrono::{DateTime, TimeZone, Utc};

/// Hourly On-Demand Linux price in US dollars.
pub fn on_demand_price(instance_type: &str) -> Option<f64> {
    let p = match instance_type {
        "m1.small" => 0.044,
        "t2.nano" => 0.0058,
        "t2.micro" => 0.0116,
        "t2.small" => 0.023,
        "t2.medium" => 0.0464,
        "t2.large" => 0.0928,
        "t3.nano" => 0.0052,
        "t3.micro" => 0.0104,
        "t3.small" => 0.0208,
        "t3.medium" => 0.0416,
        "t3.large" => 0.0832,
        "t3.xlarge" => 0.1664,
        "t3.2xlarge" => 0.3328,
        "t3a.micro" => 0.0094,
        "t3a.small" => 0.0188,
        "t3a.medium" => 0.0376,
        "t4g.nano" => 0.0042,
        "t4g.micro" => 0.0084,
        "t4g.small" => 0.0168,
        "t4g.medium" => 0.0336,
        "t4g.large" => 0.0672,
        "m5.large" => 0.096,
        "m5.xlarge" => 0.192,
        "m5.2xlarge" => 0.384,
        "m6i.large" => 0.096,
        "m6i.xlarge" => 0.192,
        "m6g.large" => 0.077,
        "m7g.large" => 0.0816,
        "m7i.large" => 0.1008,
        "c5.large" => 0.085,
        "c5.xlarge" => 0.17,
        "c6i.large" => 0.085,
        "c6g.large" => 0.068,
        "c7g.large" => 0.0725,
        "r5.large" => 0.126,
        "r6i.large" => 0.126,
        "r6g.large" => 0.1008,
        _ => return None,
    };
    Some(p)
}

/// The products the Spot market and Reserved Instances price.
pub const PRODUCTS: &[&str] = &["Linux/UNIX", "Linux/UNIX (Amazon VPC)", "Windows", "Windows (Amazon VPC)"];

/// The On-Demand price of `instance_type` running `product`.
pub fn product_price(instance_type: &str, product: &str) -> Option<f64> {
    let base = on_demand_price(instance_type)?;
    if product.starts_with("Windows") {
        let vcpus = crate::catalog::instance_type(instance_type).map(|i| i.vcpus).unwrap_or(1);
        Some(base + 0.023 * vcpus as f64)
    } else {
        Some(base)
    }
}

/// How long one Spot price lasts.
pub const SPOT_PERIOD_HOURS: i64 = 6;

/// The start of the Spot price period `at` falls in.
pub fn spot_period_start(at: DateTime<Utc>) -> DateTime<Utc> {
    let period = SPOT_PERIOD_HOURS * 3600;
    let secs = at.timestamp().div_euclid(period) * period;
    Utc.timestamp_opt(secs, 0).single().unwrap_or(at)
}

/// The Spot price of `instance_type` running `product` in `zone` at `at`.
pub fn spot_price(instance_type: &str, zone: &str, product: &str, at: DateTime<Utc>) -> Option<f64> {
    let od = product_price(instance_type, product)?;
    let period = spot_period_start(at).timestamp();
    let input = format!("{instance_type}/{zone}/{product}/{period}");
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, input.as_bytes());
    let digest = digest.as_ref();
    let n = u16::from_be_bytes([digest[0], digest[1]]) as f64 / u16::MAX as f64;
    Some(round(od * (0.25 + 0.20 * n)))
}

/// A price as EC2 prints it: six decimal places.
pub fn fmt_price(p: f64) -> String {
    format!("{p:.6}")
}

pub fn round(p: f64) -> f64 {
    (p * 1_000_000.0).round() / 1_000_000.0
}

/// A Dedicated Host of an instance family: sockets, physical cores and
/// vCPUs.
pub fn host_size(family: &str) -> Option<(i32, i32, i32)> {
    Some(match family {
        "t3" => (2, 48, 96),
        "m5" => (2, 48, 96),
        "m6i" => (2, 64, 128),
        "m6g" => (1, 64, 64),
        "m7g" => (1, 64, 64),
        "m7i" => (2, 96, 192),
        "c5" => (2, 36, 72),
        "c6i" => (2, 64, 128),
        "c6g" => (1, 64, 64),
        "c7g" => (1, 64, 64),
        "r5" => (2, 48, 96),
        "r6i" => (2, 64, 128),
        "r6g" => (1, 64, 64),
        _ => return None,
    })
}

pub fn family_of(instance_type: &str) -> &str {
    instance_type.split('.').next().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spot_prices_are_stable_within_a_period_and_below_on_demand() {
        let at = Utc.with_ymd_and_hms(2026, 1, 1, 1, 0, 0).unwrap();
        let later = Utc.with_ymd_and_hms(2026, 1, 1, 5, 59, 0).unwrap();
        let p = spot_price("m5.large", "us-east-1a", "Linux/UNIX", at).unwrap();
        assert_eq!(Some(p), spot_price("m5.large", "us-east-1a", "Linux/UNIX", later));
        assert!(p < 0.096 * 0.46 && p > 0.096 * 0.24);
        assert!(spot_price("x9.huge", "us-east-1a", "Linux/UNIX", at).is_none());
    }
}
