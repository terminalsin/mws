//! CloudWatch anomaly detection through the official Rust SDK: bands from
//! models trained on the metric's history (not the queried window), no
//! band without history, detectors created on first use, excluded time
//! ranges, detector training states, and anomaly alarms that fire on a
//! spike above the band.

use std::time::Duration;

use aws_sdk_cloudwatch::primitives::DateTime;
use aws_sdk_cloudwatch::types::{
    AnomalyDetectorConfiguration, ComparisonOperator, Dimension, Metric, MetricDataQuery, MetricDatum, MetricStat,
    Range, SingleMetricAnomalyDetector, StateValue,
};
use aws_sdk_cloudwatch::Client;
use mws_e2e::Mws;

fn dim() -> Dimension {
    Dimension::builder().name("Service").value("api").build()
}

/// The emulated clock, in epoch seconds.
pub(crate) async fn clock_now(mws: &Mws) -> i64 {
    let (status, doc) = mws.control("GET", "/_mws/clock", None).await;
    assert_eq!(status, 200);
    chrono::DateTime::parse_from_rfc3339(doc["now"].as_str().unwrap()).unwrap().timestamp()
}

/// Move the emulated clock to one second past the end of the minute that
/// holds `t`, so that minute is a completed period.
pub(crate) async fn finish_minute(mws: &Mws, t: i64) {
    let target = t - t.rem_euclid(60) + 61;
    let now = clock_now(mws).await;
    if target > now {
        let body = format!(r#"{{"advanceSeconds": {}}}"#, target - now);
        let (status, _) = mws.control("POST", "/_mws/clock", Some(&body)).await;
        assert_eq!(status, 200);
    }
}

/// Put `values` one minute apart, the last at `last`.
async fn put_history(cw: &Client, metric: &str, last: i64, values: &[f64]) {
    let n = values.len() as i64;
    for chunk in values.iter().enumerate().collect::<Vec<_>>().chunks(500) {
        let data: Vec<MetricDatum> = chunk
            .iter()
            .map(|(i, v)| {
                MetricDatum::builder()
                    .metric_name(metric)
                    .dimensions(dim())
                    .value(**v)
                    .timestamp(DateTime::from_secs(last - (n - 1 - *i as i64) * 60))
                    .build()
            })
            .collect();
        cw.put_metric_data().namespace("Anomaly").set_metric_data(Some(data)).send().await.unwrap();
    }
}

fn stat(id: &str, metric: &str) -> MetricDataQuery {
    MetricDataQuery::builder()
        .id(id)
        .metric_stat(
            MetricStat::builder()
                .metric(Metric::builder().namespace("Anomaly").metric_name(metric).dimensions(dim()).build())
                .period(60)
                .stat("Average")
                .build(),
        )
        .return_data(true)
        .build()
}

fn band(id: &str, of: &str) -> MetricDataQuery {
    MetricDataQuery::builder().id(id).expression(format!("ANOMALY_DETECTION_BAND({of}, 2)")).build()
}

/// `(timestamps, lower, upper)` of the band query `ad`.
async fn get_band(cw: &Client, metric: &str, from: i64, to: i64) -> (Vec<i64>, Vec<f64>, Vec<f64>) {
    let out = cw
        .get_metric_data()
        .metric_data_queries(stat("m1", metric))
        .metric_data_queries(band("ad", "m1"))
        .start_time(DateTime::from_secs(from))
        .end_time(DateTime::from_secs(to))
        .scan_by(aws_sdk_cloudwatch::types::ScanBy::TimestampAscending)
        .send()
        .await
        .unwrap();
    let parts: Vec<_> = out.metric_data_results().iter().filter(|r| r.id() == Some("ad")).collect();
    assert_eq!(parts.len(), 2, "{out:?}");
    let lower = parts.iter().find(|r| r.label().unwrap_or_default().contains("lower")).unwrap();
    let upper = parts.iter().find(|r| r.label().unwrap_or_default().contains("upper")).unwrap();
    (lower.timestamps().iter().map(|t| t.secs()).collect(), lower.values().to_vec(), upper.values().to_vec())
}

/// A quiet metric: 7 to 13 and round again (mean 10, standard deviation
/// 2), with no hourly pattern.
fn quiet(n: usize) -> Vec<f64> {
    (0..n).map(|i| 7.0 + (i % 7) as f64).collect()
}

#[tokio::test]
async fn bands_come_from_a_model_trained_on_history() {
    let mws = Mws::start().await;
    let cw = Client::new(&mws.root_sdk_config().await);
    let now = clock_now(&mws).await;
    let minute = now - now.rem_euclid(60);

    // No history before the query: the band has no datapoints, however
    // many points the queried window holds.
    put_history(&cw, "Fresh", minute - 60, &[10.0, 11.0, 50.0]).await;
    let (ts, lower, _) = get_band(&cw, "Fresh", minute - 600, minute).await;
    assert!(ts.is_empty() && lower.is_empty(), "{ts:?}");

    // Three hours of history, then a spike inside the queried window.
    let mut values = quiet(180);
    values.push(500.0);
    put_history(&cw, "Latency", minute - 60, &values).await;
    let (ts, lower, upper) = get_band(&cw, "Latency", minute - 300, minute).await;
    assert_eq!(ts.len(), 5, "{ts:?}");
    for (lo, hi) in lower.iter().zip(&upper) {
        // About 10 ± 2 standard deviations, whatever is in the window:
        // the spike does not widen its own band.
        assert!(*lo > 4.0 && *lo < 8.0, "{lo}");
        assert!(*hi > 12.0 && *hi < 16.0, "{hi}");
    }

    // Using the band created the metric's detector, training on under a
    // day of history.
    let detectors = cw.describe_anomaly_detectors().namespace("Anomaly").metric_name("Latency").send().await.unwrap();
    assert_eq!(detectors.anomaly_detectors().len(), 1, "{detectors:?}");
    let d = &detectors.anomaly_detectors()[0];
    let single = d.single_metric_anomaly_detector().unwrap();
    assert_eq!(single.stat(), Some("Average"));
    assert_eq!(single.dimensions().len(), 1);
    assert_eq!(d.state_value().map(|s| s.as_str()), Some("TRAINED_INSUFFICIENT_DATA"));
    let fresh = cw.describe_anomaly_detectors().metric_name("Fresh").send().await.unwrap();
    assert_eq!(fresh.anomaly_detectors()[0].state_value().map(|s| s.as_str()), Some("PENDING_TRAINING"));
}

#[tokio::test]
async fn excluded_time_ranges_leave_incidents_out_of_training() {
    let mws = Mws::start().await;
    let cw = Client::new(&mws.root_sdk_config().await);
    let now = clock_now(&mws).await;
    let minute = now - now.rem_euclid(60);
    // Two hours of quiet history with a ten-minute incident an hour ago.
    let last = minute - 60;
    let mut values = quiet(120);
    for v in values.iter_mut().skip(55).take(10) {
        *v = 1000.0;
    }
    put_history(&cw, "Errors", last, &values).await;
    let (_, _, upper) = get_band(&cw, "Errors", minute - 120, minute + 60).await;
    assert!(upper[0] > 100.0, "the incident widens an untrained band: {upper:?}");

    let incident_start = last - (119 - 55) * 60;
    let detector = SingleMetricAnomalyDetector::builder()
        .namespace("Anomaly")
        .metric_name("Errors")
        .dimensions(dim())
        .stat("Average")
        .build();
    let err = cw
        .put_anomaly_detector()
        .single_metric_anomaly_detector(detector.clone())
        .configuration(AnomalyDetectorConfiguration::builder().metric_timezone("Not/AZone").build())
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(aws_sdk_cloudwatch::error::ProvideErrorMetadata::code(&err), Some("InvalidParameterValue"));
    cw.put_anomaly_detector()
        .single_metric_anomaly_detector(detector)
        .configuration(
            AnomalyDetectorConfiguration::builder()
                .excluded_time_ranges(
                    Range::builder()
                        .start_time(DateTime::from_secs(incident_start - 30))
                        .end_time(DateTime::from_secs(incident_start + 10 * 60))
                        .build(),
                )
                .metric_timezone("Europe/Paris")
                .build(),
        )
        .send()
        .await
        .unwrap();
    let (_, lower, upper) = get_band(&cw, "Errors", minute - 120, minute + 60).await;
    assert!(upper[0] < 16.0 && lower[0] > 4.0, "{lower:?} {upper:?}");
    let detectors = cw.describe_anomaly_detectors().metric_name("Errors").send().await.unwrap();
    assert_eq!(detectors.anomaly_detectors().len(), 1, "the detector put is the one the band used");
}

#[tokio::test]
async fn anomaly_alarms_fire_on_a_spike_above_the_band() {
    let mws = Mws::start().await;
    let cw = Client::new(&mws.root_sdk_config().await);
    let now = clock_now(&mws).await;
    let minute = now - now.rem_euclid(60);
    put_history(&cw, "Requests", minute - 60, &quiet(120)).await;
    cw.put_metric_alarm()
        .alarm_name("requests-anomaly")
        .metrics(stat("m1", "Requests"))
        .metrics(band("ad1", "m1"))
        .threshold_metric_id("ad1")
        .evaluation_periods(1)
        .comparison_operator(ComparisonOperator::GreaterThanUpperThreshold)
        .send()
        .await
        .unwrap();
    let state = |cw: Client| async move {
        let out = cw.describe_alarms().alarm_names("requests-anomaly").send().await.unwrap();
        out.metric_alarms()[0].state_value().cloned()
    };
    let mut ok = false;
    for _ in 0..50 {
        if state(cw.clone()).await == Some(StateValue::Ok) {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ok, "the quiet metric is inside its band");

    // Keep clear of a minute boundary, then spike in the current minute:
    // nothing happens until that period is complete.
    let mut now = clock_now(&mws).await;
    if now.rem_euclid(60) > 50 {
        let body = format!(r#"{{"advanceSeconds": {}}}"#, 62 - now.rem_euclid(60));
        mws.control("POST", "/_mws/clock", Some(&body)).await;
        now = clock_now(&mws).await;
    }
    put_history(&cw, "Requests", now, &[400.0]).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(state(cw.clone()).await, Some(StateValue::Ok), "the current period is not evaluated");
    finish_minute(&mws, now).await;
    let mut fired = None;
    for _ in 0..50 {
        let out = cw.describe_alarms().alarm_names("requests-anomaly").send().await.unwrap();
        let a = out.metric_alarms()[0].clone();
        if a.state_value() == Some(&StateValue::Alarm) {
            fired = Some(a);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let a = fired.expect("the spike sets the alarm off");
    assert!(a.state_reason().unwrap().contains("[400.0 ("), "{:?}", a.state_reason());
    assert!(a.state_reason().unwrap().contains("greater than the upper band"), "{:?}", a.state_reason());

    // The alarm's band created the metric's detector.
    let detectors = cw.describe_anomaly_detectors().metric_name("Requests").send().await.unwrap();
    assert_eq!(detectors.anomaly_detectors().len(), 1);
}
