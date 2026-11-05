//! `GetMetricWidgetImage`: the widget's metrics are queried like
//! `GetMetricData` and drawn as a real PNG line (or stacked area) graph,
//! with horizontal annotations and a legend of colour swatches.

use std::collections::BTreeMap;
use std::io::Write;

use chrono::{DateTime, Duration, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::Value;

use crate::generated::{errors, types};
use crate::math::{self, Engine};
use crate::names;
use crate::CloudWatch;

const PALETTE: &[[u8; 3]] = &[
    [31, 119, 180],
    [255, 127, 14],
    [44, 160, 44],
    [214, 39, 40],
    [148, 103, 189],
    [140, 86, 75],
    [227, 119, 194],
    [127, 127, 127],
    [188, 189, 34],
    [23, 190, 207],
];

fn bad(m: impl Into<String>) -> ServiceError {
    errors::invalid_parameter_value(m)
}

/// A widget time: ISO 8601 or a negative duration relative to now
/// (`-PT3H`, `-P1D`).
fn widget_time(v: Option<&Value>, now: DateTime<Utc>, default: DateTime<Utc>) -> Result<DateTime<Utc>, ServiceError> {
    let Some(s) = v.and_then(Value::as_str) else { return Ok(default) };
    if let Some(d) = s.strip_prefix('-') {
        let d = crate::mute::parse_duration(d).ok_or_else(|| bad(format!("The value {s} is not a valid time.")))?;
        return Ok(now - d);
    }
    DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|_| bad(format!("The value {s} is not a valid time.")))
}

struct Widget {
    queries: Vec<types::MetricDataQuery>,
    colors: BTreeMap<String, [u8; 3]>,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    width: usize,
    height: usize,
    stacked: bool,
    annotations: Vec<f64>,
    min: Option<f64>,
    max: Option<f64>,
    legend: bool,
}

fn color(s: &str) -> Option<[u8; 3]> {
    let h = s.strip_prefix('#')?;
    if h.len() != 6 {
        return None;
    }
    let b = |i: usize| u8::from_str_radix(&h[i..i + 2], 16).ok();
    Some([b(0)?, b(2)?, b(4)?])
}

fn parse(body: &str, now: DateTime<Utc>) -> Result<Widget, ServiceError> {
    let v: Value =
        serde_json::from_str(body).map_err(|_| bad("The parameter MetricWidget must be a valid JSON object."))?;
    let o = v.as_object().ok_or_else(|| bad("The parameter MetricWidget must be a valid JSON object."))?;
    let end = widget_time(o.get("end"), now, now)?;
    let start = widget_time(o.get("start"), now, end - Duration::hours(3))?;
    if start >= end {
        return Err(bad("The start time must be before the end time."));
    }
    let span = (end - start).num_seconds().max(60);
    let default_period =
        o.get("period").and_then(Value::as_i64).unwrap_or_else(|| ((span / 1440 + 59) / 60 * 60).max(60));
    let default_stat = o.get("stat").and_then(Value::as_str).unwrap_or("Average").to_string();
    let rows = o.get("metrics").and_then(Value::as_array).cloned().unwrap_or_default();
    if rows.is_empty() {
        return Err(bad("The widget must contain at least one metric."));
    }
    let mut queries = Vec::new();
    let mut colors = BTreeMap::new();
    let mut previous: Vec<String> = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        let items = row.as_array().ok_or_else(|| bad(format!("Metric {} of the widget is not an array.", i + 1)))?;
        let (strings, opts): (Vec<&Value>, Option<&serde_json::Map<String, Value>>) = match items.last() {
            Some(Value::Object(m)) => (items[..items.len() - 1].iter().collect(), Some(m)),
            _ => (items.iter().collect(), None),
        };
        let opt = |k: &str| opts.and_then(|m| m.get(k));
        let id = opt("id").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| format!("m{}", i + 1));
        let label = opt("label").and_then(Value::as_str).map(str::to_string);
        let visible = opt("visible").and_then(Value::as_bool).unwrap_or(true);
        let period = opt("period").and_then(Value::as_i64).unwrap_or(default_period);
        if let Some(c) = opt("color").and_then(Value::as_str).and_then(color) {
            colors.insert(id.clone(), c);
        }
        if let Some(expr) = opt("expression").and_then(Value::as_str) {
            queries.push(types::MetricDataQuery {
                id,
                expression: Some(expr.to_string()),
                label,
                return_data: Some(visible),
                period: Some(period as i32),
                ..Default::default()
            });
            continue;
        }
        // `"."` repeats the value in the same position of the row above.
        let mut parts = Vec::new();
        for (j, s) in strings.iter().enumerate() {
            let s =
                s.as_str().ok_or_else(|| bad(format!("Metric {} of the widget has a non-string element.", i + 1)))?;
            if s == "." || s == ".." {
                parts.push(previous.get(j).cloned().ok_or_else(|| {
                    bad(format!("Metric {} of the widget refers to a missing previous value.", i + 1))
                })?);
            } else {
                parts.push(s.to_string());
            }
        }
        previous = parts.clone();
        if parts.len() < 2 || parts.len() % 2 != 0 {
            return Err(bad(format!(
                "Metric {} of the widget must be [Namespace, MetricName, DimensionName, DimensionValue, ...].",
                i + 1
            )));
        }
        let dimensions: Vec<types::Dimension> =
            parts[2..].chunks(2).map(|c| types::Dimension { name: c[0].clone(), value: c[1].clone() }).collect();
        queries.push(types::MetricDataQuery {
            id,
            metric_stat: Some(types::MetricStat {
                metric: types::Metric {
                    namespace: Some(parts[0].clone()),
                    metric_name: Some(parts[1].clone()),
                    dimensions: Some(dimensions),
                },
                period: period as i32,
                stat: opt("stat").and_then(Value::as_str).unwrap_or(&default_stat).to_string(),
                unit: None,
            }),
            label,
            return_data: Some(visible),
            ..Default::default()
        });
    }
    let annotations = o
        .get("annotations")
        .and_then(|a| a.get("horizontal"))
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|h| h.get("value").and_then(Value::as_f64)).collect())
        .unwrap_or_default();
    let axis = o.get("yAxis").and_then(|y| y.get("left"));
    let dim = |k: &str, d: usize| o.get(k).and_then(Value::as_u64).map(|v| v as usize).unwrap_or(d);
    let (width, height) = (dim("width", 600), dim("height", 400));
    if !(1..=2000).contains(&width) || !(1..=2000).contains(&height) {
        return Err(bad("The widget width and height must be between 1 and 2000."));
    }
    Ok(Widget {
        queries,
        colors,
        start,
        end,
        width,
        height,
        stacked: o.get("stacked").and_then(Value::as_bool).unwrap_or(false),
        annotations,
        min: axis.and_then(|a| a.get("min")).and_then(Value::as_f64),
        max: axis.and_then(|a| a.get("max")).and_then(Value::as_f64),
        legend: o.get("legend").and_then(|l| l.get("position")).and_then(Value::as_str) != Some("hidden"),
    })
}

struct Canvas {
    w: usize,
    h: usize,
    px: Vec<u8>,
}

impl Canvas {
    fn new(w: usize, h: usize) -> Self {
        Self { w, h, px: vec![255; w * h * 3] }
    }

    fn set(&mut self, x: i64, y: i64, c: [u8; 3]) {
        if x >= 0 && y >= 0 && (x as usize) < self.w && (y as usize) < self.h {
            let i = (y as usize * self.w + x as usize) * 3;
            self.px[i..i + 3].copy_from_slice(&c);
        }
    }

    fn rect(&mut self, x0: i64, y0: i64, x1: i64, y1: i64, c: [u8; 3]) {
        for y in y0..y1 {
            for x in x0..x1 {
                self.set(x, y, c);
            }
        }
    }

    fn line(&mut self, (x0, y0): (f64, f64), (x1, y1): (f64, f64), c: [u8; 3], thick: i64) {
        let steps = ((x1 - x0).abs().max((y1 - y0).abs()).ceil() as i64).max(1);
        for i in 0..=steps {
            let t = i as f64 / steps as f64;
            let (x, y) = ((x0 + (x1 - x0) * t).round() as i64, (y0 + (y1 - y0) * t).round() as i64);
            for d in 0..thick {
                self.set(x, y + d - thick / 2, c);
            }
        }
    }

    fn png(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity((self.w * 3 + 1) * self.h);
        for row in self.px.chunks(self.w * 3) {
            raw.push(0);
            raw.extend_from_slice(row);
        }
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(&raw).expect("in-memory writes succeed");
        let idat = z.finish().expect("in-memory writes succeed");
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&(self.w as u32).to_be_bytes());
        ihdr.extend_from_slice(&(self.h as u32).to_be_bytes());
        ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
        let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
        for (kind, data) in [(b"IHDR", ihdr.as_slice()), (b"IDAT", &idat), (b"IEND", &[])] {
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            let mut chunk = kind.to_vec();
            chunk.extend_from_slice(data);
            out.extend_from_slice(&chunk);
            out.extend_from_slice(&crc32(&chunk).to_be_bytes());
        }
        out
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xffff_ffffu32;
    for b in data {
        c ^= *b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
        }
    }
    !c
}

fn render(w: &Widget, series: &[(String, BTreeMap<i64, f64>)]) -> Vec<u8> {
    let mut c = Canvas::new(w.width, w.height);
    let (left, right, top) = (40.0, w.width as f64 - 10.0, 10.0);
    let legend_h = if w.legend { 20.0 } else { 0.0 };
    let bottom = (w.height as f64 - 20.0 - legend_h).max(top + 1.0);
    let mut plotted: Vec<(String, BTreeMap<i64, f64>)> = series.to_vec();
    if w.stacked {
        let mut acc: BTreeMap<i64, f64> = BTreeMap::new();
        for (_, pts) in plotted.iter_mut() {
            for (t, v) in pts.iter_mut() {
                let e = acc.entry(*t).or_default();
                *e += *v;
                *v = *e;
            }
        }
    }
    let values = plotted.iter().flat_map(|(_, p)| p.values().copied()).chain(w.annotations.iter().copied());
    let (lo, hi) = values.fold((f64::INFINITY, f64::NEG_INFINITY), |(a, b), v| (a.min(v), b.max(v)));
    let (lo, hi) = if lo.is_finite() { (w.min.unwrap_or(lo.min(0.0)), w.max.unwrap_or(hi)) } else { (0.0, 1.0) };
    let hi = if hi <= lo { lo + 1.0 } else { hi };
    let (t0, t1) = (w.start.timestamp() as f64, w.end.timestamp() as f64);
    let x = |t: i64| left + (t as f64 - t0) / (t1 - t0) * (right - left);
    let y = |v: f64| bottom - (v - lo) / (hi - lo) * (bottom - top);
    let grid = [230, 230, 230];
    for i in 0..=4 {
        let gy = top + (bottom - top) * i as f64 / 4.0;
        c.line((left, gy), (right, gy), grid, 1);
    }
    c.line((left, top), (left, bottom), [120, 120, 120], 1);
    c.line((left, bottom), (right, bottom), [120, 120, 120], 1);
    for a in &w.annotations {
        c.line((left, y(*a)), (right, y(*a)), [214, 39, 40], 1);
    }
    for (i, (id, pts)) in plotted.iter().enumerate() {
        let col = w.colors.get(id).copied().unwrap_or(PALETTE[i % PALETTE.len()]);
        let pts: Vec<(f64, f64)> = pts.iter().map(|(t, v)| (x(*t), y(*v))).collect();
        if pts.len() == 1 {
            c.rect(pts[0].0 as i64 - 2, pts[0].1 as i64 - 2, pts[0].0 as i64 + 3, pts[0].1 as i64 + 3, col);
        }
        for p in pts.windows(2) {
            c.line(p[0], p[1], col, 2);
        }
        if w.legend {
            let lx = left as i64 + i as i64 * 24;
            let ly = (w.height as f64 - legend_h + 4.0) as i64;
            c.rect(lx, ly, lx + 12, ly + 12, col);
        }
    }
    c.png()
}

impl CloudWatch {
    pub(crate) fn get_metric_widget_image(
        &self,
        ctx: &RequestContext,
        input: types::GetMetricWidgetImageInput,
    ) -> Result<types::GetMetricWidgetImageOutput, ServiceError> {
        ctx.authorize("cloudwatch:GetMetricWidgetImage", &names::any(ctx), ConditionContext::new())?;
        let format = input.output_format.as_deref().unwrap_or("png");
        if format != "png" && format != "image/png" {
            return Err(bad(format!(
                "The value {format} for parameter OutputFormat is not valid. Only png is supported."
            )));
        }
        let widget = parse(&input.metric_widget, names::now(ctx))?;
        math::validate_queries(&widget.queries, "MetricWidget.metrics")?;
        let st = self.lock();
        let region = st.region_ref(&ctx.caller.account_id, &ctx.region);
        let engine = Engine::new(region, &widget.queries, widget.start, widget.end)
            .with_logs(self.inner.logs.get(), &ctx.caller.account_id, &ctx.region)
            .with_quotas(self.inner.quotas.get().map(|quotas| crate::math::QuotaScope {
                quotas,
                account: &ctx.caller.account_id,
                region: &ctx.region,
                now: names::now(ctx),
            }));
        let series: Vec<(String, BTreeMap<i64, f64>)> =
            math::results(&engine)?.into_iter().map(|(id, _label, points)| (id, points)).collect();
        drop(st);
        Ok(types::GetMetricWidgetImageOutput { metric_widget_image: Some(render(&widget, &series)) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_matches_the_png_spec() {
        assert_eq!(crc32(b"IEND"), 0xae42_6082);
    }

    #[test]
    fn widgets_parse_and_render() {
        let now = Utc::now();
        let w =
            parse(r##"{"metrics":[["NS","M","D","a"],[".",".",".","b",{"color":"#ff0000"}]],"start":"-PT1H"}"##, now)
                .unwrap();
        assert_eq!(w.queries.len(), 2);
        assert_eq!(w.colors.get("m2"), Some(&[255, 0, 0]));
        let png = render(&w, &[("m1".into(), BTreeMap::from([(now.timestamp() - 600, 1.0), (now.timestamp(), 2.0)]))]);
        assert!(png.starts_with(b"\x89PNG"));
    }
}
