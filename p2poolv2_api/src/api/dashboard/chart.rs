// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Line charts drawn as SVG on the server.
//!
//! Every point carries an SVG `<title>`, which browsers show as a tooltip,
//! so hovering needs no script. Series are averaged down to a bounded number
//! of points, so a page stays small however long the history is.

use maud::{Markup, html};

/// Most points drawn per series.
const MAX_POINTS: usize = 240;

const WIDTH: f64 = 720.0;
const HEIGHT: f64 = 240.0;
const PAD_LEFT: f64 = 76.0;
const PAD_RIGHT: f64 = 12.0;
const PAD_TOP: f64 = 12.0;
const PAD_BOTTOM: f64 = 26.0;
const GRID_LINES: u32 = 4;

/// One line of a chart.
pub(crate) struct Series {
    pub(crate) label: &'static str,
    /// CSS class giving the line its colour.
    pub(crate) class: &'static str,
    /// (unix seconds, value), oldest first.
    pub(crate) points: Vec<(u64, f64)>,
}

/// Average `points` down to at most `max` points, one per equal slice of
/// the input, keeping their order.
pub(crate) fn downsample(points: &[(u64, f64)], max: usize) -> Vec<(u64, f64)> {
    if points.len() <= max || max == 0 {
        return points.to_vec();
    }
    let slice = points.len().div_ceil(max);
    points
        .chunks(slice)
        .map(|chunk| {
            let count = chunk.len() as f64;
            let time = chunk.iter().map(|(time, _)| *time as f64).sum::<f64>() / count;
            let value = chunk.iter().map(|(_, value)| *value).sum::<f64>() / count;
            (time.round() as u64, value)
        })
        .collect()
}

/// A line chart of `series` over their common time range, values from zero.
///
/// `format_value` labels the value axis and tooltips; `format_time` labels
/// the time axis and tooltips. With no points at all it shows a note
/// instead of an empty frame.
pub(crate) fn line_chart(
    title: &str,
    series: &[Series],
    format_value: fn(f64) -> String,
    format_time: fn(u64) -> String,
) -> Markup {
    let drawn: Vec<(&Series, Vec<(u64, f64)>)> = series
        .iter()
        .map(|line| (line, downsample(&line.points, MAX_POINTS)))
        .filter(|(_, points)| !points.is_empty())
        .collect();
    let all = || drawn.iter().flat_map(|(_, points)| points.iter());
    let (Some(start), Some(end)) = (
        all().map(|(time, _)| *time).min(),
        all().map(|(time, _)| *time).max(),
    ) else {
        return html! {
            p.empty { "Collecting data: the first points appear a minute or two after the node starts." }
        };
    };
    let span = (end.saturating_sub(start)).max(1) as f64;
    let top = all().map(|(_, value)| *value).fold(0.0_f64, f64::max);
    let top = if top > 0.0 { top * 1.1 } else { 1.0 };
    let plot_width = WIDTH - PAD_LEFT - PAD_RIGHT;
    let plot_height = HEIGHT - PAD_TOP - PAD_BOTTOM;
    let x = |time: u64| PAD_LEFT + (time.saturating_sub(start)) as f64 / span * plot_width;
    let y = |value: f64| PAD_TOP + plot_height - value / top * plot_height;

    html! {
        figure.chart {
            svg viewBox=(format!("0 0 {WIDTH} {HEIGHT}")) role="img" aria-label=(title) {
                @for step in 0..=GRID_LINES {
                    @let value = top * f64::from(step) / f64::from(GRID_LINES);
                    @let line_y = format!("{:.1}", y(value));
                    line.grid x1=(PAD_LEFT) x2=(WIDTH - PAD_RIGHT) y1=(line_y) y2=(line_y) {}
                    text.axis x=(PAD_LEFT - 6.0) y=(line_y) text-anchor="end" dominant-baseline="middle" {
                        (format_value(value))
                    }
                }
                text.axis x=(PAD_LEFT) y=(HEIGHT - 6.0) text-anchor="start" { (format_time(start)) }
                text.axis x=(WIDTH - PAD_RIGHT) y=(HEIGHT - 6.0) text-anchor="end" { (format_time(end)) }
                @for (line, points) in &drawn {
                    polyline class=(format!("line {}", line.class)) points=(
                        points
                            .iter()
                            .map(|(time, value)| format!("{:.1},{:.1}", x(*time), y(*value)))
                            .collect::<Vec<_>>()
                            .join(" ")
                    ) {}
                    @for (time, value) in points {
                        circle class=(format!("dot {}", line.class)) cx=(format!("{:.1}", x(*time))) cy=(format!("{:.1}", y(*value))) r="3" {
                            title { (line.label) ": " (format_value(*value)) " at " (format_time(*time)) }
                        }
                    }
                }
            }
            figcaption {
                @for (line, _) in &drawn {
                    span class=(format!("key {}", line.class)) { (line.label) }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(value: f64) -> String {
        format!("{value:.0}")
    }

    fn time(time: u64) -> String {
        format!("t{time}")
    }

    #[test]
    fn downsample_keeps_short_series_and_averages_long_ones() {
        let short = vec![(1, 1.0), (2, 3.0)];
        assert_eq!(downsample(&short, 10), short);
        let long: Vec<(u64, f64)> = (0..100).map(|i| (i, i as f64)).collect();
        let averaged = downsample(&long, 10);
        assert_eq!(averaged.len(), 10);
        assert_eq!(averaged[0], (5, 4.5));
    }

    #[test]
    fn an_empty_chart_shows_a_note() {
        let markup = line_chart("Hashrate", &[], value, time).into_string();
        assert!(markup.contains("Collecting data"));
        assert!(!markup.contains("<svg"));
    }

    #[test]
    fn a_chart_draws_each_series_with_tooltips_and_no_script() {
        let markup = line_chart(
            "Hashrate",
            &[Series {
                label: "Pool",
                class: "pool",
                points: vec![(100, 10.0), (160, 20.0)],
            }],
            value,
            time,
        )
        .into_string();
        assert!(markup.contains("<svg"));
        assert!(markup.contains("polyline"));
        assert!(markup.contains("<title>Pool: 20 at t160</title>"));
        assert!(!markup.contains("<script"));
    }

    #[test]
    fn chart_text_is_escaped() {
        let markup = line_chart(
            "<b>",
            &[Series {
                label: "Pool",
                class: "pool",
                points: vec![(100, 1.0)],
            }],
            |_| "<x>".to_string(),
            time,
        )
        .into_string();
        assert!(!markup.contains("<x>"));
        assert!(markup.contains("&lt;x&gt;"));
        assert!(!markup.contains("aria-label=\"<b>\""));
    }
}
