// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hashrate chart drawn as SVG by Leptos.
//!
//! Wheel zooms around the cursor, dragging selects a range to zoom into,
//! double-click resets, and hovering shows the nearest point's values. The
//! geometry is pure and unit tested; the component only wires events.

use crate::api::HashratePoint;
use crate::format;
use leptos::prelude::*;

const WIDTH: f64 = 800.0;
const HEIGHT: f64 = 260.0;
const PAD_LEFT: f64 = 70.0;
const PAD_RIGHT: f64 = 12.0;
const PAD_TOP: f64 = 12.0;
const PAD_BOTTOM: f64 = 26.0;
/// Narrowest zoom, in seconds.
const MIN_SPAN: f64 = 60.0;

/// Maps data space (time, hashrate) to the SVG viewBox.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Scale {
    pub t0: f64,
    pub t1: f64,
    pub y_max: f64,
}

impl Scale {
    pub fn x(&self, t: f64) -> f64 {
        PAD_LEFT + (t - self.t0) / (self.t1 - self.t0) * (WIDTH - PAD_LEFT - PAD_RIGHT)
    }

    pub fn y(&self, value: f64) -> f64 {
        HEIGHT - PAD_BOTTOM - value / self.y_max * (HEIGHT - PAD_TOP - PAD_BOTTOM)
    }

    /// Time at a horizontal fraction (0..1) of the rendered width.
    pub fn time_at_fraction(&self, fraction: f64) -> f64 {
        let x = fraction * WIDTH;
        let plot = (x - PAD_LEFT) / (WIDTH - PAD_LEFT - PAD_RIGHT);
        self.t0 + plot.clamp(0.0, 1.0) * (self.t1 - self.t0)
    }
}

/// Fit a scale to the points visible in `range` (or all points).
pub fn fit(points: &[HashratePoint], range: Option<(f64, f64)>) -> Option<Scale> {
    let first = points.first()?.time as f64;
    let last = points.last()?.time as f64;
    let (t0, t1) = range.unwrap_or((first, last.max(first + 1.0)));
    let y_max = points
        .iter()
        .filter(|p| (p.time as f64) >= t0 && (p.time as f64) <= t1)
        .flat_map(|p| {
            [
                p.pool_hashrate.unwrap_or(0.0),
                p.local_hashrate.unwrap_or(0.0),
            ]
        })
        .fold(0.0, f64::max);
    Some(Scale {
        t0,
        t1,
        y_max: if y_max > 0.0 { y_max * 1.1 } else { 1.0 },
    })
}

/// SVG path for one series; gaps (`None`) break the line.
pub fn path(
    points: &[HashratePoint],
    scale: &Scale,
    value: impl Fn(&HashratePoint) -> Option<f64>,
) -> String {
    let mut d = String::new();
    let mut pen_down = false;
    for point in points {
        let t = point.time as f64;
        match value(point) {
            Some(v) if t >= scale.t0 && t <= scale.t1 => {
                d.push_str(if pen_down { "L" } else { "M" });
                d.push_str(&format!("{:.1},{:.1} ", scale.x(t), scale.y(v)));
                pen_down = true;
            }
            _ => pen_down = false,
        }
    }
    d
}

/// Zoom `range` by `factor` (<1 zooms in) around time `center`, kept inside `bounds`.
pub fn zoom(range: (f64, f64), center: f64, factor: f64, bounds: (f64, f64)) -> (f64, f64) {
    let span = ((range.1 - range.0) * factor).clamp(MIN_SPAN, bounds.1 - bounds.0);
    let left_share = if range.1 > range.0 {
        (center - range.0) / (range.1 - range.0)
    } else {
        0.5
    };
    let t0 = (center - span * left_share).clamp(bounds.0, bounds.1 - span);
    (t0, t0 + span)
}

/// The point nearest to time `t`.
pub fn nearest(points: &[HashratePoint], t: f64) -> Option<&HashratePoint> {
    points.iter().min_by(|a, b| {
        (a.time as f64 - t)
            .abs()
            .total_cmp(&(b.time as f64 - t).abs())
    })
}

/// Horizontal fraction of a mouse event across the element it is bound to.
fn event_fraction(event: &web_sys::MouseEvent) -> Option<f64> {
    use wasm_bindgen::JsCast;
    let element = event
        .current_target()?
        .dyn_into::<web_sys::Element>()
        .ok()?;
    let rect = element.get_bounding_client_rect();
    if rect.width() <= 0.0 {
        return None;
    }
    Some((f64::from(event.client_x()) - rect.left()) / rect.width())
}

#[component]
pub fn HashrateChart(points: Signal<Vec<HashratePoint>>) -> impl IntoView {
    // Visible time range; `None` shows everything.
    let range = RwSignal::new(None::<(f64, f64)>);
    let hover = RwSignal::new(None::<f64>);
    let drag_start = RwSignal::new(None::<f64>);

    let scale = Memo::new(move |_| points.with(|p| fit(p, range.get())));
    let bounds = move || {
        points.with_untracked(|p| match (p.first(), p.last()) {
            (Some(a), Some(b)) => {
                Some((a.time as f64, (b.time as f64).max(a.time as f64 + MIN_SPAN)))
            }
            _ => None,
        })
    };

    let on_wheel = move |event: web_sys::WheelEvent| {
        event.prevent_default();
        let (Some(scale), Some(bounds)) = (scale.get_untracked(), bounds()) else {
            return;
        };
        let Some(fraction) = event_fraction(&event) else {
            return;
        };
        let center = scale.time_at_fraction(fraction);
        let factor = if event.delta_y() < 0.0 { 0.8 } else { 1.25 };
        range.set(Some(zoom((scale.t0, scale.t1), center, factor, bounds)));
    };
    let on_down = move |event: web_sys::MouseEvent| {
        if let (Some(scale), Some(fraction)) = (scale.get_untracked(), event_fraction(&event)) {
            drag_start.set(Some(scale.time_at_fraction(fraction)));
        }
    };
    let on_move = move |event: web_sys::MouseEvent| {
        if let (Some(scale), Some(fraction)) = (scale.get_untracked(), event_fraction(&event)) {
            hover.set(Some(scale.time_at_fraction(fraction)));
        }
    };
    let on_up = move |_| {
        if let (Some(start), Some(end)) = (drag_start.get_untracked(), hover.get_untracked())
            && (end - start).abs() >= MIN_SPAN
        {
            range.set(Some((start.min(end), start.max(end))));
        }
        drag_start.set(None);
    };
    let on_leave = move |_| {
        hover.set(None);
        drag_start.set(None);
    };

    let chart = move || {
        let Some(scale) = scale.get() else {
            return view! { <p class="muted">"No hashrate history yet."</p> }.into_any();
        };
        let (pool, local, ticks, hovered) = points.with(|p| {
            let pool = path(p, &scale, |q| q.pool_hashrate);
            let local = path(p, &scale, |q| q.local_hashrate);
            let ticks: Vec<_> = (0..=4)
                .map(|i| {
                    let value = scale.y_max * f64::from(i) / 4.0;
                    let t = scale.t0 + (scale.t1 - scale.t0) * f64::from(i) / 4.0;
                    (
                        scale.y(value),
                        format::hashrate(value),
                        scale.x(t),
                        format::clock(t as u64),
                    )
                })
                .collect();
            let hovered = hover.get().and_then(|t| nearest(p, t).cloned());
            (pool, local, ticks, hovered)
        });
        let selection = move || {
            let (start, end) = (drag_start.get()?, hover.get()?);
            let (a, b) = (scale.x(start.min(end)), scale.x(start.max(end)));
            Some(view! {
                <rect
                    class="selection"
                    x=a
                    y=PAD_TOP
                    width=b - a
                    height=HEIGHT - PAD_TOP - PAD_BOTTOM
                />
            })
        };
        let tooltip = hovered.map(|point| {
            let x = scale.x(point.time as f64);
            let label_x = if x > WIDTH * 0.7 { x - 190.0 } else { x + 8.0 };
            let pool = point
                .pool_hashrate
                .map(format::hashrate)
                .unwrap_or_else(|| "–".into());
            let local = point
                .local_hashrate
                .map(format::hashrate)
                .unwrap_or_else(|| "–".into());
            view! {
                <line class="crosshair" x1=x x2=x y1=PAD_TOP y2=HEIGHT - PAD_BOTTOM />
                <circle class="dot" cx=x cy=scale.y(point.pool_hashrate.unwrap_or(0.0)) r="4" />
                <rect class="tip" x=label_x y=PAD_TOP width="182" height="58" rx="4" />
                <text class="tip-text" x=label_x + 8.0 y=PAD_TOP + 17.0>
                    {format::utc(point.time)}
                </text>
                <text class="tip-text pool" x=label_x + 8.0 y=PAD_TOP + 34.0>
                    {format!("Pool  {pool}")}
                </text>
                <text class="tip-text local" x=label_x + 8.0 y=PAD_TOP + 51.0>
                    {format!("Local {local}")}
                </text>
            }
        });
        view! {
            <svg
                class="chart"
                viewBox=format!("0 0 {WIDTH} {HEIGHT}")
                on:wheel=on_wheel
                on:mousedown=on_down
                on:mousemove=on_move
                on:mouseup=on_up
                on:mouseleave=on_leave
                on:dblclick=move |_| range.set(None)
            >
                {ticks
                    .into_iter()
                    .map(|(y, label, x, time)| {
                        view! {
                            <line class="grid" x1=PAD_LEFT x2=WIDTH - PAD_RIGHT y1=y y2=y />
                            <text class="axis" x=PAD_LEFT - 6.0 y=y + 4.0 text-anchor="end">
                                {label}
                            </text>
                            <text class="axis" x=x y=HEIGHT - 8.0 text-anchor="middle">
                                {time}
                            </text>
                        }
                    })
                    .collect_view()}
                <path class="line-pool" d=pool />
                <path class="line-local" d=local />
                {selection}
                {tooltip}
            </svg>
        }
        .into_any()
    };

    view! {
        <div class="chart-wrap">
            {chart}
            <div class="legend">
                <span class="key pool">"Pool"</span>
                <span class="key local">"Local"</span>
                <button on:click=move |_| range.set(None)>"Reset zoom"</button>
                <span class="muted">"Scroll to zoom, drag to select, double-click to reset"</span>
            </div>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(time: u64, pool: f64, local: Option<f64>) -> HashratePoint {
        HashratePoint {
            time,
            pool_hashrate: Some(pool),
            local_hashrate: local,
        }
    }

    #[test]
    fn test_fit_uses_visible_max() {
        let points = [
            point(0, 10.0, None),
            point(100, 50.0, Some(80.0)),
            point(200, 20.0, None),
        ];
        let scale = fit(&points, None).unwrap();
        assert_eq!((scale.t0, scale.t1), (0.0, 200.0));
        assert!((scale.y_max - 88.0).abs() < 1e-9);
        let zoomed = fit(&points, Some((150.0, 200.0))).unwrap();
        assert!((zoomed.y_max - 22.0).abs() < 1e-9);
        assert!(fit(&[], None).is_none());
    }

    #[test]
    fn test_path_breaks_on_gaps() {
        let points = [
            point(0, 1.0, Some(1.0)),
            point(1, 1.0, None),
            point(2, 1.0, Some(1.0)),
        ];
        let scale = Scale {
            t0: 0.0,
            t1: 2.0,
            y_max: 2.0,
        };
        let d = path(&points, &scale, |p| p.local_hashrate);
        assert_eq!(d.matches('M').count(), 2);
        assert!(!d.contains('L'));
    }

    #[test]
    fn test_zoom_keeps_center_and_bounds() {
        assert_eq!(
            zoom((0.0, 1000.0), 500.0, 0.5, (0.0, 1000.0)),
            (250.0, 750.0)
        );
        assert_eq!(
            zoom((0.0, 1000.0), 500.0, 4.0, (0.0, 1000.0)),
            (0.0, 1000.0)
        );
        assert_eq!(
            zoom((0.0, 100.0), 0.0, 0.01, (0.0, 1000.0)),
            (0.0, MIN_SPAN)
        );
    }

    #[test]
    fn test_time_at_fraction_clamps_to_plot() {
        let scale = Scale {
            t0: 0.0,
            t1: 100.0,
            y_max: 1.0,
        };
        assert_eq!(scale.time_at_fraction(0.0), 0.0);
        assert_eq!(scale.time_at_fraction(1.0), 100.0);
        assert!((scale.x(scale.time_at_fraction(0.5)) - WIDTH * 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_nearest() {
        let points = [point(0, 1.0, None), point(60, 2.0, None)];
        assert_eq!(nearest(&points, 40.0).unwrap().time, 60);
    }
}
