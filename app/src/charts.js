// SVG charts with no dependency (the app's security policy only allows its own
// scripts). One series per chart: a 2 px line with a light fill, the last point
// ringed with the background color, a thin grid and rounded ticks. On hover or
// with the keyboard (arrow keys), a crosshair follows the nearest point in time
// and a tooltip shows the value and date. Colors come from the theme's CSS
// variables (--chart-line...); `trend` ("up" | "down") turns the line green or red
// (trend-up / trend-down classes on the container, see styles.css).

const SVG_NS = "http://www.w3.org/2000/svg";

function svgEl(name, attrs) {
  const el = document.createElementNS(SVG_NS, name);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
  return el;
}

// "Round" ticks (1, 2, 2.5, 5 × 10^n) covering [min, max].
function niceTicks(min, max, count) {
  if (min === max) {
    const pad = Math.abs(min) * 0.01 || 1;
    min -= pad;
    max += pad;
  }
  const raw = (max - min) / count;
  const magnitude = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * magnitude).find((s) => s >= raw);
  const start = Math.floor(min / step) * step;
  const end = Math.ceil(max / step) * step;
  const ticks = [];
  for (let v = start; v <= end + step / 2; v += step) ticks.push(Number(v.toPrecision(12)));
  return { ticks, step };
}

// Point closest to the x coordinate (points sorted by date).
function nearestIndex(xs, x) {
  let lo = 0;
  let hi = xs.length - 1;
  while (hi - lo > 1) {
    const mid = (lo + hi) >> 1;
    if (xs[mid] <= x) lo = mid;
    else hi = mid;
  }
  return Math.abs(xs[hi] - x) < Math.abs(xs[lo] - x) ? hi : lo;
}

/**
 * Draws `points` ([[time in seconds, value], …], sorted) into `container`.
 * options: height, formatValue(v), formatAxis(v, step), formatTime(t, span),
 * formatTooltipTime(t, span), emptyText, ariaLabel, trend. `span` is the time
 * the points actually cover (seconds), which decides how precise dates are.
 */
export function renderLineChart(container, points, options) {
  container._chart = { points, options };
  if (!container._chartObserver && "ResizeObserver" in window) {
    let lastWidth = container.clientWidth;
    container._chartObserver = new ResizeObserver(() => {
      if (Math.abs(container.clientWidth - lastWidth) > 4 && container._chart) {
        lastWidth = container.clientWidth;
        draw(container, container._chart.points, container._chart.options);
      }
    });
    container._chartObserver.observe(container);
  }
  draw(container, points, options);
}

// Line color from the direction of the change (`null`: theme color).
function applyTrend(container, trend) {
  container.classList.toggle("trend-up", trend === "up");
  container.classList.toggle("trend-down", trend === "down");
}

function draw(container, points, options) {
  const height = options.height ?? 220;
  container.replaceChildren();
  container.classList.remove("chart-loading");
  container.classList.add("chart");
  applyTrend(container, points.length < 2 ? null : options.trend);
  if (points.length < 2) {
    const empty = document.createElement("p");
    empty.className = "muted chart-empty";
    empty.textContent = options.emptyText ?? "";
    container.appendChild(empty);
    return;
  }

  const width = Math.max(container.clientWidth, 240);
  const pad = { top: 14, right: 14, bottom: 26, left: 70 };
  const values = points.map((p) => p[1]);
  const { ticks, step } = niceTicks(Math.min(...values), Math.max(...values), 4);
  const yMin = ticks[0];
  const yMax = ticks[ticks.length - 1];
  const t0 = points[0][0];
  const t1 = points[points.length - 1][0];
  const x = (t) => pad.left + ((t - t0) / (t1 - t0 || 1)) * (width - pad.left - pad.right);
  const y = (v) => pad.top + (1 - (v - yMin) / (yMax - yMin || 1)) * (height - pad.top - pad.bottom);

  const svg = svgEl("svg", { viewBox: `0 0 ${width} ${height}`, width: "100%", height, role: "img" });
  svg.setAttribute("aria-label", options.ariaLabel ?? "");

  // Horizontal grid and value ticks.
  for (const v of ticks) {
    svg.appendChild(svgEl("line", { x1: pad.left, x2: width - pad.right, y1: y(v), y2: y(v), class: "chart-grid" }));
    const label = svgEl("text", { x: pad.left - 8, y: y(v), class: "chart-axis", "text-anchor": "end", "dominant-baseline": "middle" });
    label.textContent = options.formatAxis(v, step);
    svg.appendChild(label);
  }
  // Evenly spread time ticks, fewer on a narrow chart so they never overlap.
  const span = t1 - t0;
  const timeTicks = width < 520 ? 3 : 4;
  for (let i = 0; i <= timeTicks; i++) {
    const t = t0 + ((t1 - t0) * i) / timeTicks;
    const anchor = i === 0 ? "start" : i === timeTicks ? "end" : "middle";
    const label = svgEl("text", { x: x(t), y: height - 6, class: "chart-axis", "text-anchor": anchor });
    label.textContent = options.formatTime(t, span);
    svg.appendChild(label);
  }

  const xs = points.map((p) => x(p[0]));
  const line = points.map((p, i) => `${i ? "L" : "M"}${xs[i].toFixed(1)},${y(p[1]).toFixed(1)}`).join("");
  const baseline = y(yMin);
  svg.appendChild(svgEl("path", { d: `${line}L${xs[xs.length - 1].toFixed(1)},${baseline}L${xs[0].toFixed(1)},${baseline}Z`, class: "chart-fill" }));
  svg.appendChild(svgEl("path", { d: line, class: "chart-line" }));
  const last = points[points.length - 1];
  svg.appendChild(svgEl("circle", { cx: xs[xs.length - 1], cy: y(last[1]), r: 4, class: "chart-dot" }));

  // Hover layer: crosshair, point, tooltip.
  const cross = svgEl("line", { y1: pad.top, y2: height - pad.bottom, class: "chart-crosshair", visibility: "hidden" });
  const hoverDot = svgEl("circle", { r: 4, class: "chart-dot", visibility: "hidden" });
  svg.appendChild(cross);
  svg.appendChild(hoverDot);
  const tooltip = document.createElement("div");
  tooltip.className = "chart-tooltip hidden";
  const tipValue = document.createElement("strong");
  const tipTime = document.createElement("span");
  tooltip.append(tipValue, tipTime);

  let current = -1;
  const show = (index) => {
    current = index;
    const [t, v] = points[index];
    const cx = xs[index];
    const cy = y(v);
    cross.setAttribute("x1", cx);
    cross.setAttribute("x2", cx);
    cross.setAttribute("visibility", "visible");
    hoverDot.setAttribute("cx", cx);
    hoverDot.setAttribute("cy", cy);
    hoverDot.setAttribute("visibility", "visible");
    tipValue.textContent = options.formatValue(v);
    tipTime.textContent = options.formatTooltipTime(t, span);
    tooltip.classList.remove("hidden");
    const scale = container.clientWidth / width;
    const left = cx * scale;
    const tipWidth = tooltip.offsetWidth;
    tooltip.style.left = `${Math.min(Math.max(left - tipWidth / 2, 0), container.clientWidth - tipWidth)}px`;
    tooltip.style.top = `${Math.max(cy * scale - tooltip.offsetHeight - 12, 0)}px`;
  };
  const hide = () => {
    current = -1;
    cross.setAttribute("visibility", "hidden");
    hoverDot.setAttribute("visibility", "hidden");
    tooltip.classList.add("hidden");
  };

  const overlay = svgEl("rect", { x: pad.left, y: 0, width: width - pad.left - pad.right, height, class: "chart-overlay" });
  overlay.addEventListener("pointermove", (e) => {
    const rect = svg.getBoundingClientRect();
    show(nearestIndex(xs, ((e.clientX - rect.left) / rect.width) * width));
  });
  overlay.addEventListener("pointerleave", hide);
  svg.appendChild(overlay);

  container.tabIndex = 0;
  container.onkeydown = (e) => {
    const moves = { ArrowLeft: -1, ArrowRight: 1, Home: -Infinity, End: Infinity };
    if (!(e.key in moves)) return;
    e.preventDefault();
    const from = current < 0 ? points.length - 1 : current;
    show(Math.min(Math.max(from + moves[e.key], 0), points.length - 1));
  };
  container.onfocus = () => show(current < 0 ? points.length - 1 : current);
  container.onblur = hide;

  container.append(svg, tooltip);
}

/** Small chart with no axis and no interaction (the row already carries the figures). */
export function renderSparkline(container, points, trend = null) {
  container.replaceChildren();
  applyTrend(container, points.length < 2 ? null : trend);
  if (points.length < 2) return;
  const width = 96;
  const height = 30;
  const values = points.map((p) => p[1]);
  const min = Math.min(...values);
  const max = Math.max(...values);
  const t0 = points[0][0];
  const t1 = points[points.length - 1][0];
  const x = (t) => 1 + ((t - t0) / (t1 - t0 || 1)) * (width - 2);
  const y = (v) => 2 + (1 - (v - min) / (max - min || 1)) * (height - 4);
  const line = points.map((p, i) => `${i ? "L" : "M"}${x(p[0]).toFixed(1)},${y(p[1]).toFixed(1)}`).join("");
  const svg = svgEl("svg", { viewBox: `0 0 ${width} ${height}`, width, height, "aria-hidden": "true" });
  svg.appendChild(svgEl("path", { d: `${line}L${x(t1)},${height}L${x(t0)},${height}Z`, class: "chart-fill" }));
  svg.appendChild(svgEl("path", { d: line, class: "chart-line chart-line-thin" }));
  container.appendChild(svg);
}
