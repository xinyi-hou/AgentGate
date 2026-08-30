from __future__ import annotations

import csv
from collections.abc import Callable
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

WIDTH = 1200
HEIGHT = 720
MARGIN_LEFT = 110
MARGIN_RIGHT = 55
MARGIN_TOP = 75
MARGIN_BOTTOM = 95
COLORS = ((34, 92, 146), (190, 68, 54))


def _font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for path in (
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
    ):
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def _line_chart(
    output: Path,
    *,
    title: str,
    x_label: str,
    y_label: str,
    series: list[tuple[str, list[tuple[float, float]]]],
    y_format: Callable[[float], str] = lambda value: f"{value:.1f}",
) -> None:
    image = Image.new("RGB", (WIDTH, HEIGHT), "white")
    draw = ImageDraw.Draw(image)
    title_font = _font(30)
    label_font = _font(21)
    tick_font = _font(17)
    plot_left, plot_top = MARGIN_LEFT, MARGIN_TOP
    plot_right, plot_bottom = WIDTH - MARGIN_RIGHT, HEIGHT - MARGIN_BOTTOM
    all_points = [point for _, points in series for point in points]
    x_values = [point[0] for point in all_points]
    y_values = [point[1] for point in all_points]
    x_min, x_max = min(x_values), max(x_values)
    y_min, y_max = 0.0, max(y_values) * 1.1

    def project(point: tuple[float, float]) -> tuple[float, float]:
        x, y = point
        px = plot_left + (x - x_min) / max(x_max - x_min, 1) * (plot_right - plot_left)
        py = plot_bottom - (y - y_min) / max(y_max - y_min, 1) * (plot_bottom - plot_top)
        return px, py

    draw.text((plot_left, 24), title, fill=(25, 25, 25), font=title_font)
    for index in range(6):
        value = y_min + (y_max - y_min) * index / 5
        y = project((x_min, value))[1]
        draw.line((plot_left, y, plot_right, y), fill=(224, 228, 232), width=1)
        label = y_format(value)
        draw.text((plot_left - 14, y), label, fill=(70, 70, 70), font=tick_font, anchor="rm")
    unique_x = sorted(set(x_values))
    tick_indexes = {round(index * (len(unique_x) - 1) / 5) for index in range(6)}
    for value in (unique_x[index] for index in sorted(tick_indexes)):
        x = project((value, y_min))[0]
        draw.line((x, plot_bottom, x, plot_bottom + 7), fill=(55, 55, 55), width=2)
        draw.text(
            (x, plot_bottom + 13), f"{value:g}", fill=(70, 70, 70), font=tick_font, anchor="ma"
        )
    draw.line((plot_left, plot_top, plot_left, plot_bottom), fill=(45, 45, 45), width=2)
    draw.line((plot_left, plot_bottom, plot_right, plot_bottom), fill=(45, 45, 45), width=2)

    for index, (name, points) in enumerate(series):
        color = COLORS[index % len(COLORS)]
        projected = [project(point) for point in points]
        draw.line(projected, fill=color, width=4, joint="curve")
        for x, y in projected:
            draw.ellipse((x - 6, y - 6, x + 6, y + 6), fill=color, outline="white", width=2)
        legend_x = plot_right - 235
        legend_y = plot_top + 8 + index * 34
        draw.line((legend_x, legend_y, legend_x + 35, legend_y), fill=color, width=4)
        draw.text((legend_x + 47, legend_y), name, fill=(45, 45, 45), font=tick_font, anchor="lm")

    draw.text(
        ((plot_left + plot_right) / 2, HEIGHT - 42),
        x_label,
        fill=(45, 45, 45),
        font=label_font,
        anchor="mm",
    )
    label_box = draw.textbbox((0, 0), y_label, font=label_font)
    label_image = Image.new(
        "RGBA",
        (label_box[2] - label_box[0] + 12, label_box[3] - label_box[1] + 12),
        (255, 255, 255, 0),
    )
    ImageDraw.Draw(label_image).text((6, 6), y_label, fill=(45, 45, 45), font=label_font)
    rotated = label_image.rotate(90, expand=True)
    image.paste(rotated, (18, int((plot_top + plot_bottom - rotated.height) / 2)), rotated)
    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output, optimize=True)


def build_figures(output_root: str | Path = "evaluation/results") -> None:
    root = Path(output_root)
    with (root / "tables" / "rq4_graph_scaling.csv").open(encoding="utf-8") as handle:
        graph_rows = list(csv.DictReader(handle))
    by_mode = {
        mode: [row for row in graph_rows if row["mode"] == mode]
        for mode in ("AgentGate Rules-only", "AgentGate Full")
    }
    _line_chart(
        root / "figures" / "atg_size_vs_graph_update_latency.png",
        title="ATG Size vs Runtime Latency",
        x_label="Total graph edges",
        y_label="Mean latency (ms)",
        series=[
            (
                mode.replace("AgentGate ", ""),
                [(float(row["total_edges"]), float(row["mean_call_latency_ms"])) for row in rows],
            )
            for mode, rows in by_mode.items()
        ],
    )
    full = by_mode["AgentGate Full"]
    _line_chart(
        root / "figures" / "atg_size_vs_memory.png",
        title="ATG Size vs Serialized Memory Estimate",
        x_label="Total graph edges",
        y_label="Memory (KiB)",
        series=[
            (
                "Full",
                [
                    (float(row["total_edges"]), float(row["graph_memory_bytes"]) / 1024)
                    for row in full
                ],
            )
        ],
    )
    direct = {
        int(row["tool_calls"]): float(row["mean_call_latency_ms"])
        for row in graph_rows
        if row["mode"] == "No Defense (direct executor)"
    }
    _line_chart(
        root / "figures" / "trajectory_length_vs_added_latency.png",
        title="Trajectory Length vs Added Runtime Latency",
        x_label="Tool calls",
        y_label="Added latency (ms/call)",
        series=[
            (
                mode.replace("AgentGate ", ""),
                [
                    (
                        float(row["tool_calls"]),
                        float(row["mean_call_latency_ms"]) - direct[int(row["tool_calls"])],
                    )
                    for row in rows
                ],
            )
            for mode, rows in by_mode.items()
        ],
    )


if __name__ == "__main__":
    build_figures()
