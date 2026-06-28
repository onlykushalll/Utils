# face_quality.py — Standalone face quality heuristics
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
import cv2
import numpy as np


@dataclass(frozen=True)
class FaceQuality:
    score: float
    det_score: float
    sharpness: float
    sharp_score: float
    illumination_mean: float
    illumination_score: float
    size_score: float
    height_frac: float
    center_offset: float


def measure_face_quality(frame: np.ndarray, face: Any) -> FaceQuality:
    """Estimate if a detected face is sharp, lit, foreground-sized, and centered."""
    det_score = float(getattr(face, "det_score", 0.75))
    h, w = frame.shape[:2]

    try:
        x1, y1, x2, y2 = [float(v) for v in face.bbox]
    except Exception:
        return _empty_quality(det_score)

    box_w = max(0.0, x2 - x1)
    box_h = max(0.0, y2 - y1)
    if box_w <= 1.0 or box_h <= 1.0 or h <= 0 or w <= 0:
        return _empty_quality(det_score)

    ix1 = max(0, int(round(x1)))
    iy1 = max(0, int(round(y1)))
    ix2 = min(w, int(round(x2)))
    iy2 = min(h, int(round(y2)))
    roi = frame[iy1:iy2, ix1:ix2]
    if roi.size == 0:
        return _empty_quality(det_score)

    try:
        gray = cv2.cvtColor(cv2.resize(roi, (64, 64)), cv2.COLOR_BGR2GRAY)
        sharpness = float(cv2.Laplacian(gray, cv2.CV_64F).var())
    except Exception:
        sharpness = 0.0
    sharp_score = float(np.clip(sharpness / 400.0, 0.0, 1.0))

    try:
        ycrcb = cv2.cvtColor(roi, cv2.COLOR_BGR2YCrCb)
        illumination_mean = float(np.mean(ycrcb[:, :, 0]))
    except Exception:
        illumination_mean = 128.0
    illumination_score = float(np.clip(1.0 - abs(illumination_mean - 128.0) / 128.0, 0.0, 1.0))

    face_area = box_w * box_h
    size_score = float(np.clip(face_area / ((h * w + 1.0) * 0.15), 0.0, 1.0))
    height_frac = float(box_h / max(1.0, float(h)))

    face_center_x = (x1 + x2) / 2.0
    face_center_y = (y1 + y2) / 2.0
    dist_x = abs(face_center_x - w / 2.0) / max(1.0, w / 2.0)
    dist_y = abs(face_center_y - h / 2.0) / max(1.0, h / 2.0)
    center_offset = float(np.clip((dist_x + dist_y) / 2.0, 0.0, 1.0))
    center_score = 1.0 - center_offset

    score = float(
        det_score * 0.30
        + sharp_score * 0.25
        + illumination_score * 0.20
        + size_score * 0.15
        + center_score * 0.10
    )
    return FaceQuality(
        score=score,
        det_score=det_score,
        sharpness=sharpness,
        sharp_score=sharp_score,
        illumination_mean=illumination_mean,
        illumination_score=illumination_score,
        size_score=size_score,
        height_frac=height_frac,
        center_offset=center_offset,
    )


def _empty_quality(det_score: float) -> FaceQuality:
    return FaceQuality(
        score=float(det_score) * 0.20,
        det_score=float(det_score),
        sharpness=0.0,
        sharp_score=0.0,
        illumination_mean=0.0,
        illumination_score=0.0,
        size_score=0.0,
        height_frac=0.0,
        center_offset=1.0,
    )
