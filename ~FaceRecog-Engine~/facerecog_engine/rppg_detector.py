# rppg_detector.py — Standalone CHROM rPPG blood-flow liveness detector
from __future__ import annotations
import logging
from collections import deque
from typing import Any
import cv2
import numpy as np

try:
    from scipy import signal as scipy_signal
    _SCIPY_OK = True
except ImportError:
    _SCIPY_OK = False

logger = logging.getLogger("FaceRecog.rPPG")


class CHROMrPPGDetector:
    MIN_FRAMES = 45
    WINDOW_FRAMES = 90
    FPS = 15.0
    FREQ_LO = 0.67
    FREQ_HI = 4.00

    def __init__(self):
        self._rgb_buf: deque[tuple[float, float, float]] = deque(maxlen=self.WINDOW_FRAMES)
        self._score: float = 0.5

    def reset(self) -> None:
        self._rgb_buf.clear()
        self._score = 0.5

    @property
    def score(self) -> float:
        return self._score

    @property
    def has_signal(self) -> bool:
        return len(self._rgb_buf) >= self.MIN_FRAMES

    def update(self, frame: np.ndarray, face: Any) -> float:
        if not _SCIPY_OK:
            return 0.5

        roi = self._skin_roi(frame, face)
        if roi is None or roi.size == 0:
            return self._score

        b, g, r = cv2.split(roi)
        red = float(np.mean(r))
        green = float(np.mean(g))
        blue = float(np.mean(b))
        if red < 15 or green < 15:
            return self._score

        self._rgb_buf.append((red, green, blue))
        if not self.has_signal:
            return 0.5

        self._score = self._chrom()
        return self._score

    def _chrom(self) -> float:
        frames = np.array(self._rgb_buf, dtype=np.float64)
        red = frames[:, 0]
        green = frames[:, 1]
        blue = frames[:, 2]

        red_norm = red / (np.mean(red) + 1e-9)
        green_norm = green / (np.mean(green) + 1e-9)
        blue_norm = blue / (np.mean(blue) + 1e-9)
        x_signal = 3 * red_norm - 2 * green_norm
        y_signal = 1.5 * red_norm + green_norm - 1.5 * blue_norm
        chrom_signal = x_signal - (np.std(x_signal) + 1e-9) / (np.std(y_signal) + 1e-9) * y_signal

        nyquist = self.FPS / 2.0
        try:
            b, a = scipy_signal.butter(
                4,
                [self.FREQ_LO / nyquist, min(self.FREQ_HI / nyquist, 0.98)],
                btype="band",
            )
            chrom_signal = scipy_signal.filtfilt(b, a, chrom_signal)
        except Exception as e:
            logger.debug("rPPG filter failed: %s", e)
            return 0.5

        sample_count = len(chrom_signal)
        fft = np.abs(np.fft.rfft(chrom_signal, n=sample_count * 2))
        freqs = np.fft.rfftfreq(sample_count * 2, d=1.0 / self.FPS)
        mask = (freqs >= self.FREQ_LO) & (freqs <= self.FREQ_HI)
        if mask.sum() < 2:
            return 0.5

        snr = float(np.max(fft[mask])) / (float(np.mean(fft[mask])) + 1e-9)
        score = float(np.clip((snr - 1.3) / (3.5 - 1.3), 0.0, 1.0))
        return score

    def _skin_roi(self, frame: np.ndarray, face: Any) -> np.ndarray | None:
        try:
            x1, y1, x2, y2 = [int(v) for v in face.bbox]
        except Exception:
            return None

        face_h = y2 - y1
        face_w = x2 - x1
        roi = frame[
            max(0, y1 + int(face_h * 0.05)):min(frame.shape[0], y1 + int(face_h * 0.35)),
            max(0, x1 + int(face_w * 0.20)):min(frame.shape[1], x2 - int(face_w * 0.20)),
        ]
        return roi if roi.size > 0 else None
