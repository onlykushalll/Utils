import os
import numpy as np
from typing import List, Tuple, Optional, Any
import cv2

try:
    from insightface.app import FaceAnalysis
    INSIGHTFACE_AVAILABLE = True
except ImportError:
    INSIGHTFACE_AVAILABLE = False

from facerecog_engine.exceptions import ModelLoadError


class BBoxKalmanFilter:
    """Constant-velocity Kalman filter for tracking a face bounding box."""

    def __init__(self, process_std: float = 45.0, measurement_std: float = 28.0):
        self.process_std = float(process_std)
        self.measurement_std = float(measurement_std)
        self._x: Optional[np.ndarray] = None
        self._p: Optional[np.ndarray] = None
        self._last_ts: Optional[float] = None

    @property
    def ready(self) -> bool:
        return self._x is not None

    def reset(self) -> None:
        self._x = None
        self._p = None
        self._last_ts = None

    def update(self, bbox: Optional[Tuple[float, float, float, float]], timestamp: float) -> None:
        measurement = self._bbox_to_measurement(bbox)
        if measurement is None:
            return

        if self._x is None:
            self._x = np.zeros(8, dtype=np.float64)
            self._x[:4] = measurement
            self._p = np.eye(8, dtype=np.float64) * 100.0
            self._last_ts = timestamp
            return

        self.predict(timestamp)
        assert self._x is not None and self._p is not None
        h = np.zeros((4, 8), dtype=np.float64)
        h[:4, :4] = np.eye(4, dtype=np.float64)
        r = np.eye(4, dtype=np.float64) * (self.measurement_std ** 2)
        innovation = measurement - (h @ self._x)
        s = h @ self._p @ h.T + r
        k = self._p @ h.T @ np.linalg.inv(s)
        self._x = self._x + (k @ innovation)
        self._p = (np.eye(8, dtype=np.float64) - k @ h) @ self._p
        self._last_ts = timestamp

    def predict(self, timestamp: float) -> Optional[Tuple[float, float, float, float]]:
        if self._x is None or self._p is None:
            return None
        dt = 0.0 if self._last_ts is None else float(np.clip(timestamp - self._last_ts, 0.0, 1.0))
        if dt > 0.0:
            f = np.eye(8, dtype=np.float64)
            f[0, 4] = dt
            f[1, 5] = dt
            f[2, 6] = dt
            f[3, 7] = dt
            q = np.eye(8, dtype=np.float64) * ((self.process_std ** 2) * max(dt, 0.05))
            self._x = f @ self._x
            self._p = f @ self._p @ f.T + q
            self._last_ts = timestamp
        return self.predicted_bbox()

    def predicted_bbox(self) -> Optional[Tuple[float, float, float, float]]:
        if self._x is None:
            return None
        cx, cy, bw, bh = [float(v) for v in self._x[:4]]
        bw = max(1.0, bw)
        bh = max(1.0, bh)
        return cx - bw / 2.0, cy - bh / 2.0, cx + bw / 2.0, cy + bh / 2.0

    @staticmethod
    def _bbox_to_measurement(bbox: Optional[Tuple[float, float, float, float]]) -> Optional[np.ndarray]:
        if bbox is None:
            return None
        x1, y1, x2, y2 = bbox
        bw = x2 - x1
        bh = y2 - y1
        if bw <= 0.0 or bh <= 0.0:
            return None
        return np.array([x1 + bw / 2.0, y1 + bh / 2.0, bw, bh], dtype=np.float64)


class FaceDetector:
    """InsightFace RetinaFace wrapper for face detection and tracking."""

    def __init__(self, model_dir: str, det_size: Tuple[int, int] = (320, 320), onnx_providers: Optional[List[str]] = None):
        if not INSIGHTFACE_AVAILABLE:
            raise ModelLoadError("insightface package is not installed. Please run: pip install insightface")

        self.model_dir = model_dir
        self.det_size = det_size
        self.providers = onnx_providers or ["CPUExecutionProvider"]
        self._app: Optional[FaceAnalysis] = None
        self._load_model()

    def _load_model(self) -> None:
        try:
            self._app = FaceAnalysis(
                name="buffalo_l",
                root=self.model_dir,
                providers=self.providers,
                allowed_modules=["detection"]
            )
            self._app.prepare(ctx_id=0, det_size=self.det_size)
        except Exception as e:
            raise ModelLoadError(f"Failed to load detection model from {self.model_dir}") from e

    def detect(self, frame: np.ndarray) -> List[Any]:
        """Detect faces in a frame. Returns list of face objects containing .bbox, .det_score, .kps."""
        if self._app is None:
            raise ModelLoadError("Detection model is not initialized.")
        try:
            return self._app.get(frame)
        except Exception as e:
            # Return empty if detection fails due to format issues
            return []
