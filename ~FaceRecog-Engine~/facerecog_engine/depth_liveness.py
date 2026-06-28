# depth_liveness.py — Standalone Monocular depth-based liveness via MiDaS
from __future__ import annotations
import os
import cv2
import numpy as np
import logging
from typing import Any, Optional

logger = logging.getLogger("FaceRecog.DepthLiveness")

_MODEL_FILENAME = "midas_v21_small_256.onnx"
_INPUT_SIZE     = 256          # MiDaS small uses 256×256
_REAL_CV_THRESH = 0.10         # CV above this → real
_SPOOF_CV_THRESH = 0.04        # CV below this → flat/spoof


class DepthLivenessDetector:
    """Software 3-D liveness using MiDaS monocular depth estimation."""

    def __init__(self, model_dir: str, onnx_providers: Optional[list[str]] = None):
        self._session = None
        self._input_name: str = "input"
        self.providers = onnx_providers or ["CPUExecutionProvider"]
        self._load_model(model_dir)

    def _load_model(self, model_dir: str) -> None:
        model_path = os.path.join(model_dir, _MODEL_FILENAME)
        if not os.path.exists(model_path):
            logger.info("MiDaS model not found at %s — depth liveness disabled.", model_path)
            return
        try:
            import onnxruntime as ort
            sess_opts = ort.SessionOptions()
            sess_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            self._session = ort.InferenceSession(
                model_path,
                sess_options=sess_opts,
                providers=self.providers,
            )
            self._input_name = self._session.get_inputs()[0].name
            logger.info("MiDaS depth model loaded: %s", os.path.basename(model_path))
        except Exception as e:
            logger.warning("MiDaS load failed: %s — depth liveness disabled", e)

    @property
    def available(self) -> bool:
        return self._session is not None

    def score(self, frame: np.ndarray, face: Any) -> float:
        """Compute depth-based liveness score for a detected face."""
        if not self.available:
            return 0.5

        face_crop = self._extract_face_region(frame, face)
        if face_crop is None:
            return 0.5

        depth_map = self._predict_depth(face_crop)
        if depth_map is None:
            return 0.5

        return self._depth_variance_score(depth_map, face_crop.shape)

    def _predict_depth(self, face_img: np.ndarray) -> np.ndarray | None:
        """Run MiDaS on the face crop, return normalised depth map."""
        try:
            resized = cv2.resize(face_img, (_INPUT_SIZE, _INPUT_SIZE))
            rgb     = cv2.cvtColor(resized, cv2.COLOR_BGR2RGB).astype(np.float32)

            mean = np.array([0.485, 0.456, 0.406], dtype=np.float32)
            std  = np.array([0.229, 0.224, 0.225], dtype=np.float32)
            rgb  = (rgb / 255.0 - mean) / std

            blob   = rgb.transpose(2, 0, 1)[np.newaxis]
            output = self._session.run(None, {self._input_name: blob})[0]

            depth = output.squeeze()
            mn, mx = float(depth.min()), float(depth.max())
            if mx - mn < 1e-6:
                return None
            return (depth - mn) / (mx - mn)
        except Exception as e:
            logger.debug("MiDaS inference error: %s", e)
            return None

    def _depth_variance_score(self, depth_map: np.ndarray, face_shape: tuple) -> float:
        h, w = depth_map.shape
        ch, cw = h // 3, w // 3
        cells = []
        for row in range(3):
            for col in range(3):
                cell = depth_map[row*ch:(row+1)*ch, col*cw:(col+1)*cw]
                cells.append(float(np.mean(cell)))

        cells = np.array(cells)
        mean  = float(np.mean(cells)) + 1e-6
        cv    = float(np.std(cells)) / mean

        centre = cells[4]
        corner_mean = float(np.mean([cells[0], cells[2], cells[6], cells[8]]))
        nose_delta  = abs(centre - corner_mean)

        depth_score = (cv / _REAL_CV_THRESH) * 0.6 + (nose_delta / 0.15) * 0.4
        return float(np.clip(depth_score, 0.0, 1.0))

    @staticmethod
    def _extract_face_region(frame: np.ndarray, face: Any, padding: float = 0.15) -> np.ndarray | None:
        try:
            x1, y1, x2, y2 = [int(v) for v in face.bbox]
            fw, fh = x2 - x1, y2 - y1
            if fw < 32 or fh < 32:
                return None
            px, py = int(fw * padding), int(fh * padding)
            ih, iw = frame.shape[:2]
            x1 = max(0, x1 - px)
            y1 = max(0, y1 - py)
            x2 = min(iw, x2 + px)
            y2 = min(ih, y2 + py)
            crop = frame[y1:y2, x1:x2]
            return crop if crop.size > 0 else None
        except Exception:
            return None
