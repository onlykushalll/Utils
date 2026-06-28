# liveness_detector.py — Standalone 12-layer passive anti-spoofing engine
import cv2
import numpy as np
import os
import logging
from collections import deque
from typing import Any, Optional

from facerecog_engine.attention_detector import AttentionDetector
from facerecog_engine.depth_liveness import DepthLivenessDetector
from facerecog_engine.rppg_detector import CHROMrPPGDetector
from facerecog_engine.face_quality import measure_face_quality

logger = logging.getLogger("FaceRecog.Liveness")

_ONNX_AVAILABLE = False
_ort = None
try:
    import onnxruntime as ort
    _ort = ort
    _ONNX_AVAILABLE = True
except ImportError:
    pass


class LivenessDetector:
    _WINDOW = 30
    _MIN_FRAMES_FOR_PASS = 5
    _MIN_USABLE_FACE_QUALITY = 0.40

    def __init__(self, model_dir: str = "", onnx_providers: Optional[list[str]] = None):
        self._score_history: deque[float] = deque(maxlen=self._WINDOW)
        self._frame_index = 0
        self._last_smoothed_score = 0.0
        self.providers = onnx_providers or ["CPUExecutionProvider"]

        self._eye_brightness_history: deque[float] = deque(maxlen=30)
        self._blink_count = 0
        self._blink_cooldown = 0
        self._last_blink_frame = 0
        self._in_blink = False

        self._face_center_history: deque[tuple[float, float]] = deque(maxlen=30)
        self._frame_hashes: deque[bytes] = deque(maxlen=300)
        self._duplicate_frame_count = 0

        self._landmark_ratios: deque[list[float]] = deque(maxlen=20)
        self._hist_history: deque[np.ndarray] = deque(maxlen=15)
        self._onnx_score_history: deque[float] = deque(maxlen=5)

        self._depth_liveness = DepthLivenessDetector(model_dir, onnx_providers=self.providers) if model_dir else None
        self._rppg = CHROMrPPGDetector()
        self._attention = AttentionDetector()

        self._antispoof_session: Optional[Any] = None
        self._antispoof_input_name: str = "input"
        self._antispoof_h: int = 128
        self._antispoof_w: int = 128
        self._last_onnx_idx0: float = float("nan")
        self._last_onnx_idx1: float = float("nan")
        self._onnx_consecutive_failures: int = 0
        self._load_antispoof_model(model_dir)

    def reset_session(self) -> None:
        self._score_history.clear()
        self._frame_index = 0
        self._last_smoothed_score = 0.0
        self._eye_brightness_history.clear()
        self._blink_count = 0
        self._blink_cooldown = 0
        self._last_blink_frame = 0
        self._in_blink = False
        self._face_center_history.clear()
        self._frame_hashes.clear()
        self._duplicate_frame_count = 0
        self._landmark_ratios.clear()
        self._hist_history.clear()
        self._onnx_score_history.clear()
        if self._rppg is not None:
            self._rppg.reset()
        self._onnx_consecutive_failures = 0

    def close(self) -> None:
        if self._attention is not None:
            try:
                self._attention.close()
            except Exception:
                pass

    _ANTISPOOF_FILENAMES = [
        "antispoof_minifasv2.onnx",
        "anti_spoof.onnx",
        "MiniFASNetV2.onnx",
        "minifasv2_128.onnx",
    ]

    def _load_antispoof_model(self, model_dir: str):
        if not _ONNX_AVAILABLE or not model_dir:
            return

        model_path = None
        for fname in self._ANTISPOOF_FILENAMES:
            candidate = os.path.join(model_dir, fname)
            if os.path.exists(candidate):
                model_path = candidate
                break

        if model_path is None:
            logger.info("No anti-spoof ONNX model found in %s — using heuristic layers only.", model_dir)
            return

        try:
            opts = _ort.SessionOptions()
            opts.inter_op_num_threads = 1
            opts.intra_op_num_threads = 2
            opts.graph_optimization_level = _ort.GraphOptimizationLevel.ORT_ENABLE_ALL

            self._antispoof_session = _ort.InferenceSession(
                model_path,
                sess_options=opts,
                providers=self.providers,
            )

            inp = self._antispoof_session.get_inputs()[0]
            self._antispoof_input_name = inp.name
            shape = inp.shape
            self._antispoof_h = int(shape[2]) if len(shape) > 2 and isinstance(shape[2], int) else 128
            self._antispoof_w = int(shape[3]) if len(shape) > 3 and isinstance(shape[3], int) else 128

            logger.info("Anti-spoof ONNX loaded: %s (input %dx%d)", os.path.basename(model_path), self._antispoof_h, self._antispoof_w)
        except Exception as e:
            logger.warning("Failed to load anti-spoof model: %s", e)
            self._antispoof_session = None

    def score_fast(self, frame: np.ndarray, face: Any) -> float:
        quality = measure_face_quality(frame, face)
        if quality.score < self._MIN_USABLE_FACE_QUALITY:
            return 0.0

        roi = self._extract_roi(frame, face)
        if roi is None:
            return 0.0

        self._frame_index += 1
        replay_penalty = self._replay_detection(roi)
        if replay_penalty < 0.3:
            logger.warning("Replay attack detected during fast liveness")
            return 0.1

        lbp_score = self._lbp_texture_score(roi)
        specular_score = self._specular_score(roi)
        temporal_score = self._temporal_blink_score(frame, face)
        boundary_score = self._boundary_score(frame, face)
        onnx_score = self._onnx_antispoof_score(roi)
        depth_score = self._depth_geometry_score(face)

        if onnx_score is not None:
            combined = (
                onnx_score * 0.28
                + lbp_score * 0.18
                + specular_score * 0.12
                + temporal_score * 0.12
                + boundary_score * 0.12
                + depth_score * 0.10
                + replay_penalty * 0.08
            )
        else:
            combined = (
                lbp_score * 0.24
                + specular_score * 0.16
                + temporal_score * 0.16
                + boundary_score * 0.16
                + depth_score * 0.14
                + replay_penalty * 0.14
            )
        return float(np.clip(combined, 0.0, 1.0))

    def score_full(self, frame: np.ndarray, face: Any) -> float:
        quality = measure_face_quality(frame, face)
        if quality.score < self._MIN_USABLE_FACE_QUALITY:
            return self._last_smoothed_score if self._score_history else 0.0

        roi = self._extract_roi(frame, face)
        if roi is None:
            return 0.0

        self._frame_index += 1
        replay_penalty = self._replay_detection(roi)
        if replay_penalty < 0.3:
            logger.warning("Replay attack detected (duplicate frames)")
            return 0.1

        lbp_score = self._lbp_texture_score(roi)
        specular_score = self._specular_score(roi)
        color_score = self._color_space_score(roi)
        moire_score = self._moire_score(roi)
        temporal_score = self._temporal_blink_score(frame, face)
        boundary_score = self._boundary_score(frame, face)
        onnx_score = self._onnx_antispoof_score(roi)
        depth_score = self._depth_geometry_score(face)
        hist_score = self._histogram_consistency_score(roi)

        midas_score = (
            self._depth_liveness.score(frame, face)
            if self._depth_liveness is not None else 0.5
        )

        rppg_score = self._rppg.update(frame, face)
        attention_score = self._attention.score(frame)

        if onnx_score is not None:
            combined = (
                onnx_score       * 0.10 +
                lbp_score        * 0.13 +
                specular_score   * 0.08 +
                color_score      * 0.09 +
                moire_score      * 0.10 +
                temporal_score   * 0.10 +
                boundary_score   * 0.09 +
                depth_score      * 0.09 +
                hist_score       * 0.08 +
                replay_penalty   * 0.14
            )
        else:
            combined = (
                lbp_score        * 0.18 +
                specular_score   * 0.10 +
                color_score      * 0.14 +
                moire_score      * 0.10 +
                temporal_score   * 0.14 +
                boundary_score   * 0.08 +
                depth_score      * 0.12 +
                hist_score       * 0.07 +
                replay_penalty   * 0.07
            )

        if self._depth_liveness is not None and self._depth_liveness.available:
            if midas_score < 0.38:
                combined = combined * 0.85 + midas_score * 0.15
            elif midas_score > 0.72:
                combined = combined * 0.88 + midas_score * 0.12

        if self._rppg.has_signal:
            if rppg_score >= 0.60 or attention_score >= 0.75:
                combined = min(
                    0.98,
                    combined
                    + max(0.0, rppg_score - 0.50) * 0.06
                    + max(0.0, attention_score - 0.50) * 0.04,
                )
            else:
                combined = combined * 0.94 + rppg_score * 0.04 + attention_score * 0.02

        self._score_history.append(combined)

        if self._frame_index < self._MIN_FRAMES_FOR_PASS:
            smoothed = min(float(np.mean(self._score_history)), 0.75)
        else:
            window = list(self._score_history)[-30:]
            smoothed = float(np.percentile(window, 10))

        self._last_smoothed_score = smoothed
        return smoothed

    def score(self, frame: np.ndarray, face: Any) -> float:
        return self.score_full(frame, face)

    def _lbp_texture_score(self, roi: np.ndarray) -> float:
        gray = cv2.cvtColor(roi, cv2.COLOR_BGR2GRAY)
        lbp = self._compute_lbp(gray)
        lbp_inner = lbp[1:-1, 1:-1]
        hist, _ = np.histogram(lbp_inner.ravel(), bins=256, range=(0, 256))
        hist = hist.astype(float)
        hist /= (hist.sum() + 1e-7)
        entropy = -np.sum(hist * np.log2(hist + 1e-7))
        lbp_var = float(np.var(lbp_inner.astype(np.float32)))
        entropy_score = float(np.clip((entropy - 3.5) / 3.0, 0.0, 1.0))
        var_score = float(np.clip((lbp_var - 1000) / 2000, 0.0, 1.0))
        return entropy_score * 0.7 + var_score * 0.3

    def _compute_lbp(self, gray: np.ndarray) -> np.ndarray:
        rows, cols = gray.shape
        lbp = np.zeros_like(gray)
        offsets = [(-1,-1), (-1,0), (-1,1), (0,1), (1,1), (1,0), (1,-1), (0,-1)]
        center = gray[1:-1, 1:-1].astype(np.int16)
        for bit, (dr, dc) in enumerate(offsets):
            neighbor = gray[1+dr:rows-1+dr, 1+dc:cols-1+dc].astype(np.int16)
            lbp[1:-1, 1:-1] |= ((neighbor >= center).astype(np.uint8) << bit)
        return lbp

    def _specular_score(self, roi: np.ndarray) -> float:
        hsv = cv2.cvtColor(roi, cv2.COLOR_BGR2HSV)
        saturation = hsv[:, :, 1]
        value = hsv[:, :, 2]
        glare_mask = (value > 225) & (saturation < 40)
        glare_fraction = float(np.count_nonzero(glare_mask)) / float(glare_mask.size)
        if glare_fraction < 0.05:
            return 0.9
        ys, xs = np.nonzero(glare_mask)
        if xs.size == 0:
            return 0.9
        spatial_std = float((np.std(xs) + np.std(ys)) * 0.5)
        if glare_fraction > 0.15 and spatial_std < 30.0:
            return 0.2
        t = np.clip((glare_fraction - 0.05) / 0.10, 0.0, 1.0)
        score = 0.9 - (0.7 * t)
        if spatial_std >= 30.0:
            score = max(score, 0.65)
        return float(np.clip(score, 0.2, 0.9))

    def _color_space_score(self, roi: np.ndarray) -> float:
        h, w = roi.shape[:2]
        y1, y2 = int(h * 0.12), int(h * 0.88)
        x1, x2 = int(w * 0.12), int(w * 0.88)
        core = roi[y1:y2, x1:x2]
        if core.size == 0:
            core = roi
        ycrcb = cv2.cvtColor(core, cv2.COLOR_BGR2YCrCb)
        cr = ycrcb[:, :, 1].astype(np.float32)
        cb = ycrcb[:, :, 2].astype(np.float32)
        hsv = cv2.cvtColor(core, cv2.COLOR_BGR2HSV)
        hue = hsv[:, :, 0]
        sat = hsv[:, :, 1]
        val = hsv[:, :, 2]
        skin_ycrcb = (cr >= 118) & (cr <= 190) & (cb >= 55) & (cb <= 155)
        skin_hsv = (((hue <= 28) | (hue >= 160)) & (sat >= 18) & (sat <= 210) & (val >= 35))
        skin_mask = skin_ycrcb | skin_hsv
        skin_ratio = float(np.count_nonzero(skin_mask)) / float(skin_mask.size)
        if skin_ratio < 0.10:
            skin_score = 0.35
        elif skin_ratio > 0.85:
            skin_score = 0.70
        else:
            skin_score = float(np.clip(0.45 + (skin_ratio - 0.10) / 0.55, 0.45, 1.0))
        cr_std = float(np.std(cr))
        cb_std = float(np.std(cb))
        cr_var_score = 1.0 - float(np.clip(abs(cr_std - 15) / 15, 0.0, 1.0))
        cb_var_score = 1.0 - float(np.clip(abs(cb_std - 12) / 12, 0.0, 1.0))
        chromatic_score = (cr_var_score + cb_var_score) / 2.0
        cr_flat = cr.flatten()
        cb_flat = cb.flatten()
        if cr_flat.std() > 0 and cb_flat.std() > 0:
            corr = float(np.corrcoef(cr_flat, cb_flat)[0, 1])
            corr_score = float(np.clip(corr * 0.5 + 0.5, 0.2, 1.0))
        else:
            corr_score = 0.3
        score = skin_score * 0.45 + chromatic_score * 0.30 + corr_score * 0.25
        return float(np.clip(score, 0.55, 0.95))

    def _moire_score(self, roi: np.ndarray) -> float:
        gray = cv2.cvtColor(roi, cv2.COLOR_BGR2GRAY).astype(np.float32)
        f_transform = np.fft.fft2(gray)
        f_shift = np.fft.fftshift(f_transform)
        magnitude = np.log1p(np.abs(f_shift))
        h, w = magnitude.shape
        cy, cx = h // 2, w // 2
        r_inner = 5
        r_outer = min(cy, cx) - 1
        y, x = np.ogrid[:h, :w]
        dist = np.sqrt((x - cx)**2 + (y - cy)**2)
        ring_mask = (dist >= r_inner) & (dist <= r_outer)
        ring_values = magnitude[ring_mask]
        if ring_values.size == 0:
            return 0.7
        mean_mag = float(np.mean(ring_values))
        std_mag = float(np.std(ring_values))
        if std_mag < 1e-6:
            return 0.7
        max_mag = float(np.max(ring_values))
        peak_ratio = (max_mag - mean_mag) / std_mag
        if peak_ratio > 10:
            return 0.15
        elif peak_ratio > 7:
            return 0.4
        elif peak_ratio < 4:
            return 0.9
        else:
            return float(np.clip(1.0 - (peak_ratio - 4) / 6, 0.3, 0.9))

    def _temporal_blink_score(self, frame: np.ndarray, face: Any) -> float:
        kps = getattr(face, "kps", None)
        if kps is None or len(kps) < 2:
            return 0.5
        bbox = face.bbox
        fc_x = float(bbox[0] + bbox[2]) / 2.0
        fc_y = float(bbox[1] + bbox[3]) / 2.0
        self._face_center_history.append((fc_x, fc_y))
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        left_eye = kps[0]
        right_eye = kps[1]
        eye_dist = float(np.sqrt((left_eye[0] - right_eye[0])**2 + (left_eye[1] - right_eye[1])**2))
        patch_h = max(int(eye_dist * 0.25), 6)
        patch_w = max(int(eye_dist * 0.35), 8)
        left_brightness = self._eye_patch_brightness(gray, left_eye, patch_w, patch_h)
        right_brightness = self._eye_patch_brightness(gray, right_eye, patch_w, patch_h)
        if left_brightness is None or right_brightness is None:
            return 0.5
        avg_brightness = (left_brightness + right_brightness) / 2.0
        self._eye_brightness_history.append(avg_brightness)
        if self._blink_cooldown > 0:
            self._blink_cooldown -= 1
        if len(self._eye_brightness_history) >= 3 and self._blink_cooldown == 0:
            vals = list(self._eye_brightness_history)
            current = vals[-1]
            prev = vals[-2]
            before = vals[-3]
            if not self._in_blink and prev < before * 0.85 and prev < current * 0.85:
                self._blink_count += 1
                self._last_blink_frame = self._frame_index
                self._blink_cooldown = 5
                self._in_blink = False
            elif current < prev * 0.82:
                self._in_blink = True
            elif current > prev * 1.1:
                self._in_blink = False
        blink_score = 0.5
        if self._blink_count >= 1:
            frames_since_blink = self._frame_index - self._last_blink_frame
            if frames_since_blink <= 60:
                blink_score = 0.95
            elif frames_since_blink <= 120:
                blink_score = 0.8
            else:
                blink_score = 0.6
        movement_score = self._micro_movement_score()
        return blink_score * 0.6 + movement_score * 0.4

    def _eye_patch_brightness(self, gray: np.ndarray, eye_center, pw: int, ph: int) -> Optional[float]:
        h, w = gray.shape
        cx, cy = int(eye_center[0]), int(eye_center[1])
        x1, x2 = max(0, cx - pw), min(w, cx + pw)
        y1, y2 = max(0, cy - ph), min(h, cy + ph)
        if x2 <= x1 or y2 <= y1:
            return None
        patch = gray[y1:y2, x1:x2]
        mid = patch.shape[0] // 2
        upper = float(patch[:mid, :].mean()) if mid > 0 else float(patch.mean())
        lower = float(patch[mid:, :].mean())
        return upper * 0.6 + lower * 0.4

    def _micro_movement_score(self) -> float:
        if len(self._face_center_history) < 10:
            return 0.5
        centers = np.array(list(self._face_center_history))
        diffs = np.diff(centers, axis=0)
        displacements = np.sqrt(diffs[:, 0]**2 + diffs[:, 1]**2)
        mean_disp = float(np.mean(displacements))
        std_disp = float(np.std(displacements))
        if mean_disp < 0.1:
            return 0.2
        if std_disp < 0.05 and mean_disp > 0.3:
            return 0.3
        if mean_disp > 15:
            return 0.4
        return float(np.clip(0.5 + std_disp * 0.3, 0.5, 0.95))

    def _boundary_score(self, frame: np.ndarray, face: Any) -> float:
        bbox = face.bbox
        x1, y1, x2, y2 = [int(v) for v in bbox]
        h, w = frame.shape[:2]
        expand = int((x2 - x1) * 0.4)
        ox1, oy1 = max(0, x1 - expand), max(0, y1 - expand)
        ox2, oy2 = min(w, x2 + expand), min(h, y2 + expand)
        outer_roi = frame[oy1:oy2, ox1:ox2]
        if outer_roi.size == 0:
            return 0.7
        gray = cv2.cvtColor(outer_roi, cv2.COLOR_BGR2GRAY)
        edges = cv2.Canny(gray, 50, 150)
        lines = cv2.HoughLinesP(edges, 1, np.pi / 180, threshold=40, minLineLength=30, maxLineGap=10)
        if lines is None:
            return 0.9
        roi_h, roi_w = outer_roi.shape[:2]
        min_dim = min(roi_h, roi_w)
        border_margin = max(12, int(min_dim * 0.12))
        long_lines = 0
        sides = {"top": False, "bottom": False, "left": False, "right": False}
        for line in lines:
            x1l, y1l, x2l, y2l = line[0]
            dx, dy = float(x2l - x1l), float(y2l - y1l)
            length = float(np.sqrt(dx * dx + dy * dy))
            if length <= min_dim * 0.38:
                continue
            long_lines += 1
            angle = abs(float(np.degrees(np.arctan2(dy, dx))))
            angle = min(angle, 180.0 - angle)
            if angle <= 12.0:
                avg_y = (float(y1l) + float(y2l)) * 0.5
                if avg_y <= border_margin:
                    sides["top"] = True
                elif avg_y >= roi_h - border_margin:
                    sides["bottom"] = True
            elif abs(angle - 90.0) <= 12.0:
                avg_x = (float(x1l) + float(x2l)) * 0.5
                if avg_x <= border_margin:
                    sides["left"] = True
                elif avg_x >= roi_w - border_margin:
                    sides["right"] = True
        side_count = sum(1 for present in sides.values() if present)
        if side_count >= 4:
            return 0.2
        if side_count == 3:
            return 0.45
        if side_count == 2 and long_lines >= 4:
            return 0.65
        if long_lines >= 6:
            return 0.72
        return 0.85

    def _onnx_antispoof_score(self, roi: np.ndarray) -> Optional[float]:
        if self._antispoof_session is None:
            return None
        try:
            h, w = self._antispoof_h, self._antispoof_w
            input_name = self._antispoof_input_name
            resized = cv2.resize(roi, (w, h), interpolation=cv2.INTER_LINEAR)
            rgb = cv2.cvtColor(resized, cv2.COLOR_BGR2RGB).astype(np.float32) / 255.0
            chw  = np.transpose(rgb, (2, 0, 1))
            blob = np.expand_dims(chw, axis=0)
            outputs = self._antispoof_session.run(None, {input_name: blob})
            logits  = outputs[0][0]
            exp_logits = np.exp(logits - np.max(logits))
            probs = exp_logits / exp_logits.sum()
            self._last_onnx_idx0 = float(probs[0])
            self._last_onnx_idx1 = float(probs[1]) if len(probs) > 1 else float("nan")
            real_prob = float(probs[0])
            self._onnx_score_history.append(real_prob)
            if len(self._onnx_score_history) >= 3:
                real_prob = float(np.median(self._onnx_score_history))
            return float(np.clip(real_prob, 0.0, 1.0))
        except Exception as e:
            self._onnx_consecutive_failures += 1
            return None

    def _extract_roi(self, frame: np.ndarray, face: Any) -> Optional[np.ndarray]:
        try:
            x1, y1, x2, y2 = [int(v) for v in face.bbox]
            h, w = frame.shape[:2]
            box_w = max(1, x2 - x1)
            box_h = max(1, y2 - y1)
            crop_size = int(max(box_w, box_h) * 1.5)
            if crop_size <= 1:
                return None
            center_x = (x1 + x2) * 0.5
            center_y = (y1 + y2) * 0.5
            crop_x1 = int(center_x - crop_size * 0.5)
            crop_y1 = int(center_y - crop_size * 0.5)
            crop_x2 = crop_x1 + crop_size
            crop_y2 = crop_y1 + crop_size
            src_x1 = max(0, crop_x1)
            src_y1 = max(0, crop_y1)
            src_x2 = min(w, crop_x2)
            src_y2 = min(h, crop_y2)
            if src_x2 <= src_x1 or src_y2 <= src_y1:
                return None
            roi = frame[src_y1:src_y2, src_x1:src_x2]
            top = max(0, -crop_y1)
            left = max(0, -crop_x1)
            bottom = max(0, crop_y2 - h)
            right = max(0, crop_x2 - w)
            if top or bottom or left or right:
                roi = cv2.copyMakeBorder(roi, top, bottom, left, right, cv2.BORDER_REFLECT_101)
            interpolation = cv2.INTER_LANCZOS4 if crop_size < 128 else cv2.INTER_AREA
            return cv2.resize(roi, (128, 128), interpolation=interpolation)
        except Exception:
            return None

    def _depth_geometry_score(self, face: Any) -> float:
        kps = getattr(face, "kps", None)
        if kps is None or len(kps) < 5:
            return 0.5
        left_eye, right_eye = kps[0], kps[1]
        nose = kps[2]
        left_mouth, right_mouth = kps[3], kps[4]
        eye_dist = float(np.sqrt((left_eye[0] - right_eye[0])**2 + (left_eye[1] - right_eye[1])**2))
        if eye_dist < 1.0:
            return 0.3
        nose_to_left = float(np.sqrt((nose[0] - left_eye[0])**2 + (nose[1] - left_eye[1])**2))
        nose_to_right = float(np.sqrt((nose[0] - right_eye[0])**2 + (nose[1] - right_eye[1])**2))
        mouth_width = float(np.sqrt((left_mouth[0] - right_mouth[0])**2 + (left_mouth[1] - right_mouth[1])**2))
        asymmetry = abs(nose_to_left - nose_to_right) / eye_dist
        eye_mid_y = (left_eye[1] + right_eye[1]) / 2.0
        mouth_mid_y = (left_mouth[1] + right_mouth[1]) / 2.0
        upper_face = abs(nose[1] - eye_mid_y)
        lower_face = abs(mouth_mid_y - nose[1])
        vert_ratio = upper_face / (lower_face + 1e-6)
        width_ratio = mouth_width / eye_dist
        ratios = [asymmetry, vert_ratio, width_ratio]
        self._landmark_ratios.append(ratios)
        if len(self._landmark_ratios) < 5:
            return 0.5
        ratios_arr = np.array(list(self._landmark_ratios))
        ratio_stds = np.std(ratios_arr, axis=0)
        mean_variance = float(np.mean(ratio_stds))
        if mean_variance < 0.003:
            return 0.2
        if mean_variance < 0.008:
            return 0.5
        if mean_variance > 0.12:
            return 0.45
        if mean_variance > 0.05:
            return 0.62
        return float(np.clip(0.55 + mean_variance * 10, 0.55, 0.95))

    def _histogram_consistency_score(self, roi: np.ndarray) -> float:
        hsv = cv2.cvtColor(roi, cv2.COLOR_BGR2HSV)
        hist = cv2.calcHist([hsv], [0, 1], None, [18, 8], [0, 180, 0, 256]).flatten().astype(np.float32)
        hist /= (hist.sum() + 1e-7)
        self._hist_history.append(hist)
        if len(self._hist_history) < 5:
            return 0.60
        similarities = []
        hists = list(self._hist_history)
        for i in range(1, len(hists)):
            sim = float(cv2.compareHist(hists[i-1], hists[i], cv2.HISTCMP_CORREL))
            similarities.append(sim)
        mean_sim = float(np.mean(similarities))
        std_sim = float(np.std(similarities))
        if mean_sim > 0.999 and std_sim < 0.0005:
            return 0.45
        if mean_sim > 0.996 and std_sim < 0.001:
            return 0.55
        if mean_sim < 0.70:
            return 0.55
        jitter_score = float(np.clip(std_sim / 0.006, 0.0, 1.0))
        variation_score = float(np.clip((1.0 - mean_sim) / 0.08, 0.0, 1.0))
        return float(np.clip(0.62 + jitter_score * 0.20 + variation_score * 0.13, 0.55, 0.95))

    def _dhash(self, roi: np.ndarray) -> bytes:
        small = cv2.resize(roi, (9, 8))
        gray = cv2.cvtColor(small, cv2.COLOR_BGR2GRAY)
        diff = gray[:, 1:] > gray[:, :-1]
        hash_bytes = bytearray(8)
        for i in range(8):
            val = 0
            for j in range(8):
                if diff[i, j]:
                    val |= (1 << j)
            hash_bytes[i] = val
        return bytes(hash_bytes)

    def _hamming_distance(self, h1: bytes, h2: bytes) -> int:
        return sum(bin(b1 ^ b2).count("1") for b1, b2 in zip(h1, h2))

    def _replay_detection(self, roi: np.ndarray) -> float:
        frame_hash = self._dhash(roi)
        matches = sum(1 for h in self._frame_hashes if self._hamming_distance(h, frame_hash) < 3)
        self._frame_hashes.append(frame_hash)
        if matches == 0:
            self._duplicate_frame_count = max(0, self._duplicate_frame_count - 1)
            return 0.95
        self._duplicate_frame_count += 1
        if self._duplicate_frame_count <= 2:
            return 0.8
        if self._duplicate_frame_count <= 5:
            return 0.5
        return 0.1
