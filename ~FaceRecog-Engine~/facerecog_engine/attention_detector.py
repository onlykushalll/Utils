# attention_detector.py — MediaPipe iris gaze VARIABILITY detector
import cv2
import numpy as np
import logging
from collections import deque

logger = logging.getLogger("FaceRecog.Attention")

_LEFT_IRIS   = [468, 469, 470, 471]
_RIGHT_IRIS  = [472, 473, 474, 475]
_L_EAR_V     = [(159, 145), (158, 153)]
_L_EAR_H     = (33, 133)
_R_EAR_V     = [(386, 374), (385, 380)]
_R_EAR_H     = (362, 263)

_MIN_STD_LIVE   = 0.008
_SPOOF_STD_MAX  = 0.002
_HISTORY_LEN    = 45
_EAR_BLINK_THRESH = 0.18


class AttentionDetector:
    def __init__(self):
        self._mesh   = None
        self._ready  = False

        self._iris_x_hist: deque[float] = deque(maxlen=_HISTORY_LEN)
        self._iris_y_hist: deque[float] = deque(maxlen=_HISTORY_LEN)

        self._blink_count    = 0
        self._was_blinking   = False
        self._frames_watched = 0

        try:
            import mediapipe as mp
            self._mesh = mp.solutions.face_mesh.FaceMesh(
                static_image_mode=False,
                max_num_faces=1,
                refine_landmarks=True,
                min_detection_confidence=0.5,
                min_tracking_confidence=0.5,
            )
            self._ready = True
            logger.info("AttentionDetector ready (gaze variability mode)")
        except Exception as e:
            logger.warning("MediaPipe unavailable — attention layer disabled: %s", e)

    def close(self) -> None:
        if self._mesh is not None:
            try:
                self._mesh.close()
            except Exception:
                pass

    def score(self, frame: np.ndarray) -> float:
        """
        Returns 0.0–1.0.
          >= 0.70 -> live person (eyes moving and/or blinking)
          <= 0.35 -> suspicious
          0.5     -> neutral
        """
        if not self._ready or self._mesh is None:
            return 0.5

        try:
            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            result = self._mesh.process(rgb)
        except Exception:
            return 0.5

        if not result.multi_face_landmarks:
            return 0.5

        lm = result.multi_face_landmarks[0].landmark
        self._frames_watched += 1

        iris_x, iris_y = self._iris_position(lm)
        if iris_x is not None:
            self._iris_x_hist.append(iris_x)
            self._iris_y_hist.append(iris_y)

        ear = self._ear(lm)
        is_blinking = ear < _EAR_BLINK_THRESH
        if is_blinking and not self._was_blinking:
            self._blink_count += 1
            self._was_blinking = True
        elif not is_blinking:
            self._was_blinking = False

        if len(self._iris_x_hist) < 15:
            return 0.5

        std_x = float(np.std(self._iris_x_hist))
        std_y = float(np.std(self._iris_y_hist))
        total_std = np.sqrt(std_x**2 + std_y**2)

        if total_std < _SPOOF_STD_MAX:
            gaze_score = 0.2
        elif total_std > _MIN_STD_LIVE:
            gaze_score = 0.95
        else:
            gaze_score = 0.5 + 0.45 * ((total_std - _SPOOF_STD_MAX) / (_MIN_STD_LIVE - _SPOOF_STD_MAX))

        blink_bonus = 0.0
        if self._blink_count > 0:
            blink_bonus = 0.15

        return float(np.clip(gaze_score + blink_bonus, 0.0, 1.0))

    def _iris_position(self, landmarks) -> tuple[float | None, float | None]:
        try:
            l_iris = np.mean([[landmarks[i].x, landmarks[i].y] for i in _LEFT_IRIS], axis=0)
            r_iris = np.mean([[landmarks[i].x, landmarks[i].y] for i in _RIGHT_IRIS], axis=0)
            
            l_corner = np.array([landmarks[_L_EAR_H[0]].x, landmarks[_L_EAR_H[0]].y])
            r_corner = np.array([landmarks[_L_EAR_H[1]].x, landmarks[_L_EAR_H[1]].y])
            eye_w = np.linalg.norm(l_corner - r_corner) + 1e-8
            
            offset = l_iris - l_corner
            return float(offset[0] / eye_w), float(offset[1] / eye_w)
        except Exception:
            return None, None

    def _ear(self, landmarks) -> float:
        try:
            def get_dist(p1, p2):
                return np.sqrt((landmarks[p1].x - landmarks[p2].x)**2 + (landmarks[p1].y - landmarks[p2].y)**2)
            
            l_v1 = get_dist(_L_EAR_V[0][0], _L_EAR_V[0][1])
            l_v2 = get_dist(_L_EAR_V[1][0], _L_EAR_V[1][1])
            l_h = get_dist(_L_EAR_H[0], _L_EAR_H[1])
            l_ear = (l_v1 + l_v2) / (2.0 * l_h + 1e-8)

            r_v1 = get_dist(_R_EAR_V[0][0], _R_EAR_V[0][1])
            r_v2 = get_dist(_R_EAR_V[1][0], _R_EAR_V[1][1])
            r_h = get_dist(_R_EAR_H[0], _R_EAR_H[1])
            r_ear = (r_v1 + r_v2) / (2.0 * r_h + 1e-8)

            return float((l_ear + r_ear) / 2.0)
        except Exception:
            return 0.3
