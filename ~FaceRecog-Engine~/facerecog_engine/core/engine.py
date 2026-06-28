# engine.py — FaceRecog security and liveness engine coordinator
import time
import logging
import numpy as np
import cv2
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any

from facerecog_engine.config import SecurityConfig
from facerecog_engine.exceptions import CameraError, ModelLoadError
from facerecog_engine.core.detector import FaceDetector, BBoxKalmanFilter
from facerecog_engine.core.recognizer import FaceRecognizer
from facerecog_engine.liveness_detector import LivenessDetector
from facerecog_engine.virtual_camera_detector import is_virtual_camera
from facerecog_engine.face_quality import measure_face_quality
from facerecog_engine.utils.image import enhance_low_light

logger = logging.getLogger("FaceRecog.Engine")


@dataclass
class VerificationResult:
    face_count: int
    primary_user_present: bool
    recognition_score: float
    liveness_score: float
    liveness_passed: bool
    virtual_camera_detected: bool
    camera_obstructed: bool
    inference_ms: float
    matched_user_id: Optional[str] = None
    frame_quality: float = 0.0


class FaceSecurityEngine:
    """The unified orchestrator for camera feed reading, face quality, recognition and liveness."""

    def __init__(self, config: SecurityConfig, camera_idx: int = 0):
        self.config = config
        self.camera_idx = camera_idx
        
        self._detector = FaceDetector(
            model_dir=config.model_dir,
            onnx_providers=config.onnx_providers
        )
        
        self._recognizer = FaceRecognizer(
            model_dir=config.model_dir,
            onnx_providers=config.onnx_providers,
            face_analysis_app=self._detector._app
        )
        
        self._liveness = LivenessDetector(
            model_dir=config.model_dir,
            onnx_providers=config.onnx_providers
        )
        
        self._kalman = BBoxKalmanFilter()
        self._reference_templates: Dict[str, List[np.ndarray]] = {}
        self._cap: Optional[cv2.VideoCapture] = None
        self._clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))

        # Temporal consensus state
        self._consecutive_matches = 0
        self._consecutive_liveness = 0

    def set_reference_templates(self, templates: Dict[str, List[np.ndarray]]) -> None:
        """Register the reference/enrolled user templates in memory."""
        self._reference_templates = templates

    def reset_session(self) -> None:
        """Reset historical and tracking states."""
        self._liveness.reset_session()
        self._kalman.reset()
        self._consecutive_matches = 0
        self._consecutive_liveness = 0

    def shutdown(self) -> None:
        """Close camera and release ONNX sessions."""
        if self._cap is not None:
            self._cap.release()
            self._cap = None
        self._liveness.close()
        logger.info("FaceSecurityEngine shut down successfully.")

    def process_frame(self, frame: Optional[np.ndarray] = None, *, liveness_mode: str = "full") -> VerificationResult:
        """
        Process a single frame. If frame is None, captures a frame from the initialized webcam.
        """
        t_start = time.perf_counter()

        # 1. Virtual Camera check
        if is_virtual_camera(self.camera_idx):
            self.reset_session()
            return VerificationResult(
                face_count=0, primary_user_present=False,
                recognition_score=0.0, liveness_score=0.0,
                liveness_passed=False, virtual_camera_detected=True,
                camera_obstructed=False,
                inference_ms=(time.perf_counter() - t_start) * 1000,
            )

        # 2. Frame retrieval
        if frame is None:
            frame = self._read_frame()
            
        if frame is None:
            raise CameraError("Failed to retrieve frame from camera.")

        # 3. Obstruction check
        if self._is_obstructed(frame):
            self.reset_session()
            return VerificationResult(
                face_count=0, primary_user_present=False,
                recognition_score=0.0, liveness_score=0.0,
                liveness_passed=False, virtual_camera_detected=False,
                camera_obstructed=True,
                inference_ms=(time.perf_counter() - t_start) * 1000,
            )

        # 4. Low-light contrast enhancement
        enhanced = enhance_low_light(frame, self._clahe)

        # 5. Face detection
        faces = self._detector.detect(enhanced)
        if not faces:
            self.reset_session()
            return VerificationResult(
                face_count=0, primary_user_present=False,
                recognition_score=0.0, liveness_score=0.0,
                liveness_passed=False, virtual_camera_detected=False,
                camera_obstructed=False,
                inference_ms=(time.perf_counter() - t_start) * 1000,
            )

        # 6. Select primary face
        primary_face = self._select_primary_face(enhanced, faces)
        if primary_face is None:
            self.reset_session()
            return VerificationResult(
                face_count=0, primary_user_present=False,
                recognition_score=0.0, liveness_score=0.0,
                liveness_passed=False, virtual_camera_detected=False,
                camera_obstructed=False,
                inference_ms=(time.perf_counter() - t_start) * 1000,
            )

        # 7. Check quality threshold
        quality = measure_face_quality(enhanced, primary_face)
        if quality.score < self.config.min_face_quality:
            return VerificationResult(
                face_count=1, primary_user_present=False,
                recognition_score=0.0, liveness_score=0.0,
                liveness_passed=False, virtual_camera_detected=False,
                camera_obstructed=False,
                inference_ms=(time.perf_counter() - t_start) * 1000,
                frame_quality=quality.score
            )

        # 8. Update Kalman filter
        self._kalman.update(primary_face.bbox, time.monotonic())

        # 9. Liveness check
        if liveness_mode == "full":
            liveness_score = self._liveness.score_full(enhanced, primary_face)
        else:
            liveness_score = self._liveness.score_fast(enhanced, primary_face)
            
        liveness_passed = liveness_score >= self.config.liveness_threshold

        # 10. Recognition check
        recognition_score = 0.0
        primary_user_present = False
        matched_user_id = None
        
        try:
            embedding = self._recognizer.get_embedding(enhanced, primary_face)
            if self._reference_templates:
                matched_user_id, recognition_score = self._recognizer.match_face(
                    embedding, self._reference_templates
                )
                if recognition_score >= self.config.recognition_threshold:
                    primary_user_present = True
        except Exception as e:
            logger.debug("Recognition extraction failed: %s", e)

        # 11. Temporal consensus check
        if primary_user_present:
            self._consecutive_matches += 1
        else:
            self._consecutive_matches = 0

        if liveness_passed:
            self._consecutive_liveness += 1
        else:
            self._consecutive_liveness = 0

        consensus_passed = (
            self._consecutive_matches >= self.config.consensus_threshold and
            self._consecutive_liveness >= self.config.consensus_threshold
        )

        return VerificationResult(
            face_count=1,
            primary_user_present=primary_user_present and consensus_passed,
            recognition_score=recognition_score,
            liveness_score=liveness_score,
            liveness_passed=liveness_passed,
            virtual_camera_detected=False,
            camera_obstructed=False,
            inference_ms=(time.perf_counter() - t_start) * 1000,
            matched_user_id=matched_user_id if consensus_passed else None,
            frame_quality=quality.score
        )

    def _read_frame(self) -> Optional[np.ndarray]:
        if self._cap is None:
            self._cap = cv2.VideoCapture(self.camera_idx)
            if not self._cap.isOpened():
                raise CameraError(f"Could not open camera device at index {self.camera_idx}")
        ret, frame = self._cap.read()
        return frame if ret else None

    @staticmethod
    def _is_obstructed(frame: np.ndarray) -> bool:
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        return float(gray.mean()) < 8.0

    def _select_primary_face(self, frame: np.ndarray, faces: List[Any]) -> Optional[Any]:
        if not faces:
            return None
            
        # Select by highest candidate score (closest to center and largest)
        selected = max(faces, key=lambda face: self._primary_face_candidate_score(frame, face))
        if self._primary_face_candidate_score(frame, selected) >= 0.0:
            return selected
        return None

    @staticmethod
    def _primary_face_candidate_score(frame: np.ndarray, face: Any) -> float:
        try:
            x1, y1, x2, y2 = [float(v) for v in face.bbox]
        except Exception:
            return -1.0

        h, w = frame.shape[:2]
        frame_area = max(1, h * w)
        frame_center_x = w / 2.0
        frame_center_y = h / 2.0

        box_w = max(0.0, x2 - x1)
        box_h = max(0.0, y2 - y1)
        if box_w <= 0.0 or box_h <= 0.0:
            return -1.0

        area_score = min(1.0, ((box_w * box_h) / frame_area) / 0.35)
        face_center_x = (x1 + x2) / 2.0
        face_center_y = (y1 + y2) / 2.0
        dist_x = abs(face_center_x - frame_center_x) / max(1.0, frame_center_x)
        dist_y = abs(face_center_y - frame_center_y) / max(1.0, frame_center_y)
        center_score = max(0.0, 1.0 - ((dist_x + dist_y) / 2.0))
        
        contains_center = x1 <= frame_center_x <= x2 and y1 <= frame_center_y <= y2
        center_bonus = 0.15 if contains_center else 0.0
        det_score = float(getattr(face, "det_score", 0.75))

        return (
            det_score * 0.45 +
            area_score * 0.30 +
            center_score * 0.20 +
            center_bonus
        )
