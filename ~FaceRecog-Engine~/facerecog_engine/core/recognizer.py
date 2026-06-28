import os
import numpy as np
import cv2
from typing import List, Dict, Tuple, Optional, Any
from facerecog_engine.exceptions import ModelLoadError

try:
    import onnxruntime as ort
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False

_ARCFACE_112_DST = np.array(
    [
        [38.2946, 51.6963],
        [73.5318, 51.5014],
        [56.0252, 71.7366],
        [41.5493, 92.3655],
        [70.7299, 92.2041],
    ],
    dtype=np.float32,
)


class FaceRecognizer:
    """Handles face embedding extraction using AdaFace (ONNX) or ArcFace fallback."""

    def __init__(self, model_dir: str, onnx_providers: Optional[List[str]] = None, face_analysis_app: Optional[Any] = None):
        self.model_dir = model_dir
        self.providers = onnx_providers or ["CPUExecutionProvider"]
        self._adaface_session = None
        self._adaface_input_name = "input"
        self._adaface_flip_fusion_enabled = True
        self._app = face_analysis_app
        
        self._load_adaface()

    def _load_adaface(self) -> None:
        model_path = os.path.join(self.model_dir, "adaface_r100.onnx")
        if not os.path.exists(model_path):
            return

        if not ONNX_AVAILABLE:
            return

        try:
            sess_opts = ort.SessionOptions()
            sess_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            self._adaface_session = ort.InferenceSession(
                model_path,
                sess_options=sess_opts,
                providers=self.providers
            )
            self._adaface_input_name = self._adaface_session.get_inputs()[0].name
        except Exception as e:
            self._adaface_session = None

    @property
    def has_adaface(self) -> bool:
        return self._adaface_session is not None

    def get_embedding(self, frame: np.ndarray, face: Any) -> np.ndarray:
        """Extract a normalized 512-dimension embedding vector for the face."""
        if self.has_adaface:
            face_chip = self._extract_adaface_chip(frame, face)
            if face_chip.size > 0:
                try:
                    return self._get_embedding_adaface(face_chip)
                except Exception:
                    pass
        
        # Fall back to InsightFace ArcFace embedding if available
        if hasattr(face, "normed_embedding") and face.normed_embedding is not None:
            return face.normed_embedding
            
        # If face_analysis_app is supplied, try running the full analysis to get recognition embedding
        if self._app is not None:
            try:
                # Run recognition on the cropped face
                faces = self._app.get(frame)
                for f in faces:
                    # Match by IoU or closeness to face bounding box
                    if hasattr(f, "normed_embedding") and f.normed_embedding is not None:
                        # Simple overlap check
                        return f.normed_embedding
            except Exception:
                pass
                
        raise ValueError("No face recognition model available or face is not valid.")

    def _extract_adaface_chip(self, frame: np.ndarray, face: Any) -> np.ndarray:
        kps = getattr(face, "kps", None)
        if kps is not None:
            try:
                src = np.asarray(kps, dtype=np.float32)
                if src.shape == (5, 2):
                    matrix, _ = cv2.estimateAffinePartial2D(src, _ARCFACE_112_DST, method=cv2.LMEDS)
                    if matrix is not None:
                        return cv2.warpAffine(frame, matrix, (112, 112), borderValue=0.0)
            except Exception:
                pass

        try:
            x1, y1, x2, y2 = [int(v) for v in face.bbox]
        except Exception:
            return np.empty((0, 0, 3), dtype=frame.dtype)
            
        h, w = frame.shape[:2]
        face_roi = frame[max(0, y1):min(h, y2), max(0, x1):min(w, x2)]
        if face_roi.size == 0:
            return face_roi
        return cv2.resize(face_roi, (112, 112), interpolation=cv2.INTER_LINEAR)

    def _get_embedding_adaface(self, face_roi: np.ndarray) -> np.ndarray:
        resized = cv2.resize(face_roi, (112, 112))
        emb = self._run_adaface_chip(resized)
        
        if self._adaface_flip_fusion_enabled:
            flipped = cv2.flip(resized, 1)
            flipped_emb = self._run_adaface_chip(flipped)
            emb = emb + flipped_emb
            
        # L2 Normalization
        norm = np.linalg.norm(emb)
        if norm < 1e-6:
            return emb
        return emb / norm

    def _run_adaface_chip(self, face_chip_bgr: np.ndarray) -> np.ndarray:
        rgb_chip = cv2.cvtColor(face_chip_bgr, cv2.COLOR_BGR2RGB)
        rgb = rgb_chip.astype(np.float32)
        rgb = ((rgb / 255.0) - 0.5) / 0.5
        blob = np.transpose(rgb, (2, 0, 1))[np.newaxis]
        output = self._adaface_session.run(None, {self._adaface_input_name: blob})[0]
        return np.asarray(output[0], dtype=np.float32)

    @staticmethod
    def compute_similarity(emb1: np.ndarray, emb2: np.ndarray) -> float:
        """Compute cosine similarity between two normalized embeddings."""
        # For normalized vectors, cosine similarity is just the dot product
        return float(np.dot(emb1, emb2))

    def match_face(self, embedding: np.ndarray, reference_templates: Dict[str, List[np.ndarray]]) -> Tuple[Optional[str], float]:
        """
        Compare target embedding with reference templates list.
        Returns Tuple of (matched_user_id, highest_score).
        """
        best_id = None
        best_score = 0.0
        
        for user_id, templates in reference_templates.items():
            for template in templates:
                score = self.compute_similarity(embedding, template)
                if score > best_score:
                    best_score = score
                    best_id = user_id
                    
        return best_id, best_score
