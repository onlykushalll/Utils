import cv2
import numpy as np
from typing import Tuple

def compute_sharpness(roi: np.ndarray) -> float:
    """Calculate the Laplacian variance of the face ROI."""
    if roi.size == 0 or roi.shape[0] == 0 or roi.shape[1] == 0:
        return 0.0
    gray = cv2.cvtColor(cv2.resize(roi, (64, 64)), cv2.COLOR_BGR2GRAY)
    return float(cv2.Laplacian(gray, cv2.CV_64F).var())

def compute_illumination(roi: np.ndarray) -> float:
    """Calculate average lightness Y channel in YCrCb color space."""
    if roi.size == 0 or roi.shape[0] == 0 or roi.shape[1] == 0:
        return 0.0
    ycrcb = cv2.cvtColor(roi, cv2.COLOR_BGR2YCrCb)
    return float(np.mean(ycrcb[:, :, 0]))

def compute_face_size_ratio(bbox: Tuple[float, float, float, float], frame_shape: Tuple[int, int]) -> float:
    """Calculate face bounding box area relative to image frame area."""
    h, w = frame_shape[:2]
    x1, y1, x2, y2 = bbox
    face_area = max(0.0, x2 - x1) * max(0.0, y2 - y1)
    frame_area = h * w
    return float(face_area / (frame_area + 1e-8))

def compute_face_centering(bbox: Tuple[float, float, float, float], frame_shape: Tuple[int, int]) -> float:
    """
    Calculate bounding box center alignment.
    Returns 1.0 (perfectly centered) to 0.0 (maximum off-center).
    """
    h, w = frame_shape[:2]
    x1, y1, x2, y2 = bbox
    
    face_cx = (x1 + x2) / 2.0
    face_cy = (y1 + y2) / 2.0
    frame_cx = w / 2.0
    frame_cy = h / 2.0
    
    dx = (face_cx - frame_cx) / (w / 2.0 + 1e-8)
    dy = (face_cy - frame_cy) / (h / 2.0 + 1e-8)
    distance = np.sqrt(dx**2 + dy**2)
    return float(np.clip(1.0 - distance, 0.0, 1.0))

def evaluate_quality_score(roi: np.ndarray, bbox: Tuple[float, float, float, float], frame_shape: Tuple[int, int], det_score: float) -> Tuple[float, dict]:
    """
    Evaluate and combine face metrics into a quality score matching face_engine.py.
    """
    sharpness = compute_sharpness(roi)
    sharp_score = float(np.clip(sharpness / 400.0, 0.0, 1.0))
    
    mean_y = compute_illumination(roi)
    illum_score = float(np.clip(1.0 - abs(mean_y - 128.0) / 128.0, 0.0, 1.0))
    
    size_ratio = compute_face_size_ratio(bbox, frame_shape)
    h, w = frame_shape[:2]
    frame_area = h * w
    face_area = size_ratio * frame_area
    size_score = float(np.clip(face_area / ((frame_area + 1) * 0.15), 0.0, 1.0))
    
    centering = compute_face_centering(bbox, frame_shape)
    
    # Combined score formula matching original face_engine.py
    overall_quality = float(
        det_score * 0.40 +
        sharp_score * 0.30 +
        illum_score * 0.20 +
        size_score * 0.10
    )
    
    metrics = {
        "sharpness": sharpness,
        "sharp_score": sharp_score,
        "mean_y": mean_y,
        "illum_score": illum_score,
        "size_ratio": size_ratio,
        "size_score": size_score,
        "centering_score": centering,
        "overall_quality": overall_quality
    }
    return overall_quality, metrics
