import pytest
import numpy as np
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from facerecog_engine.config import SecurityConfig
from facerecog_engine.exceptions import ModelLoadError

# Import classes from facerecog_engine.core.detector
from facerecog_engine.core.detector import FaceBoxKalman, FaceDetector, FaceDetection

@pytest.fixture
def mock_model_dir(tmp_path):
    d = tmp_path / "models"
    d.mkdir()
    return str(d)

@pytest.fixture
def base_config(mock_model_dir):
    return SecurityConfig(
        model_dir=mock_model_dir,
        recognition_threshold=0.75,
        liveness_threshold=0.70,
        consensus_threshold=3,
        min_face_quality=0.40
    )


def test_face_box_kalman_predicts_constant_velocity_motion():
    tracker = FaceBoxKalman(process_std=10.0, measurement_std=4.0)

    # Initial frame
    tracker.update((20.0, 100.0, 220.0, 400.0), timestamp=10.0)
    # Moving frame
    tracker.update((70.0, 100.0, 270.0, 400.0), timestamp=11.0)
    # Predict next state
    predicted = tracker.predict(timestamp=12.0)

    assert predicted is not None
    x1, y1, x2, y2 = predicted
    assert x1 > 75.0
    assert y1 == pytest.approx(100.0, abs=8.0)
    assert x2 - x1 == pytest.approx(200.0, abs=12.0)


def test_face_box_kalman_reset():
    tracker = FaceBoxKalman()
    tracker.update((10, 10, 50, 50), timestamp=1.0)
    assert tracker.ready is True

    tracker.reset()
    assert tracker.ready is False
    assert tracker.predict(2.0) is None


@patch("facerecog_engine.core.detector.INSIGHTFACE_AVAILABLE", True)
@patch("facerecog_engine.core.detector.FaceAnalysis")
def test_detector_initialization(mock_face_analysis, base_config):
    # Test that config is processed correctly
    detector = FaceDetector(base_config)
    assert detector.config == base_config
    assert detector.det_size == (320, 320)
    mock_face_analysis.assert_called_once_with(
        name="buffalo_l",
        root=base_config.model_dir,
        providers=["CPUExecutionProvider"],
        allowed_modules=["detection", "recognition"],
    )


@patch("facerecog_engine.core.detector.INSIGHTFACE_AVAILABLE", True)
@patch("facerecog_engine.core.detector.FaceAnalysis")
def test_detector_size_update(mock_face_analysis, base_config):
    detector = FaceDetector(base_config)
    detector.set_detector_size(640, 480)
    assert detector.det_size == (640, 480)
    # The prepare method is called during init and then again for size update
    assert detector._app.prepare.call_count == 2


@patch("facerecog_engine.core.detector.INSIGHTFACE_AVAILABLE", True)
@patch("facerecog_engine.core.detector.FaceAnalysis")
def test_detect_faces(mock_face_analysis, base_config):
    detector = FaceDetector(base_config)
    
    # Mock FaceAnalysis get return value
    mock_face = SimpleNamespace(
        bbox=np.array([10.0, 20.0, 110.0, 120.0]),
        kps=np.array([[15.0, 25.0], [25.0, 25.0], [20.0, 30.0], [15.0, 35.0], [25.0, 35.0]]),
        det_score=0.92
    )
    detector._app.get.return_value = [mock_face]

    frame = np.zeros((240, 320, 3), dtype=np.uint8)
    detections = detector.detect_faces(frame)

    assert len(detections) == 1
    det = detections[0]
    assert det.bbox == (10.0, 20.0, 110.0, 120.0)
    assert det.confidence == 0.92
    assert det.landmarks is not None
    assert np.allclose(det.landmarks[0], [15.0, 25.0])


@patch("facerecog_engine.core.detector.INSIGHTFACE_AVAILABLE", True)
@patch("facerecog_engine.core.detector.FaceAnalysis")
def test_track_and_stabilize_target(mock_face_analysis, base_config):
    detector = FaceDetector(base_config)
    
    # Initialize target tracking with an initial bbox
    detector.kalman.update((10.0, 10.0, 110.0, 110.0), timestamp=10.0)

    detections = [
        FaceDetection(bbox=(12.0, 12.0, 112.0, 112.0), landmarks=None, confidence=0.90),
        FaceDetection(bbox=(200.0, 200.0, 300.0, 300.0), landmarks=None, confidence=0.95),  # Stranger
    ]

    matched_det, stabilized_bbox, reason, sticky_iou, predicted_iou = detector.track_and_stabilize_target(
        detections=detections,
        last_target_bbox=(10.0, 10.0, 110.0, 110.0),
        last_seen_timestamp=10.0,
        current_timestamp=10.1
    )

    assert matched_det is not None
    assert matched_det.bbox == (12.0, 12.0, 112.0, 112.0)
    assert reason == "sticky_iou"
    assert sticky_iou > 0.8
    assert stabilized_bbox is not None
    # Check that stabilized box is close but smoothed
    assert stabilized_bbox[0] != 12.0 or stabilized_bbox[1] != 12.0
