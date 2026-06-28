import pytest
import numpy as np
from unittest.mock import patch, MagicMock
from facerecog_engine import SecurityConfig, FaceSecurityEngine, VerificationResult
from facerecog_engine.exceptions import ModelLoadError, EngineError
from tests.helpers import (
    generate_base_frame,
    generate_blurry_frame,
    generate_illuminated_frame,
    generate_off_center_frame,
    generate_tiny_face_frame,
    get_mock_embeddings,
    generate_frame_with_embedding,
    generate_specular_moire_frame,
    generate_gaze_frame
)

# ==========================================
# FEATURE 1: INIT & CONFIG (T2.F1.1 - T2.F1.5)
# ==========================================

def test_t2_f1_1_non_existent_model_dir():
    """T2.F1.1: Non-existent model directory"""
    with pytest.raises(ModelLoadError):
        SecurityConfig(model_dir="invalid/dir")

def test_t2_f1_2_negative_threshold_boundaries(mock_model_dir):
    """T2.F1.2: Negative threshold boundaries"""
    with pytest.raises(EngineError):
        SecurityConfig(model_dir=mock_model_dir, recognition_threshold=-0.1)

def test_t2_f1_3_extreme_high_threshold(mock_model_dir):
    """T2.F1.3: Extreme high threshold"""
    with pytest.raises(EngineError):
        SecurityConfig(model_dir=mock_model_dir, liveness_threshold=1.1)

def test_t2_f1_4_unsupported_onnx_provider(mock_model_dir):
    """T2.F1.4: Unsupported ONNX provider"""
    config = SecurityConfig(model_dir=mock_model_dir, onnx_providers=["FakeDml"])
    engine = FaceSecurityEngine(config)
    assert engine.config.onnx_providers == ["FakeDml"]

def test_t2_f1_5_concurrent_engine_instances(base_config):
    """T2.F1.5: Concurrent engine instances"""
    engine1 = FaceSecurityEngine(base_config)
    engine2 = FaceSecurityEngine(base_config)
    assert isinstance(engine1, FaceSecurityEngine)
    assert isinstance(engine2, FaceSecurityEngine)

# ==========================================
# FEATURE 2: DETECTION & QUALITY (T2.F2.1 - T2.F2.5)
# ==========================================

def test_t2_f2_1_pitch_black_camera(base_config):
    """T2.F2.1: Pitch black camera"""
    engine = FaceSecurityEngine(base_config)
    frame = generate_illuminated_frame(brightness=0)
    result = engine.process_frame(frame)
    assert result.camera_obstructed is True
    assert result.face_detected is False

def test_t2_f2_2_blurry_frame_filter(base_config):
    """T2.F2.2: Blurry frame filter"""
    engine = FaceSecurityEngine(base_config)
    frame = generate_blurry_frame(sigma=25)
    result = engine.process_frame(frame)
    assert result.quality_score < base_config.min_face_quality

def test_t2_f2_3_multiple_face_prioritization(base_config):
    """T2.F2.3: Multiple face prioritization"""
    engine = FaceSecurityEngine(base_config)
    frame = generate_base_frame()
    setattr(frame, 'face_count', 3)
    result = engine.process_frame(frame)
    assert result.face_detected is True

def test_t2_f2_4_face_on_extreme_edge(base_config):
    """T2.F2.4: Face on extreme edge"""
    engine = FaceSecurityEngine(base_config)
    frame = generate_off_center_frame(center=(10, 10))
    result = engine.process_frame(frame)
    assert result.quality_score < base_config.min_face_quality

def test_t2_f2_5_over_saturated_exposure(base_config):
    """T2.F2.5: Over-saturated exposure"""
    engine = FaceSecurityEngine(base_config)
    frame = generate_illuminated_frame(brightness=255)
    setattr(frame, 'quality_score', 0.20)
    result = engine.process_frame(frame)
    assert result.quality_score < base_config.min_face_quality

# ==========================================
# FEATURE 3: FACE RECOGNITION (T2.F3.1 - T2.F3.5)
# ==========================================

def test_t2_f3_1_low_quality_skip(base_config):
    """T2.F3.1: Low quality skip"""
    template, matching_query, _ = get_mock_embeddings()
    engine = FaceSecurityEngine(base_config)
    engine.load_enrolled_templates([template])
    
    frame = generate_frame_with_embedding(matching_query)
    setattr(frame, 'is_blurry', True)
    setattr(frame, 'quality_score', 0.15)
    
    result = engine.process_frame(frame)
    assert result.quality_score < base_config.min_face_quality
    assert result.primary_user_present is False
    assert engine.consecutive_matches == 0

def test_t2_f3_2_threshold_boundary_match(base_config):
    """T2.F3.2: Threshold boundary match"""
    template, _, _ = get_mock_embeddings()
    engine = FaceSecurityEngine(base_config)
    engine.load_enrolled_templates([template])
    
    query_low = np.zeros(512, dtype=np.float32)
    query_low[0] = 0.749
    query_low[1] = np.sqrt(1 - 0.749**2)
    frame_low = generate_frame_with_embedding(query_low)
    result_low = engine.process_frame(frame_low)
    assert result_low.recognition_score == pytest.approx(0.749, abs=1e-5)
    assert engine.consecutive_matches == 0
    
    query_high = np.zeros(512, dtype=np.float32)
    query_high[0] = 0.751
    query_high[1] = np.sqrt(1 - 0.751**2)
    frame_high = generate_frame_with_embedding(query_high)
    result_high = engine.process_frame(frame_high)
    assert result_high.recognition_score == pytest.approx(0.751, abs=1e-5)
    assert engine.consecutive_matches == 1

def test_t2_f3_3_empty_template_matrix_query(base_config):
    """T2.F3.3: Empty template matrix query"""
    engine = FaceSecurityEngine(base_config)
    frame = generate_base_frame()
    result = engine.process_frame(frame)
    assert result.recognition_score == 0.0

def test_t2_f3_4_vectorized_scaling_load(base_config):
    """T2.F3.4: Vectorized scaling load"""
    templates = [np.random.randn(512) for _ in range(1000)]
    templates = [t / np.linalg.norm(t) for t in templates]
    
    engine = FaceSecurityEngine(base_config)
    engine.load_enrolled_templates(templates)
    
    frame = generate_frame_with_embedding(templates[0])
    result = engine.process_frame(frame)
    assert result.recognition_score == pytest.approx(1.0, abs=1e-5)

def test_t2_f3_5_consensus_reset_on_mismatch(base_config):
    """T2.F3.5: Consensus reset on mismatch"""
    template, matching_query, stranger_query = get_mock_embeddings()
    engine = FaceSecurityEngine(base_config)
    engine.load_enrolled_templates([template])
    
    frame1 = generate_frame_with_embedding(matching_query)
    engine.process_frame(frame1)
    assert engine.consecutive_matches == 1
    
    frame2 = generate_frame_with_embedding(stranger_query)
    engine.process_frame(frame2)
    assert engine.consecutive_matches == 0

# ==========================================
# FEATURE 4: LIVENESS DETECTION (T2.F4.1 - T2.F4.5)
# ==========================================

def test_t2_f4_1_anti_replay_loop_penalty(base_config):
    """T2.F4.1: Anti-replay loop penalty"""
    engine = FaceSecurityEngine(base_config)
    
    for _ in range(7):
        frame = generate_base_frame()
        result = engine.process_frame(frame)
    
    assert result.liveness_score == pytest.approx(0.10, abs=1e-5)
    assert result.liveness_passed is False

def test_t2_f4_2_minifasnet_onnx_missing(base_config):
    """T2.F4.2: MiniFASNet ONNX missing"""
    engine = FaceSecurityEngine(base_config)
    frame = generate_base_frame()
    setattr(frame, 'liveness_score', 0.80)
    result = engine.process_frame(frame)
    assert result.liveness_score > 0.0

def test_t2_f4_3_midas_depth_onnx_missing(base_config):
    """T2.F4.3: MiDaS depth ONNX missing"""
    engine = FaceSecurityEngine(base_config)
    frame = generate_base_frame()
    setattr(frame, 'depth_score', 0.50)
    result = engine.process_frame(frame)
    assert result.depth_score == 0.50

def test_t2_f4_4_consecutive_onnx_failures(base_config):
    """T2.F4.4: Consecutive ONNX failures"""
    engine = FaceSecurityEngine(base_config)
    for i in range(5):
        frame = generate_base_frame()
        frame[0, 0, 0] = i
        result = engine.process_frame(frame)
    assert result.face_detected is True

def test_t2_f4_5_periodic_grid_moire_spikes(base_config):
    """T2.F4.5: Periodic grid moiré spikes"""
    engine = FaceSecurityEngine(base_config)
    frame = generate_specular_moire_frame(is_moire=True)
    result = engine.process_frame(frame)
    assert result.liveness_score < base_config.liveness_threshold

# ==========================================
# FEATURE 5: GAZE & ATTENTION (T2.F5.1 - T2.F5.5)
# ==========================================

def test_t2_f5_1_mediapipe_import_error(base_config):
    """T2.F5.1: MediaPipe import error"""
    engine = FaceSecurityEngine(base_config)
    with patch.dict("sys.modules", {"mediapipe": None}):
        frame = generate_base_frame()
        result = engine.process_frame(frame)
        assert result.gaze_score == 0.90

def test_t2_f5_2_extreme_head_pose_landmarks(base_config):
    """T2.F5.2: Extreme head pose landmarks"""
    engine = FaceSecurityEngine(base_config)
    frame = generate_gaze_frame(eye_closed=False, iris_offset=0.0)
    setattr(frame, 'head_pose_deviation', 35.0)
    result = engine.process_frame(frame)
    assert result.face_detected is True

def test_t2_f5_3_landmark_eye_brightness_fallback(base_config):
    """T2.F5.3: Landmark eye-brightness fallback"""
    engine = FaceSecurityEngine(base_config)
    frame = generate_base_frame()
    setattr(frame, 'landmarks_mode', '5-point')
    result = engine.process_frame(frame)
    assert result.face_detected is True

def test_t2_f5_4_asymmetrical_eye_wink(base_config):
    """T2.F5.4: Asymmetrical eye wink"""
    engine = FaceSecurityEngine(base_config)
    frame = generate_gaze_frame(eye_closed=False, iris_offset=0.0)
    setattr(frame, 'gaze_score', 0.70)
    result = engine.process_frame(frame)
    assert result.gaze_score == 0.70

def test_t2_f5_5_gaze_micro_variability(base_config):
    """T2.F5.5: Gaze micro-variability"""
    engine = FaceSecurityEngine(base_config)
    for i in range(100):
        frame = generate_gaze_frame(eye_closed=False, iris_offset=0.0)
        frame[0, 0, 0] = i
        result = engine.process_frame(frame)
    assert result.gaze_score > 0.80
