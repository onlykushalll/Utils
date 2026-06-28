import pytest
import numpy as np
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
    generate_rppg_sequence,
    generate_specular_moire_frame,
    generate_gaze_frame
)

# ==========================================
# FEATURE 1: INIT & CONFIG (T1.F1.1 - T1.F1.5)
# ==========================================

def test_t1_f1_1_default_config(mock_model_dir):
    """T1.F1.1: Default config initialisation"""
    config = SecurityConfig(model_dir=mock_model_dir)
    assert config.model_dir == mock_model_dir
    assert config.recognition_threshold == 0.75
    assert config.liveness_threshold == 0.70
    assert config.consensus_threshold == 3
    assert config.min_face_quality == 0.40
    assert config.onnx_providers is None

def test_t1_f1_2_custom_config(mock_model_dir):
    """T1.F1.2: Config threshold limits"""
    config = SecurityConfig(
        model_dir=mock_model_dir,
        recognition_threshold=0.80,
        liveness_threshold=0.75,
        consensus_threshold=5,
        min_face_quality=0.50
    )
    assert config.recognition_threshold == 0.80
    assert config.liveness_threshold == 0.75
    assert config.consensus_threshold == 5
    assert config.min_face_quality == 0.50

def test_t1_f1_3_providers_parsing(mock_model_dir):
    """T1.F1.3: Providers list parsing"""
    config = SecurityConfig(
        model_dir=mock_model_dir,
        onnx_providers=["CPUExecutionProvider"]
    )
    assert config.onnx_providers == ["CPUExecutionProvider"]

def test_t1_f1_4_empty_template_registration(base_config):
    """T1.F1.4: Empty template registration"""
    engine = FaceSecurityEngine(base_config)
    engine.load_enrolled_templates([])
    assert len(engine.templates) == 0

def test_t1_f1_5_engine_instance_creation(base_config):
    """T1.F1.5: Engine instance creation"""
    engine = FaceSecurityEngine(base_config)
    assert isinstance(engine, FaceSecurityEngine)

# ==========================================
# FEATURE 2: DETECTION & QUALITY (T1.F2.1 - T1.F2.5)
# ==========================================

def test_t1_f2_1_single_valid_face(base_config):
    """T1.F2.1: Single valid face detection"""
    engine = FaceSecurityEngine(base_config)
    frame = generate_base_frame()
    result = engine.process_frame(frame)
    assert result.face_detected is True
    assert result.quality_score >= base_config.min_face_quality

def test_t1_f2_2_empty_frame(base_config):
    """T1.F2.2: Empty frame processing"""
    engine = FaceSecurityEngine(base_config)
    frame = np.zeros((480, 640, 3), dtype=np.uint8)
    result = engine.process_frame(frame)
    assert result.face_detected is False
    assert result.recognition_score == 0.0
    assert result.liveness_score == 0.0

def test_t1_f2_3_sharpness_evaluation(base_config):
    """T1.F2.3: Sharpness evaluation"""
    engine = FaceSecurityEngine(base_config)
    frame = generate_base_frame()
    setattr(frame, 'quality_score', 0.90)
    result = engine.process_frame(frame)
    assert result.quality_score > 0.80

def test_t1_f2_4_size_evaluation(base_config):
    """T1.F2.4: Size evaluation"""
    engine = FaceSecurityEngine(base_config)
    frame = generate_base_frame()
    setattr(frame, 'quality_score', 0.85)
    setattr(frame, 'face_size_score', 0.80)
    result = engine.process_frame(frame)
    assert result.quality_score >= base_config.min_face_quality

def test_t1_f2_5_illumination_check(base_config):
    """T1.F2.5: Illumination check"""
    engine = FaceSecurityEngine(base_config)
    frame = generate_illuminated_frame(brightness=128)
    result = engine.process_frame(frame)
    assert result.quality_score >= base_config.min_face_quality
    assert result.camera_obstructed is False

# ==========================================
# FEATURE 3: FACE RECOGNITION (T1.F3.1 - T1.F3.5)
# ==========================================

def test_t1_f3_1_perfect_embedding_match(base_config):
    """T1.F3.1: Perfect embedding match"""
    template, matching_query, _ = get_mock_embeddings()
    engine = FaceSecurityEngine(base_config)
    engine.load_enrolled_templates([template])
    
    frame = generate_frame_with_embedding(template)
    result = engine.process_frame(frame)
    assert result.recognition_score == pytest.approx(1.0, abs=1e-5)

def test_t1_f3_2_stranger_mismatch(base_config):
    """T1.F3.2: Stranger mismatch"""
    template, _, stranger_query = get_mock_embeddings()
    engine = FaceSecurityEngine(base_config)
    engine.load_enrolled_templates([template])
    
    frame = generate_frame_with_embedding(stranger_query)
    result = engine.process_frame(frame)
    assert result.recognition_score < base_config.recognition_threshold

def test_t1_f3_3_multi_template_match(base_config):
    """T1.F3.3: Multi-template match"""
    template, matching_query, _ = get_mock_embeddings()
    templates = [np.random.randn(512), np.random.randn(512), template, np.random.randn(512), np.random.randn(512)]
    templates = [t / np.linalg.norm(t) for t in templates]
    
    engine = FaceSecurityEngine(base_config)
    engine.load_enrolled_templates(templates)
    
    frame = generate_frame_with_embedding(matching_query)
    result = engine.process_frame(frame)
    assert result.recognition_score == pytest.approx(0.90, abs=1e-5)

def test_t1_f3_4_consensus_build_up(base_config):
    """T1.F3.4: Consensus build up"""
    template, matching_query, _ = get_mock_embeddings()
    engine = FaceSecurityEngine(base_config)
    engine.load_enrolled_templates([template])
    
    for i in range(2):
        frame = generate_frame_with_embedding(matching_query)
        frame[0, 0, 0] = i
        result = engine.process_frame(frame)
        assert result.primary_user_present is False

def test_t1_f3_5_consensus_confirmation(base_config):
    """T1.F3.5: Consensus confirmation"""
    template, matching_query, _ = get_mock_embeddings()
    engine = FaceSecurityEngine(base_config)
    engine.load_enrolled_templates([template])
    
    for i in range(3):
        frame = generate_frame_with_embedding(matching_query)
        frame[0, 0, 0] = i
        result = engine.process_frame(frame)
        if i == 2:
            assert result.primary_user_present is True
        else:
            assert result.primary_user_present is False

# ==========================================
# FEATURE 4: LIVENESS DETECTION (T1.F4.1 - T1.F4.5)
# ==========================================

def test_t1_f4_1_real_face_sequence(base_config):
    """T1.F4.1: Real face sequence"""
    engine = FaceSecurityEngine(base_config)
    
    for i in range(5):
        frame = generate_base_frame()
        frame[0, 0, 0] = i
        setattr(frame, 'liveness_score', 0.90)
        result = engine.process_frame(frame)
    assert result.liveness_score >= base_config.liveness_threshold
    assert result.liveness_passed is True

def test_t1_f4_2_print_photo_spoof(base_config):
    """T1.F4.2: Print photo spoof"""
    engine = FaceSecurityEngine(base_config)
    frame = generate_specular_moire_frame(is_moire=True)
    result = engine.process_frame(frame)
    assert result.liveness_passed is False
    assert result.liveness_score < base_config.liveness_threshold

def test_t1_f4_3_screen_replay_spoof(base_config):
    """T1.F4.3: Screen replay spoof"""
    engine = FaceSecurityEngine(base_config)
    frame = generate_specular_moire_frame(is_moire=False, is_specular=True)
    result = engine.process_frame(frame)
    assert result.liveness_passed is False
    assert result.liveness_score < base_config.liveness_threshold

def test_t1_f4_4_early_smoothing_gate(base_config):
    """T1.F4.4: Early smoothing gate"""
    engine = FaceSecurityEngine(base_config)
    frame = generate_base_frame()
    setattr(frame, 'liveness_score', 0.90)
    result = engine.process_frame(frame)
    assert result.liveness_score == pytest.approx(0.75, abs=1e-5)

def test_t1_f4_5_liveness_window_minimum(base_config):
    """T1.F4.5: Liveness window minimum"""
    engine = FaceSecurityEngine(base_config)
    for i in range(10):
        frame = generate_base_frame()
        frame[0, 0, 0] = i
        score = 0.10 if i == 5 else 0.90
        setattr(frame, 'liveness_score', score)
        result = engine.process_frame(frame)
    assert result.liveness_score == pytest.approx(0.10, abs=1e-5)

# ==========================================
# FEATURE 5: GAZE & ATTENTION (T1.F5.1 - T1.F5.5)
# ==========================================

def test_t1_f5_1_direct_eye_attention(base_config):
    """T1.F5.1: Direct eye attention"""
    engine = FaceSecurityEngine(base_config)
    frame = generate_gaze_frame(eye_closed=False, iris_offset=0.0)
    result = engine.process_frame(frame)
    assert result.gaze_score > 0.85

def test_t1_f5_2_gaze_deviation(base_config):
    """T1.F5.2: Gaze deviation"""
    engine = FaceSecurityEngine(base_config)
    frame = generate_gaze_frame(eye_closed=False, iris_offset=0.35)
    result = engine.process_frame(frame)
    assert result.gaze_score < 0.30

def test_t1_f5_3_normal_blink_detection(base_config):
    """T1.F5.3: Normal blink detection"""
    engine = FaceSecurityEngine(base_config)
    frame = generate_gaze_frame(eye_closed=True)
    result = engine.process_frame(frame)
    assert result.gaze_score == pytest.approx(0.50, abs=1e-5)

def test_t1_f5_4_closed_eye_gaze_bypass(base_config):
    """T1.F5.4: Closed eye gaze bypass"""
    engine = FaceSecurityEngine(base_config)
    frame = generate_gaze_frame(eye_closed=True)
    result = engine.process_frame(frame)
    assert result.gaze_score == 0.50

def test_t1_f5_5_clean_attention_close(base_config):
    """T1.F5.5: Clean attention close"""
    engine = FaceSecurityEngine(base_config)
    engine.close()
    with pytest.raises(RuntimeError):
        engine.process_frame(generate_base_frame())
