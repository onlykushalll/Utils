import pytest
import numpy as np
from facerecog_engine import SecurityConfig, FaceSecurityEngine, VerificationResult
from tests.helpers import (
    generate_base_frame,
    generate_blurry_frame,
    generate_illuminated_frame,
    get_mock_embeddings,
    generate_frame_with_embedding,
    generate_specular_moire_frame,
    generate_gaze_frame
)

def test_t3_1_quality_and_recognition(base_config):
    """
    T3.1 (Quality & Recognition):
    Verify that quality marginally above min_face_quality (0.41) executes recognition and consensus,
    while quality marginally below (0.39) skips recognition and resets consensus.
    """
    template, matching_query, _ = get_mock_embeddings()
    engine = FaceSecurityEngine(base_config)
    engine.load_enrolled_templates([template])

    # 1. Marginally below: 0.39
    frame_low = generate_frame_with_embedding(matching_query)
    setattr(frame_low, 'quality_score', 0.39)
    result_low = engine.process_frame(frame_low)
    assert result_low.quality_score < base_config.min_face_quality
    assert engine.consecutive_matches == 0

    # 2. Marginally above: 0.41 (x3 frames to trigger consensus)
    for i in range(3):
        frame_high = generate_frame_with_embedding(matching_query)
        frame_high[0, 0, 0] = i
        setattr(frame_high, 'quality_score', 0.41)
        result_high = engine.process_frame(frame_high)
        
    assert result_high.quality_score >= base_config.min_face_quality
    assert engine.consecutive_matches == 3
    assert result_high.primary_user_present is True

    # 3. Hit it with low quality again to verify consensus reset
    frame_low_reset = generate_frame_with_embedding(matching_query)
    setattr(frame_low_reset, 'quality_score', 0.39)
    result_reset = engine.process_frame(frame_low_reset)
    assert engine.consecutive_matches == 0
    assert result_reset.primary_user_present is False


def test_t3_2_recognition_and_gaze(base_config):
    """
    T3.2 (Recognition & Gaze):
    User face matches template perfectly, but is looking away (gaze score < 0.3).
    Verify primary_user_present remains False.
    """
    template, matching_query, _ = get_mock_embeddings()
    engine = FaceSecurityEngine(base_config)
    engine.load_enrolled_templates([template])

    for i in range(3):
        frame = generate_frame_with_embedding(matching_query)
        frame[0, 0, 0] = i
        setattr(frame, 'gaze_score', 0.20)
        result = engine.process_frame(frame)
        
    assert result.recognition_score > base_config.recognition_threshold
    assert result.gaze_score < 0.30
    assert result.primary_user_present is False
    assert engine.consecutive_matches == 0


def test_t3_3_liveness_and_recognition(base_config):
    """
    T3.3 (Liveness & Recognition):
    High-fidelity photo spoof matches user template perfectly but fails liveness.
    Verify primary_user_present remains False.
    """
    template, matching_query, _ = get_mock_embeddings()
    engine = FaceSecurityEngine(base_config)
    engine.load_enrolled_templates([template])

    for i in range(3):
        frame = generate_frame_with_embedding(matching_query)
        frame[0, 0, 0] = i
        setattr(frame, 'liveness_score', 0.12)
        result = engine.process_frame(frame)
        
    assert result.recognition_score > base_config.recognition_threshold
    assert result.liveness_passed is False
    assert result.primary_user_present is False
    assert engine.consecutive_matches == 0


def test_t3_4_liveness_and_gaze(base_config):
    """
    T3.4 (Liveness & Gaze):
    Spoof video playback on tablet: user blinks and looks at camera (passes gaze/blink),
    but fails texture/moire checks. Verify liveness_passed is False.
    """
    engine = FaceSecurityEngine(base_config)
    
    frame = generate_specular_moire_frame(is_moire=True)
    setattr(frame, 'eye_closed', True)
    setattr(frame, 'liveness_score', 0.20)
    
    result = engine.process_frame(frame)
    assert result.gaze_score == 0.50
    assert result.liveness_passed is False
    assert result.liveness_score < base_config.liveness_threshold


def test_t3_5_quality_and_liveness(base_config):
    """
    T3.5 (Quality & Liveness):
    Face is poorly lit. enhancement increases quality above threshold, allowing liveness to pass.
    """
    template, matching_query, _ = get_mock_embeddings()
    engine = FaceSecurityEngine(base_config)
    engine.load_enrolled_templates([template])

    # 1. Untreated frame: mean illumination ~35, quality score is low
    frame_dark = generate_illuminated_frame(brightness=35)
    setattr(frame_dark, 'embedding', matching_query)
    result_dark = engine.process_frame(frame_dark)
    assert result_dark.quality_score < base_config.min_face_quality
    assert engine.consecutive_matches == 0

    # 2. Enhanced frame: mean illumination ~35 but enhanced = True, quality score is boosted
    for i in range(3):
        frame_enhanced = generate_illuminated_frame(brightness=35)
        frame_enhanced[0, 0, 0] = i
        setattr(frame_enhanced, 'enhanced', True)
        setattr(frame_enhanced, 'quality_score', 0.60)
        setattr(frame_enhanced, 'embedding', matching_query)
        result_enhanced = engine.process_frame(frame_enhanced)
        
    assert result_enhanced.quality_score >= base_config.min_face_quality
    assert result_enhanced.liveness_passed is True
    assert result_enhanced.primary_user_present is True
    assert engine.consecutive_matches == 3
