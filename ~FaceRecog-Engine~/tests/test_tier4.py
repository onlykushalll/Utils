import pytest
import numpy as np
from facerecog_engine import SecurityConfig, FaceSecurityEngine, VerificationResult
from tests.helpers import (
    generate_base_frame,
    generate_illuminated_frame,
    get_mock_embeddings,
    generate_frame_with_embedding,
    generate_specular_moire_frame
)

def test_t4_1_standard_authorized_login(base_config):
    """
    T4.1 (Standard Authorized Login Flow):
    - Frames 1-2: Low centering quality -> primary_user_present = False
    - Frames 3-5: Centered face -> quality & liveness & recog passes -> primary_user_present = True at Frame 5
    - Frames 6-8: Matching face continues -> primary_user_present = True
    - Frame 9: Remaining -> primary_user_present = True
    """
    template, matching_query, _ = get_mock_embeddings()
    engine = FaceSecurityEngine(base_config)
    engine.load_enrolled_templates([template])

    # Frames 1-2: Low quality face
    for i in range(2):
        frame = generate_frame_with_embedding(matching_query)
        frame[0, 0, 0] = i
        setattr(frame, 'quality_score', 0.30)
        res = engine.process_frame(frame)
        assert res.face_detected is True
        assert res.primary_user_present is False

    # Frames 3-5: Centered face, high quality, recog passes
    for i in range(3):
        frame = generate_frame_with_embedding(matching_query)
        frame[0, 0, 0] = i + 10
        setattr(frame, 'quality_score', 0.85)
        res = engine.process_frame(frame)
        if i == 2:
            assert res.primary_user_present is True
        else:
            assert res.primary_user_present is False

    # Frames 6-8: Continued match
    for i in range(3):
        frame = generate_frame_with_embedding(matching_query)
        frame[0, 0, 0] = i + 20
        setattr(frame, 'quality_score', 0.85)
        res = engine.process_frame(frame)
        assert res.primary_user_present is True

    # Frame 9: Remaining
    frame = generate_frame_with_embedding(matching_query)
    frame[0, 0, 0] = 30
    setattr(frame, 'quality_score', 0.85)
    res = engine.process_frame(frame)
    assert res.primary_user_present is True


def test_t4_2_photo_spoof_attack_prevention(base_config):
    """
    T4.2 (Photo Spoof Attack Prevention):
    - Frames 1-10: Attacker holds printed photo. Recog score is high but liveness is low.
    - Verify liveness_passed remains False, primary_user_present is False.
    """
    template, matching_query, _ = get_mock_embeddings()
    engine = FaceSecurityEngine(base_config)
    engine.load_enrolled_templates([template])

    for i in range(10):
        frame = generate_specular_moire_frame(is_moire=True)
        frame[0, 0, 0] = i
        setattr(frame, 'embedding', matching_query)
        setattr(frame, 'liveness_score', 0.12)
        res = engine.process_frame(frame)
        assert res.recognition_score > base_config.recognition_threshold
        assert res.liveness_passed is False
        assert res.primary_user_present is False


def test_t4_3_transient_occlusion_recovery(base_config):
    """
    T4.3 (Transient Occlusion Recovery):
    - Frames 1-2: Authorized user. Consensus counter is at 2.
    - Frame 3: Hand occludes camera (black frame). face_detected = False, consensus counter resets.
    - Frames 4-6: Hand removed. User face detected again. Consensus met at Frame 6, primary_user_present = True.
    """
    template, matching_query, _ = get_mock_embeddings()
    engine = FaceSecurityEngine(base_config)
    engine.load_enrolled_templates([template])

    # Frames 1-2: Authorized user approaches
    for i in range(2):
        frame = generate_frame_with_embedding(matching_query)
        frame[0, 0, 0] = i
        res = engine.process_frame(frame)
        assert res.primary_user_present is False
    assert engine.consecutive_matches == 2

    # Frame 3: Hand occludes camera
    frame_black = np.zeros((480, 640, 3), dtype=np.uint8)
    res_black = engine.process_frame(frame_black)
    assert res_black.face_detected is False
    assert engine.consecutive_matches == 0

    # Frames 4-6: Hand removed, user matches again
    for i in range(3):
        frame = generate_frame_with_embedding(matching_query)
        frame[0, 0, 0] = i + 10
        res = engine.process_frame(frame)
        if i == 2:
            assert res.primary_user_present is True
        else:
            assert res.primary_user_present is False


def test_t4_4_unauthorized_strangers(base_config):
    """
    T4.4 (Strangers / Unauthorized Users):
    - Frames 1-10: Stranger in front of camera. Quality is high, liveness passes, but recog score is low.
    - Verify primary_user_present remains False.
    """
    template, _, stranger_query = get_mock_embeddings()
    engine = FaceSecurityEngine(base_config)
    engine.load_enrolled_templates([template])

    for i in range(10):
        frame = generate_frame_with_embedding(stranger_query)
        frame[0, 0, 0] = i
        res = engine.process_frame(frame)
        assert res.face_detected is True
        assert res.liveness_passed is True
        assert res.recognition_score < base_config.recognition_threshold
        assert res.primary_user_present is False


def test_t4_5_low_light_login_recovery(base_config):
    """
    T4.5 (Low-Light Login Recovery):
    - Frame 1: User in dark room (mean illumination ~35). No CLAHE. Quality score is low, no match.
    - Frames 2-4: CLAHE enhancement active. Quality passes, liveness passes, recognition passes.
    - At Frame 4, consensus is met and primary_user_present becomes True.
    """
    template, matching_query, _ = get_mock_embeddings()
    engine = FaceSecurityEngine(base_config)
    engine.load_enrolled_templates([template])

    # Frame 1: Dark room, no enhancement
    frame_dark = generate_illuminated_frame(brightness=35)
    setattr(frame_dark, 'embedding', matching_query)
    res = engine.process_frame(frame_dark)
    assert res.quality_score < base_config.min_face_quality
    assert engine.consecutive_matches == 0

    # Frames 2-4: CLAHE enhancement active
    for i in range(3):
        frame_enhanced = generate_illuminated_frame(brightness=35)
        frame_enhanced[0, 0, 0] = i
        setattr(frame_enhanced, 'enhanced', True)
        setattr(frame_enhanced, 'quality_score', 0.60)
        setattr(frame_enhanced, 'embedding', matching_query)
        res = engine.process_frame(frame_enhanced)
        if i == 2:
            assert res.primary_user_present is True
        else:
            assert res.primary_user_present is False
