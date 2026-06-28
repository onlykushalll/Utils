import numpy as np
import pytest
import cv2
from facerecog_engine.utils.quality import (
    compute_sharpness,
    compute_illumination,
    compute_face_size_ratio,
    compute_face_centering,
    evaluate_quality_score,
)

def test_compute_sharpness():
    # Empty ROI
    empty_roi = np.empty((0, 0, 3), dtype=np.uint8)
    assert compute_sharpness(empty_roi) == 0.0

    # Constant color image (perfectly smooth, low sharpness)
    flat_roi = np.ones((100, 100, 3), dtype=np.uint8) * 128
    flat_sharpness = compute_sharpness(flat_roi)
    assert flat_sharpness == 0.0

    # High contrast checkerboard image (high sharpness)
    checkerboard = np.zeros((100, 100, 3), dtype=np.uint8)
    for i in range(100):
        for j in range(100):
            if (i // 10 + j // 10) % 2 == 0:
                checkerboard[i, j] = [255, 255, 255]
    
    sharp_sharpness = compute_sharpness(checkerboard)
    assert sharp_sharpness > 100.0

    # Blurred checkerboard (should have lower sharpness than the original sharp checkerboard)
    blurred_checkerboard = cv2.GaussianBlur(checkerboard, (15, 15), 0)
    blurred_sharpness = compute_sharpness(blurred_checkerboard)
    assert blurred_sharpness < sharp_sharpness

def test_compute_illumination():
    # Empty ROI
    empty_roi = np.empty((0, 0, 3), dtype=np.uint8)
    assert compute_illumination(empty_roi) == 0.0

    # Constant BGR color. In YCrCb, Y is computed from BGR.
    # Let's use pure black image: Y should be 0.
    black_roi = np.zeros((50, 50, 3), dtype=np.uint8)
    assert compute_illumination(black_roi) == 0.0

    # Pure white image: Y should be 255 (or very close).
    white_roi = np.ones((50, 50, 3), dtype=np.uint8) * 255
    assert abs(compute_illumination(white_roi) - 255.0) < 1.0

    # Mid gray image: Y should be around 128.
    gray_roi = np.ones((50, 50, 3), dtype=np.uint8) * 128
    assert abs(compute_illumination(gray_roi) - 128.0) < 5.0

def test_compute_face_size_ratio():
    frame_shape = (480, 640)
    # Bounding box of size 160x160
    bbox = (100.0, 100.0, 260.0, 260.0)
    expected_ratio = (160 * 160) / (480 * 640)
    ratio = compute_face_size_ratio(bbox, frame_shape)
    assert pytest.approx(ratio, rel=1e-5) == expected_ratio

    # Invalid box (negative coordinates or empty area)
    bad_bbox = (100.0, 100.0, 50.0, 50.0)
    assert compute_face_size_ratio(bad_bbox, frame_shape) == 0.0

def test_compute_face_centering():
    frame_shape = (400, 400)
    
    # Perfectly centered box (center at 200, 200)
    bbox_centered = (150.0, 150.0, 250.0, 250.0)
    assert compute_face_centering(bbox_centered, frame_shape) == 1.0

    # Off-center box
    bbox_offcenter = (300.0, 300.0, 400.0, 400.0)  # center at (350, 350)
    # dx = (350 - 200) / 200 = 150/200 = 0.75
    # dy = (350 - 200) / 200 = 150/200 = 0.75
    # distance = sqrt(0.75^2 + 0.75^2) = sqrt(1.125) = ~1.06066
    # clip(1 - 1.06066, 0.0, 1.0) = 0.0
    assert compute_face_centering(bbox_offcenter, frame_shape) == 0.0

    # Slightly off-center box
    bbox_partial = (200.0, 200.0, 300.0, 300.0) # center at (250, 250)
    # dx = (250 - 200) / 200 = 0.25
    # dy = (250 - 200) / 200 = 0.25
    # distance = sqrt(0.25^2 + 0.25^2) = sqrt(0.125) = ~0.35355
    # score = 1.0 - 0.35355 = ~0.64645
    score = compute_face_centering(bbox_partial, frame_shape)
    assert 0.64 < score < 0.65

def test_evaluate_quality_score():
    frame_shape = (480, 640)
    roi = np.ones((100, 100, 3), dtype=np.uint8) * 128
    bbox = (200.0, 150.0, 300.0, 250.0) # 100x100 box
    det_score = 0.90

    overall_quality, metrics = evaluate_quality_score(roi, bbox, frame_shape, det_score)
    
    assert "sharpness" in metrics
    assert "sharp_score" in metrics
    assert "mean_y" in metrics
    assert "illum_score" in metrics
    assert "size_ratio" in metrics
    assert "size_score" in metrics
    assert "centering_score" in metrics
    assert "overall_quality" in metrics
    
    # Verify the formula combination is mathematically correct
    expected_overall = (
        det_score * 0.40 +
        metrics["sharp_score"] * 0.30 +
        metrics["illum_score"] * 0.20 +
        metrics["size_score"] * 0.10
    )
    assert pytest.approx(overall_quality, rel=1e-5) == expected_overall
