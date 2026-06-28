import cv2
import numpy as np
from facerecog_engine.utils.image import (
    enhance_low_light,
    resize_with_aspect_ratio,
)

def test_enhance_low_light():
    # 1. Normal light image (mean lightness > 100). Should be bypassed without modification.
    normal_light_img = np.ones((100, 100, 3), dtype=np.uint8) * 180
    enhanced_normal = enhance_low_light(normal_light_img)
    assert np.array_equal(normal_light_img, enhanced_normal)

    # 2. Low light image (mean lightness < 100). Should be enhanced.
    low_light_img = np.ones((100, 100, 3), dtype=np.uint8) * 40
    enhanced_low = enhance_low_light(low_light_img)
    # Check that it's no longer the exact same image
    assert not np.array_equal(low_light_img, enhanced_low)
    # Check that the mean lightness is increased
    lab_orig = cv2.cvtColor(low_light_img, cv2.COLOR_BGR2LAB)
    lab_enh = cv2.cvtColor(enhanced_low, cv2.COLOR_BGR2LAB)
    assert np.mean(lab_enh[:, :, 0]) > np.mean(lab_orig[:, :, 0])

    # 3. Empty image should not crash
    empty_img = np.empty((0, 0, 3), dtype=np.uint8)
    assert np.array_equal(enhance_low_light(empty_img), empty_img)

def test_resize_with_aspect_ratio():
    # Aspect ratio preserving resize to 120x120
    # Input is wide image: 100x200
    img_wide = np.ones((100, 200, 3), dtype=np.uint8) * 255
    target_size = 120
    
    resized = resize_with_aspect_ratio(img_wide, target_size)
    
    # Target shape must be 120x120x3
    assert resized.shape == (120, 120, 3)
    
    # The original width (200) was scaled to 120 (scale = 0.6)
    # Original height (100) scaled to 60.
    # Pad height is (120 - 60) // 2 = 30 at top and bottom.
    # The top 30 rows and bottom 30 rows should be black (0)
    assert np.all(resized[0:30, :, :] == 0)
    assert np.all(resized[90:120, :, :] == 0)
    # The middle rows (30 to 90) should contain the image data (non-zero)
    assert np.any(resized[30:90, :, :] == 255)

    # Input is tall image: 200x100
    img_tall = np.ones((200, 100, 3), dtype=np.uint8) * 255
    resized_tall = resize_with_aspect_ratio(img_tall, target_size)
    assert resized_tall.shape == (120, 120, 3)
    # Scale = 0.6. Height becomes 120, width becomes 60.
    # Pad width is (120 - 60) // 2 = 30 at left and right.
    assert np.all(resized_tall[:, 0:30, :] == 0)
    assert np.all(resized_tall[:, 90:120, :] == 0)
    assert np.any(resized_tall[:, 30:90, :] == 255)

    # Empty image check
    empty_img = np.empty((0, 0, 3), dtype=np.uint8)
    resized_empty = resize_with_aspect_ratio(empty_img, target_size)
    assert resized_empty.shape == (120, 120, 3)
    assert np.all(resized_empty == 0)
