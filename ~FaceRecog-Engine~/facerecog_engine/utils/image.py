import cv2
import numpy as np

def enhance_low_light(frame: np.ndarray, clahe_obj: cv2.CLAHE = None) -> np.ndarray:
    """
    Applies CLAHE on L channel of BGR image if it is in low light.
    """
    try:
        if frame.size == 0 or frame.shape[0] == 0 or frame.shape[1] == 0:
            return frame
        lab = cv2.cvtColor(frame, cv2.COLOR_BGR2LAB)
        l, a, b = cv2.split(lab)
        mean_l = float(np.mean(l))
        if mean_l > 100:
            return frame
        
        # Instantiate CLAHE if not pre-allocated
        if clahe_obj is None:
            clahe_obj = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
            
        l_enhanced = clahe_obj.apply(l)
        if mean_l < 50:
            gamma = 0.6
            l_enhanced = (np.power(l_enhanced / 255.0, gamma) * 255.0).astype(np.uint8)
        
        enhanced = cv2.merge([l_enhanced, a, b])
        return cv2.cvtColor(enhanced, cv2.COLOR_LAB2BGR)
    except Exception:
        return frame

def resize_with_aspect_ratio(image: np.ndarray, target_size: int, interpolation=cv2.INTER_LINEAR) -> np.ndarray:
    """
    Resizes an image with aspect ratio preservation (padding to square).
    """
    h, w = image.shape[:2]
    if h == 0 or w == 0:
        # Avoid division by zero
        return np.zeros((target_size, target_size, image.shape[2] if len(image.shape) > 2 else 1), dtype=image.dtype)
    scale = target_size / max(h, w)
    nh, nw = int(h * scale), int(w * scale)
    # Ensure nh and nw are at least 1
    nh = max(1, nh)
    nw = max(1, nw)
    resized = cv2.resize(image, (nw, nh), interpolation=interpolation)
    
    pad_h = (target_size - nh) // 2
    pad_w = (target_size - nw) // 2
    
    padded = cv2.copyMakeBorder(
        resized,
        pad_h,
        target_size - nh - pad_h,
        pad_w,
        target_size - nw - pad_w,
        cv2.BORDER_CONSTANT,
        value=[0, 0, 0]
    )
    return padded
