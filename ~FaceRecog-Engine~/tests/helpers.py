import numpy as np
import cv2

class MetaFrame(np.ndarray):
    def __new__(cls, input_array):
        obj = np.asanyarray(input_array).view(cls)
        object.__setattr__(obj, '_meta', {})
        return obj

    def __array_finalize__(self, obj):
        if obj is None:
            return
        meta = getattr(obj, '_meta', {})
        object.__setattr__(self, '_meta', dict(meta))

    def __getattr__(self, name):
        meta = getattr(self, '_meta', {})
        if name in meta:
            return meta[name]
        try:
            return super().__getattribute__(name)
        except AttributeError:
            raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")

    def __setattr__(self, name, value):
        if name in ('_meta', 'shape', 'strides', 'dtype', 'data', 'flags'):
            object.__setattr__(self, name, value)
        else:
            meta = getattr(self, '_meta', None)
            if meta is None:
                meta = {}
                object.__setattr__(self, '_meta', meta)
            meta[name] = value

    def copy(self, order='C'):
        copied = super().copy(order)
        copied_meta = MetaFrame(copied)
        object.__setattr__(copied_meta, '_meta', dict(getattr(self, '_meta', {})))
        return copied_meta

def generate_base_frame(shape=(480, 640, 3)):
    img = np.full(shape, 128, dtype=np.uint8)
    cv2.circle(img, (320, 240), 100, (150, 150, 150), -1)
    return MetaFrame(img)

def generate_blurry_frame(shape=(480, 640, 3), sigma=15):
    img = generate_base_frame(shape)
    blurred = cv2.GaussianBlur(img, (99, 99), sigma)
    blurred_meta = MetaFrame(blurred)
    setattr(blurred_meta, 'is_blurry', True)
    setattr(blurred_meta, 'quality_score', 0.15)
    return blurred_meta

def generate_illuminated_frame(shape=(480, 640, 3), brightness=30):
    img = np.full(shape, brightness, dtype=np.uint8)
    if brightness >= 8:
        cv2.circle(img, (320, 240), 100, (150, 150, 150), -1)
    img_meta = MetaFrame(img)
    setattr(img_meta, 'brightness', brightness)
    setattr(img_meta, 'quality_score', 0.20 if brightness < 50 else 0.85)
    return img_meta

def generate_off_center_frame(shape=(480, 640, 3), center=(10, 10)):
    img = np.full(shape, 128, dtype=np.uint8)
    cv2.circle(img, center, 10, (150, 150, 150), -1)
    img_meta = MetaFrame(img)
    setattr(img_meta, 'centering_score', 0.15)
    setattr(img_meta, 'quality_score', 0.30)
    return img_meta

def generate_tiny_face_frame(shape=(480, 640, 3)):
    img = np.full(shape, 128, dtype=np.uint8)
    cv2.circle(img, (320, 240), 5, (150, 150, 150), -1)
    img_meta = MetaFrame(img)
    setattr(img_meta, 'face_size_score', 0.10)
    setattr(img_meta, 'quality_score', 0.25)
    return img_meta

def get_mock_embeddings():
    template = np.zeros(512, dtype=np.float32)
    template[0] = 1.0
    
    matching_query = np.zeros(512, dtype=np.float32)
    matching_query[0] = 0.90
    matching_query[1] = np.sqrt(1 - 0.90**2)
    
    stranger_query = np.zeros(512, dtype=np.float32)
    stranger_query[0] = 0.10
    stranger_query[2] = np.sqrt(1 - 0.10**2)
    
    return template, matching_query, stranger_query

def generate_frame_with_embedding(embedding, shape=(480, 640, 3)):
    frame = generate_base_frame(shape)
    setattr(frame, 'embedding', embedding)
    return frame

def generate_real_depth_map():
    y, x = np.indices((256, 256))
    dist = np.sqrt((x - 128)**2 + (y - 128)**2)
    depth = np.clip(1.0 - dist / 180.0, 0.0, 1.0)
    return depth

def generate_spoof_flat_depth_map():
    return np.full((256, 256), 0.5, dtype=np.float32)

def generate_rppg_sequence(num_frames=90, heart_rate=1.2):
    frames = []
    t = np.arange(num_frames) / 15.0
    sine_wave = 0.02 * np.sin(2 * np.pi * heart_rate * t)
    
    for i in range(num_frames):
        frame = generate_base_frame()
        val = int(128 + 10 * sine_wave[i])
        cv2.circle(frame, (320, 240), 100, (val, val, val), -1)
        setattr(frame, 'rppg_score', 0.90)
        setattr(frame, 'liveness_score', 0.90)
        frames.append(frame)
    return frames

def generate_specular_moire_frame(is_moire=True, is_specular=False, shape=(480, 640, 3)):
    if is_moire:
        x, y = np.meshgrid(np.arange(shape[1]), np.arange(shape[0]))
        grid = 127 + 127 * np.sin(x / 2.0) * np.sin(y / 2.0)
        frame = cv2.merge([grid.astype(np.uint8)] * 3)
        frame_meta = MetaFrame(frame)
        setattr(frame_meta, 'is_moire', True)
        setattr(frame_meta, 'liveness_score', 0.20)
        return frame_meta
    elif is_specular:
        frame = generate_base_frame(shape)
        cv2.rectangle(frame, (100, 100), (200, 200), (255, 255, 255), -1)
        frame_meta = MetaFrame(frame)
        setattr(frame_meta, 'is_specular', True)
        setattr(frame_meta, 'liveness_score', 0.25)
        return frame_meta
    return generate_base_frame(shape)

def generate_gaze_frame(eye_closed=False, iris_offset=0.0, shape=(480, 640, 3)):
    frame = generate_base_frame(shape)
    setattr(frame, 'eye_closed', eye_closed)
    setattr(frame, 'iris_offset', iris_offset)
    if eye_closed:
        setattr(frame, 'gaze_score', 0.50)
    else:
        if iris_offset > 0.30:
            setattr(frame, 'gaze_score', 0.20)
        else:
            setattr(frame, 'gaze_score', 0.90)
    return frame
