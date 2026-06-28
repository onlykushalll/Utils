import os
from dataclasses import dataclass, field
from typing import Optional, List, Tuple

@dataclass
class SecurityConfig:
    model_dir: str
    recognition_threshold: float = 0.75
    liveness_threshold: float = 0.70
    consensus_threshold: int = 3
    onnx_providers: Optional[List[str]] = None
    min_face_quality: float = 0.40

@dataclass
class CameraConfig:
    device_index: int = 0
    width: int = 640
    height: int = 480
    fps: int = 30
    backend: str = "DSHOW"  # Windows fallback, or DEFAULT

@dataclass
class QualityConfig:
    min_sharpness: float = 400.0
    min_illumination_y: float = 50.0
    target_illumination_y: float = 128.0
    min_face_size_ratio: float = 0.10
    max_face_size_ratio: float = 0.80
    min_overall_quality: float = 0.35
    min_det_score: float = 0.85

@dataclass
class ModelConfig:
    model_dir: str = field(default_factory=lambda: os.path.join(os.getcwd(), "models"))
    det_size: Tuple[int, int] = (160, 160)
    recognition_threshold: float = 0.75
    liveness_threshold: float = 0.85

@dataclass
class CryptoConfig:
    pbkdf2_iterations: int = 100_000
    salt_length: int = 16
    nonce_length: int = 12

@dataclass
class EngineConfig:
    camera: CameraConfig = field(default_factory=CameraConfig)
    quality: QualityConfig = field(default_factory=QualityConfig)
    models: ModelConfig = field(default_factory=ModelConfig)
    crypto: CryptoConfig = field(default_factory=CryptoConfig)
