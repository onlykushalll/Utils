class EngineError(Exception):
    """Base exception for all FaceRecog engine errors."""
    pass


class ModelLoadError(EngineError):
    """Raised when a neural network model fails to load or compile."""
    pass


class FaceQualityError(EngineError):
    """Raised when an input image or face crop does not meet quality requirements."""
    pass


class CameraError(EngineError):
    """Raised when camera initialization or frame retrieval fails."""
    pass


class CryptoError(EngineError):
    """Raised when encryption or decryption operations fail."""
    pass
