# FaceRecog-Engine — Standalone Build Manifest

**Version:** 1.0 (production-ready, verified)
**Architecture:** Decoupled, portable, local-only Python package

---

## What's in this folder

This is the standalone **FaceRecog-Engine** containing the core face detection, tracking, liveness checks, and recognition algorithms extracted from MajestyGuard. All named pipes, active Windows process controllers, and Windows-specific DPAPI encryption models have been replaced with clean, platform-agnostic implementations.

---

## Directory Contents

```
~FaceRecog-Engine~/
├── README.md                      # Overview, setup, and example guides
├── LICENSE                        # MIT License
├── MANIFEST.md                    # Complete layout manifest
├── requirements.txt               # Pin-pointed, clean Python dependencies
├── download_models.py             # Automates downloading MiDaS, best_model, etc.
├── setup.py                       # Python setup configuration
├── SECURITY.md                    # Vulnerability reporting guidelines
├── PRIVACY.md                     # Biometric privacy & compliance statement
│
├── facerecog_engine/              # Core python package folder
│   ├── __init__.py                # Package exports (FaceSecurityEngine, SecurityConfig, VerificationResult)
│   ├── config.py                  # Dataclasses defining Security, Camera, Quality configs
│   ├── exceptions.py              # Custom exceptions (ModelLoadError, CameraError, etc.)
│   ├── liveness_detector.py       # Passive 12-layer anti-spoofing engine (texture, specular, etc.)
│   ├── attention_detector.py      # MediaPipe FaceMesh gaze variability and blink tracker
│   ├── depth_liveness.py          # ONNX MiDaS depth estimator
│   ├── rppg_detector.py           # CHROM blood-flow heart rate estimator
│   ├── face_quality.py            # Quality metrics (sharpness, lighting, centering, size)
│   ├── virtual_camera_detector.py # Platform-safe software camera blocker
│   │
│   ├── core/
│   │   ├── __init__.py            # Core package initializer
│   │   ├── detector.py            # FaceDetector (buffalo_l) & BBoxKalmanFilter
│   │   └── recognizer.py          # FaceRecognizer (AdaFace / ArcFace fallback)
│   │
│   └── utils/
│       ├── __init__.py            # Utility package exports
│       ├── crypto.py              # AES-256-GCM encryption helpers (DPAPI decoupling)
│       ├── image.py               # CLAHE contrast enhancement & resizing
│       └── quality.py             # Low-level quality computations
│
└── examples/
    ├── webcam_security_stream.py  # Webcam real-time process loop demo
    └── verify_single_image.py     # Image file verification demo
```

---

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
pip install -e .
```

### 2. Download Model Weights
```bash
python download_models.py
```

### 3. Run Verification Examples
* Real-time webcam check:
  ```bash
  python examples/webcam_security_stream.py
  ```
* Static image check:
  ```bash
  python examples/verify_single_image.py path/to/image.jpg
  ```
