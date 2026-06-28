# FaceRecog-engine

A standalone, decoupled, plug-and-play Face Recognition and passive Multi-Layer Liveness detection engine extracted from MajestyGuard. 

This package compiles all advanced computer vision security layers into a portable Python library, removing Windows Named Pipes and service infrastructure, making it usable for any global project.

## 🚀 Features
1. **RetinaFace Detection & Landmark Tracking**: Clean localized face bounds using InsightFace.
2. **Kalman-Filtered Bbox Stabilization**: Bounding box smoothing to prevent jitter.
3. **AdaFace Recognition (L2-Normalized 512-dim)**: Quality-adaptive margin embedding generation with optional flip fusion.
4. **12-Layer Passive Liveness (Anti-Spoofing)**:
   - **Texture**: Local Binary Patterns (LBP) entropy & variance analysis.
   - **Specular Reflection**: Glare fraction & spatial spread mapping.
   - **Color Space**: YCbCr skin distribution & correlation.
   - **Moiré Frequency**: FFT peak-to-mean ratio detection.
   - **Temporal Blink**: Eye patch brightness tracking (landmarks-based).
   - **Face Boundary**: Hough line rectangular frame check.
   - **ONNX Anti-Spoof**: MiniFASNetV2 integration.
   - **Depth Geometry**: 3D facial landmark ratio variance.
   - **Histogram Consistency**: Temporal stability of color profiles.
   - **MiDaS Depth**: Monocular 3D depth variance.
   - **rPPG Blood Flow**: Heartbeat SNR signal analysis.
   - **Attention/Gaze**: MediaPipe Iris variability.

---

## 🛠️ Setup & Installation

### 1. Requirements
Ensure your Python environment is version `3.8` or newer. Install dependencies:
```bash
pip install -r requirements.txt
```

To install this package in editable mode:
```bash
pip install -e .
```

### 2. Download Model Weights
Run the downloader script to fetch required ONNX weights (MiniFASNetV2, MiDaS, and InsightFace detection assets):
```bash
python download_models.py
```
This saves ONNX weights into a local `./models/` folder.

---

## 💡 Example Usage

### Webcam Stream Security Check
Run the real-time webcam demo:
```bash
python examples/webcam_security_stream.py
```

### Static Image Validation
Verify a single face image file:
```bash
python examples/verify_single_image.py path/to/image.jpg
```
