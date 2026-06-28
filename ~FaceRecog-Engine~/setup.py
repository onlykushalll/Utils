from setuptools import setup, find_packages

setup(
    name="facerecog_engine",
    version="1.0.0",
    description="Standalone MajestyGuard Computer Vision, Face Recognition, and Passive Liveness Detection Engine",
    author="Antigravity",
    packages=find_packages(),
    install_requires=[
        "numpy>=1.20.0",
        "opencv-python>=4.5.0",
        "mediapipe>=0.10.0",
        "onnxruntime>=1.15.0",
        "scipy>=1.9.0",
        "insightface>=0.7.3",
        "cryptography>=41.0.0",
    ],
    python_requires=">=3.8",
)
