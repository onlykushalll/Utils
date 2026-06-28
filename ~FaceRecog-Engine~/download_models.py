# download_models.py — Standalone Model Downloader
import os
import sys
import urllib.request
import hashlib
import logging

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("FaceRecog.ModelDownloader")

MODELS = {
    "buffalo_l": {
        "description": "InsightFace buffalo_l (face detection + recognition)",
        "auto_download": True,
        "size_mb": 300,
    },
    "antispoof_minifasv2": {
        "description": "MiniFASNetV2 anti-spoofing model (600KB)",
        "url": "https://github.com/facenox/face-antispoof-onnx/releases/download/v1.0.0/best_model.onnx",
        "filename": "antispoof_minifasv2.onnx",
        "sha256": "af2381b88f38769222ed93379e12444e2a50814575de1c46170de570c55a42b6",
        "size_mb": 0.6,
    },
    "midas_v21_small": {
        "description": "MiDaS v2.1 small monocular depth model (21MB)",
        "url": "https://github.com/isl-org/MiDaS/releases/download/v2_1/model-small.onnx",
        "filename": "midas_v21_small_256.onnx",
        "sha256": "2d8c6cb8f415229daf1eb041024208e2608c9f98e17c81cc7c6ecb449c56fd58",
        "size_mb": 21,
    },
}

def download_file(url: str, dest_path: str, description: str, expected_sha256: str = None) -> bool:
    logger.info("Downloading %s...", description)
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    try:
        def reporthook(count, block_size, total_size):
            if total_size > 0:
                pct = min(100, count * block_size * 100 // total_size)
                sys.stdout.write(f"\r  {pct}% ")
                sys.stdout.flush()

        urllib.request.urlretrieve(url, dest_path, reporthook)
        sys.stdout.write("\r  100%\n")

        if expected_sha256:
            logger.info("  Verifying checksum...")
            sha256_hash = hashlib.sha256()
            with open(dest_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            actual_sha256 = sha256_hash.hexdigest().lower()
            if actual_sha256 != expected_sha256.lower():
                logger.error("  Verification FAILED! Checksum mismatch.")
                os.remove(dest_path)
                return False
            logger.info("  Checksum verified ✓")
        return True
    except Exception as e:
        logger.error("  Download failed: %s", e)
        if os.path.exists(dest_path):
            os.remove(dest_path)
        return False

def download_insightface_model(model_dir: str) -> bool:
    logger.info("Pre-downloading InsightFace buffalo_l model...")
    try:
        from insightface.app import FaceAnalysis
        app = FaceAnalysis(
            name="buffalo_l",
            root=model_dir,
            providers=["CPUExecutionProvider"],
        )
        app.prepare(ctx_id=0, det_size=(160, 160))
        logger.info("  buffalo_l ready.")
        return True
    except ImportError:
        logger.error("  InsightFace not installed. Run: pip install insightface")
        return False
    except Exception as e:
        logger.error("  buffalo_l download failed: %s", e)
        return False

def main():
    model_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(__file__), "models"
    )
    logger.info("=" * 55)
    logger.info("  FaceRecog Engine Model Downloader")
    logger.info("  Model directory: %s", model_dir)
    logger.info("=" * 55)

    results = {}
    results["buffalo_l"] = download_insightface_model(model_dir)
    
    # Download anti-spoof
    info = MODELS["antispoof_minifasv2"]
    dest_as = os.path.join(model_dir, info["filename"])
    results["antispoof"] = download_file(info["url"], dest_as, info["description"], info["sha256"]) if not os.path.exists(dest_as) else True
    
    # Download midas
    info_md = MODELS["midas_v21_small"]
    dest_md = os.path.join(model_dir, info_md["filename"])
    results["midas"] = download_file(info_md["url"], dest_md, info_md["description"], info_md["sha256"]) if not os.path.exists(dest_md) else True

    logger.info("\nDownload summary:")
    for name, ok in results.items():
        status = "✓" if ok else "✗ FAILED"
        logger.info("  %s  %s", status, name)

    if not all(results.values()):
        sys.exit(1)

    logger.info("\nAll models ready.")

if __name__ == "__main__":
    main()
