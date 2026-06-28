# examples/verify_single_image.py — Verify single image demo
import cv2
import os
import sys
import numpy as np

# Ensure target package is discoverable
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from facerecog_engine import FaceSecurityEngine, SecurityConfig

def main():
    if len(sys.argv) < 2:
        print("Usage: python verify_single_image.py <path_to_image_file>")
        return
        
    image_path = sys.argv[1]
    if not os.path.exists(image_path):
        print(f"Error: image file {image_path} does not exist.")
        return

    model_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
    if not os.path.exists(os.path.join(model_dir, "midas_v21_small_256.onnx")):
        print(f"Models not found in {model_dir}. Please run download_models.py first.")
        return

    config = SecurityConfig(
        model_dir=model_dir,
        recognition_threshold=0.75,
        liveness_threshold=0.70,
        consensus_threshold=1,  # Set consensus to 1 since we are checking a single static image
        min_face_quality=0.30
    )

    image = cv2.imread(image_path)
    if image is None:
        print(f"Error: Failed to read image from {image_path}")
        return

    print("Initializing FaceSecurityEngine...")
    # Initialize engine without opening camera device
    engine = FaceSecurityEngine(config=config, camera_idx=-1)

    try:
        print(f"Processing image: {image_path}")
        result = engine.process_frame(frame=image, liveness_mode="full")
        
        print("\n--- Result Summary ---")
        print(f"Face Count: {result.face_count}")
        print(f"Quality Score: {result.frame_quality:.3f}")
        print(f"Liveness Passed: {result.liveness_passed} (Score: {result.liveness_score:.3f})")
        print(f"Inference Time: {result.inference_ms:.1f}ms")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        engine.shutdown()

if __name__ == "__main__":
    main()
