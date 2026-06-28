# examples/webcam_security_stream.py — Real-time camera processing demo
import cv2
import os
import sys
import numpy as np

# Ensure target package is discoverable
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from facerecog_engine import FaceSecurityEngine, SecurityConfig

def main():
    model_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
    if not os.path.exists(os.path.join(model_dir, "midas_v21_small_256.onnx")):
        print(f"Models not found in {model_dir}. Please run download_models.py first.")
        return

    config = SecurityConfig(
        model_dir=model_dir,
        recognition_threshold=0.75,
        liveness_threshold=0.70,
        consensus_threshold=3,
        min_face_quality=0.40
    )

    print("Initializing FaceSecurityEngine...")
    engine = FaceSecurityEngine(config=config, camera_idx=0)

    # Register a mock user with a random 512-dimension embedding for testing
    mock_user_embedding = np.random.randn(512).astype(np.float32)
    mock_user_embedding /= np.linalg.norm(mock_user_embedding)  # L2 Normalized
    
    engine.set_reference_templates({
        "authorized_user_1": [mock_user_embedding]
    })
    
    print("\nStarting video stream loop. Press 'q' to exit.")
    
    try:
        while True:
            # We pass frame=None so the engine automatically grabs from the default camera
            # (internally handled via cv2.VideoCapture)
            result = engine.process_frame(frame=None, liveness_mode="full")
            
            # Print frame results to console
            print(f"Face Count: {result.face_count} | "
                  f"User Present: {result.primary_user_present} | "
                  f"Liveness Passed: {result.liveness_passed} (Score: {result.liveness_score:.3f}) | "
                  f"Quality: {result.frame_quality:.3f} | "
                  f"Inference: {result.inference_ms:.1f}ms")
                  
            if result.virtual_camera_detected:
                print("WARNING: Virtual Camera Blocked!")
            if result.camera_obstructed:
                print("WARNING: Camera Obstructed!")

            # To run at a reasonable speed
            cv2.waitKey(60)
            
    except KeyboardInterrupt:
        print("\nStopping...")
    except Exception as e:
        print(f"Error during execution: {e}")
    finally:
        engine.shutdown()

if __name__ == "__main__":
    main()
