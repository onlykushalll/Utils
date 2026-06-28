# Biometric Privacy Statement

`FaceRecog-Engine` is designed from the ground up to respect user privacy and adhere to modern biometric data compliance principles.

## 1. 100% Local Execution
* All face detection, landmark tracking, AdaFace embedding extraction, and multi-layer liveness checks are executed **locally on the host machine**.
* The engine makes **zero network requests** and does not stream biometric data, frames, or telemetry to any external server.

## 2. Zero-Disk Biometric Policy
* Camera frames and face ROI crops are processed strictly in volatile memory (RAM).
* Biometric image buffers are **never written to disk**.

## 3. Memory Zeroing & Sanitization
* To prevent RAM-based exposure, the engine immediately zeros out intermediate frame arrays after inference is completed.
* The system utilizes in-memory garbage collection and explicit array clearing (`frame[:] = 0`) to minimize the lifetime of biometric information in memory.

## 4. Complete Storage Decoupling
* The engine does not store user templates internally.
* Embedding vectors are handled as transient NumPy arrays passed in-memory during validation. This architecture allows the host application to enforce its own database security, encryption (e.g. using the provided AES-GCM helpers), and compliance frameworks.
