# virtual_camera_detector.py — Standalone Virtual/Software Camera Detector
import os
import re
import time
import logging
import subprocess
from typing import Optional

logger = logging.getLogger("FaceRecog.VirtualCameraDetector")

_PHYSICAL_HW_ID_PREFIXES = frozenset(["USB\\", "PCI\\", "ACPI\\", "SWD\\"])
_VIRTUAL_HW_ID_PREFIXES = frozenset(["ROOT\\", "SW\\", "VIRTUAL\\"])

_VIRTUAL_CAMERA_NAMES = frozenset([
    "obs virtual", "manycam", "xsplit vcam", "droidcam", "splitcam",
    "snap camera", "iriun", "epoccam", "camo", "ndi virtual",
    "virtual camera", "windows virtual camera", "avermedia virtual", "logi capture"
])

_VIRTUAL_CAMERA_CLSIDS = frozenset([
    "{A3FCE0F5-3493-419F-958A-ABA1250EC20B}",
    "{8E14549A-DB61-4309-AFA1-3578E927E935}",
    "{FBC9D74C-A950-11D1-8BD2-00A0C955FC6E}",
    "{7D8C3B72-8787-4CE8-B9EF-B5B50B43D6D4}",
])

import threading

class VirtualCameraDetector:
    def __init__(self):
        self._cache: dict[int, tuple[float, bool]] = {}
        self._cache_ttl: float = 30.0
        self._lock = threading.Lock()
        self._updating: set[int] = set()

    def is_virtual(self, camera_index: int) -> bool:
        # Graceful fallback on non-Windows platforms
        if os.name != "nt":
            return False
            
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(camera_index)
            if cached is not None:
                if (now - cached[0]) >= self._cache_ttl:
                    if camera_index not in self._updating:
                        self._updating.add(camera_index)
                        threading.Thread(
                            target=self._async_update,
                            args=(camera_index,),
                            name=f"mg-vcam-refresh-{camera_index}",
                            daemon=True,
                        ).start()
                return cached[1]

            if camera_index not in self._updating:
                self._updating.add(camera_index)
                try:
                    result = self._detect(camera_index)
                    self._cache[camera_index] = (time.monotonic(), result)
                finally:
                    self._updating.discard(camera_index)
                return self._cache[camera_index][1]
            else:
                return True

    def _async_update(self, camera_index: int) -> None:
        try:
            result = self._detect(camera_index)
            with self._lock:
                self._cache[camera_index] = (time.monotonic(), result)
        except Exception:
            pass
        finally:
            with self._lock:
                self._updating.discard(camera_index)

    def invalidate_cache(self):
        with self._lock:
            self._cache.clear()

    def _detect(self, camera_index: int) -> bool:
        camera_name = self._get_camera_name(camera_index)
        if camera_name:
            name_lower = camera_name.lower()
            for virtual_name in _VIRTUAL_CAMERA_NAMES:
                if virtual_name in name_lower:
                    return True

        if self._check_clsid_blocklist(camera_name):
            return True

        mf_result = self._check_mf_hardware_source(camera_index)
        if mf_result is False:
            return True

        hw_id = self._get_hardware_id(camera_name or "")
        if hw_id:
            for virtual_prefix in _VIRTUAL_HW_ID_PREFIXES:
                if hw_id.upper().startswith(virtual_prefix):
                    return True
            has_physical = any(hw_id.upper().startswith(p) for p in _PHYSICAL_HW_ID_PREFIXES)
            if not has_physical:
                return True

        return False

    def _check_clsid_blocklist(self, camera_name: Optional[str] = None) -> bool:
        if os.name != "nt":
            return False
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\CLSID", access=winreg.KEY_READ) as root:
                for clsid in _VIRTUAL_CAMERA_CLSIDS:
                    try:
                        key = winreg.OpenKey(root, clsid)
                        try:
                            friendly, _ = winreg.QueryValueEx(key, "")
                        except FileNotFoundError:
                            friendly = ""
                        finally:
                            key.Close()

                        friendly_lower = (friendly or "").lower()
                        if camera_name and friendly_lower:
                            cam_lower = camera_name.lower()
                            if cam_lower in friendly_lower or friendly_lower in cam_lower:
                                return True
                    except FileNotFoundError:
                        pass
        except Exception:
            pass
        return False

    def _check_mf_hardware_source(self, camera_index: int):
        if os.name != "nt":
            return None
        try:
            ps_cmd = (
                "$devices = [Windows.Devices.Enumeration.DeviceInformation]::"
                "FindAllAsync([Windows.Devices.Enumeration.DeviceClass]::VideoCapture)"
                ".GetAwaiter().GetResult(); "
                "$devices | Select-Object Name,Id | ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode == 0 and result.stdout.strip():
                import json
                devices = json.loads(result.stdout)
                if isinstance(devices, dict):
                    devices = [devices]
                if camera_index < len(devices):
                    name = (devices[camera_index].get("Name") or "").lower()
                    if "windows virtual camera" in name:
                        return False
                    return True
        except Exception:
            pass
        return None

    def _get_camera_name(self, camera_index: int) -> Optional[str]:
        if os.name != "nt":
            return None
        try:
            result = subprocess.run(
                ["wmic", "path", "Win32_PnPEntity", "where", "PNPClass='Camera'", "get", "Name", "/format:list"],
                capture_output=True, text=True, timeout=3
            )
            names = [
                line.split("=", 1)[1].strip()
                for line in result.stdout.splitlines()
                if line.startswith("Name=") and line.split("=", 1)[1].strip()
            ]
            if camera_index < len(names):
                return names[camera_index]
            if names:
                return names[0]
        except Exception:
            pass

        try:
            ps_cmd = (
                "$devices = [Windows.Devices.Enumeration.DeviceInformation]::"
                "FindAllAsync([Windows.Devices.Enumeration.DeviceClass]::VideoCapture)"
                ".GetAwaiter().GetResult(); "
                "$devices | Select-Object -ExpandProperty Name"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=3
            )
            names = [n.strip() for n in result.stdout.strip().splitlines() if n.strip()]
            if camera_index < len(names):
                return names[camera_index]
        except Exception:
            pass

        return None

    def _get_hardware_id(self, camera_name: str) -> Optional[str]:
        if os.name != "nt" or not camera_name:
            return None

        try:
            ps_cmd = (
                "Get-PnpDevice -Class Camera -Status OK | "
                "Select-Object FriendlyName,HardwareID | ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode != 0:
                return None

            import json
            devices = json.loads(result.stdout)
            if isinstance(devices, dict):
                devices = [devices]

            name_lower = camera_name.lower()
            for device in devices:
                fn = (device.get("FriendlyName") or "").lower()
                hw = device.get("HardwareID")
                if name_lower in fn or fn in name_lower:
                    if isinstance(hw, list) and hw:
                        return hw[0]
                    elif isinstance(hw, str):
                        return hw
        except Exception:
            pass
        return None

_detector = VirtualCameraDetector()

def is_virtual_camera(camera_index: int) -> bool:
    return _detector.is_virtual(camera_index)

def invalidate_camera_cache():
    _detector.invalidate_cache()
