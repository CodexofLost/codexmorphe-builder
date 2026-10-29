import subprocess
from pathlib import Path
from typing import List, Optional
from ..config import D8_BIN


def merge_dex_files(dex_inputs: List[Path], output_dir: Path) -> Optional[Path]:
    """
    Merge multiple Dalvik DEX / .mpe files into classes.dex inside output_dir using d8.
    """
    if not D8_BIN:
        raise RuntimeError("d8 binary not found. Please verify Android SDK build-tools installation.")

    output_dir.mkdir(parents=True, exist_ok=True)
    if not dex_inputs:
        print("[WARN] No DEX files to merge.")
        return None

    cmd = [
        str(D8_BIN),
        "--release",
        "--min-api", "26",
        "--output", str(output_dir)
    ] + [str(p) for p in dex_inputs]

    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"d8 failed (code {res.returncode}):\n{res.stderr}")

    out_dex = output_dir / "classes.dex"
    if out_dex.exists():
        return out_dex
    return None
