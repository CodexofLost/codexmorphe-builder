import hashlib
import json
import os
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

from .cache_ledger import CacheLedger
from .source_model import SourceDescriptor


def get_github_token() -> Optional[str]:
    # 1. Environment variable (standard in GitHub Actions)
    if "GITHUB_TOKEN" in os.environ and os.environ["GITHUB_TOKEN"].strip():
        return os.environ["GITHUB_TOKEN"].strip()
    if "GH_TOKEN" in os.environ and os.environ["GH_TOKEN"].strip():
        return os.environ["GH_TOKEN"].strip()

    # 2. Check gh CLI authentication
    if shutil.which("gh"):
        try:
            res = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except Exception:
            pass
    return None


class ReleaseClient:
    def __init__(self, mpp_cache_dir: Path, ledger: CacheLedger):
        self.mpp_cache_dir = mpp_cache_dir
        self.ledger = ledger
        self.token = get_github_token()
        self.mpp_cache_dir.mkdir(parents=True, exist_ok=True)

    def fetch_source(self, source: SourceDescriptor, force: bool = False) -> Optional[Path]:
        """
        Resolve and download the latest .mpp asset for the given source.
        Returns the local path to the verified .mpp archive.
        """
        if not source.enabled:
            print(f"[SKIP] Source '{source.id}' is disabled.")
            return None

        print(f"\n[FETCH] Processing '{source.name}' ({source.id})...")

        if source.type == "local_file":
            return self._handle_local_file(source)
        elif source.type == "direct_url":
            return self._handle_direct_url(source, force)
        elif source.type == "github_release":
            return self._handle_github_release(source, force)
        else:
            print(f"[ERROR] Unsupported source type '{source.type}' for source '{source.id}'")
            return None

    def _handle_local_file(self, source: SourceDescriptor) -> Optional[Path]:
        if not source.local_path:
            print(f"[ERROR] local_path not specified for '{source.id}'")
            return None
        p = Path(source.local_path).expanduser()
        if not p.exists():
            print(f"[ERROR] Local file does not exist: {p}")
            return None
        sha256 = self._compute_sha256(p)
        self.ledger.update(
            source_id=source.id,
            tag="local",
            asset_name=p.name,
            asset_id=None,
            sha256=sha256,
            file_path=p,
            file_size=p.stat().st_size
        )
        return p

    def _handle_direct_url(self, source: SourceDescriptor, force: bool) -> Optional[Path]:
        if not source.direct_url:
            print(f"[ERROR] direct_url not specified for '{source.id}'")
            return None

        filename = f"{source.id}-direct.mpp"
        target_path = self.mpp_cache_dir / filename

        # Download directly
        print(f"  Downloading from {source.direct_url}...")
        self._download_url(source.direct_url, target_path)
        sha256 = self._compute_sha256(target_path)
        self.ledger.update(
            source_id=source.id,
            tag="direct",
            asset_name=filename,
            asset_id=None,
            sha256=sha256,
            file_path=target_path,
            file_size=target_path.stat().st_size
        )
        return target_path

    def _handle_github_release(self, source: SourceDescriptor, force: bool) -> Optional[Path]:
        if not source.repository:
            print(f"[ERROR] repository not specified for source '{source.id}'")
            return None

        repo = source.repository.strip()
        api_url = f"https://api.github.com/repos/{repo}/releases"
        if not source.include_prerelease:
            api_url = f"https://api.github.com/repos/{repo}/releases/latest"

        req = urllib.request.Request(api_url)
        req.add_header("User-Agent", "CodexMorpheBuilder/0.1.0")
        req.add_header("Accept", "application/vnd.github.v3+json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404 and not source.include_prerelease:
                # If /releases/latest returned 404, fallback to first release from list
                return self._fetch_first_available_release(source, force)
            print(f"  [ERROR] GitHub API failed ({e.code}): {e.reason}")
            return None
        except Exception as e:
            print(f"  [ERROR] Failed to query GitHub API: {e}")
            return None

        release = data if isinstance(data, dict) else (data[0] if data else None)
        if not release:
            print(f"  [WARN] No releases found for {repo}")
            return None

        return self._process_release_asset(source, release, force)

    def _fetch_first_available_release(self, source: SourceDescriptor, force: bool) -> Optional[Path]:
        repo = source.repository.strip()
        api_url = f"https://api.github.com/repos/{repo}/releases"
        req = urllib.request.Request(api_url)
        req.add_header("User-Agent", "CodexMorpheBuilder/0.1.0")
        req.add_header("Accept", "application/vnd.github.v3+json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                releases = json.loads(resp.read().decode("utf-8"))
                if releases:
                    return self._process_release_asset(source, releases[0], force)
        except Exception as e:
            print(f"  [ERROR] Fallback releases query failed: {e}")
        return None

    def _process_release_asset(self, source: SourceDescriptor, release: Dict[str, Any], force: bool) -> Optional[Path]:
        tag = release.get("tag_name", "unknown")
        assets = release.get("assets", [])

        # Find matching .mpp asset
        matched_asset = None
        for asset in assets:
            name = asset.get("name", "")
            if source.matches_asset(name):
                matched_asset = asset
                break

        if not matched_asset:
            print(f"  [WARN] No asset matching pattern '{source.asset_pattern}' in release {tag}")
            return None

        asset_name = matched_asset["name"]
        asset_id = matched_asset["id"]
        download_url = matched_asset["browser_download_url"]
        target_path = self.mpp_cache_dir / f"{source.id}-{tag}-{asset_name}"

        # Check ledger cache
        if not force and self.ledger.is_up_to_date(source.id, tag, asset_id) and target_path.exists():
            print(f"  [UP-TO-DATE] {source.name} {tag} ({asset_name}) is already cached.")
            return target_path

        print(f"  Downloading {asset_name} ({tag})...")
        self._download_url(download_url, target_path)

        sha256 = self._compute_sha256(target_path)
        self.ledger.update(
            source_id=source.id,
            tag=tag,
            asset_name=asset_name,
            asset_id=asset_id,
            sha256=sha256,
            file_path=target_path,
            file_size=target_path.stat().st_size
        )
        print(f"  ✓ Saved to {target_path.name} (SHA256: {sha256[:12]}...)")
        return target_path

    def _download_url(self, url: str, dest: Path) -> None:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "CodexMorpheBuilder/0.1.0")
        tmp_dest = dest.with_suffix(".tmp")
        with urllib.request.urlopen(req, timeout=60) as resp, open(tmp_dest, "wb") as out:
            shutil.copyfileobj(resp, out)
        tmp_dest.replace(dest)

    def _compute_sha256(self, path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
