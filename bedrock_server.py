from __future__ import annotations

from typing import Iterable, List, Optional, Tuple, Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from datetime import datetime
import hashlib
import json
import os
import re
import tempfile
import zipfile
import requests
from email.utils import parsedate_to_datetime

ROOT_PATH = Path(__file__).parent
BEDROCK_SERVER_PATH = ROOT_PATH / "bedrock" / "server"

BEDROCK_SERVER_VERSION_FILE = BEDROCK_SERVER_PATH / "versions.json"

BEDROCK_SERVER_PLATFORM_WINDOWS = BEDROCK_SERVER_PATH / "windows"
BEDROCK_SERVER_PLATFORM_LINUX = BEDROCK_SERVER_PATH / "linux"

BEDROCK_SERVER_RELEASE_PATH_WINDOWS = BEDROCK_SERVER_PLATFORM_WINDOWS / "release"
BEDROCK_SERVER_PREVIEW_PATH_WINDOWS = BEDROCK_SERVER_PLATFORM_WINDOWS / "preview"

BEDROCK_SERVER_RELEASE_PATH_LINUX = BEDROCK_SERVER_PLATFORM_LINUX / "release"
BEDROCK_SERVER_PREVIEW_PATH_LINUX = BEDROCK_SERVER_PLATFORM_LINUX / "preview"

HEADERS = {"User-Agent": "TorchCS/1.1"}
IS_CI = os.getenv("GITHUB_ACTIONS") == "true"

os.makedirs(BEDROCK_SERVER_RELEASE_PATH_WINDOWS, exist_ok=True)
os.makedirs(BEDROCK_SERVER_PREVIEW_PATH_WINDOWS, exist_ok=True)
os.makedirs(BEDROCK_SERVER_RELEASE_PATH_LINUX, exist_ok=True)
os.makedirs(BEDROCK_SERVER_PREVIEW_PATH_LINUX, exist_ok=True)


class ReleaseType(str, Enum):
    RELEASE = "release"
    PREVIEW = "preview"
    JAVA = "java"


class OS(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    ANY = "any"


@dataclass(frozen=True)
class DownloadEntry:
    release_type: ReleaseType
    os: OS
    version: Optional[str]
    url: str
    raw_type: str

    @property
    def version_tuple(self) -> Tuple[int, ...]:
        if not self.version:
            return ()
        return tuple(int(x) for x in re.findall(r"\d+", self.version))

    def as_dict(self) -> dict:
        file_name = os.path.basename(self.url) if self.url else None
        return {
            "file_name": file_name,
            "file_size": None,
            "version": self.version,
            "url": self.url,
            "os": self.os.value,
            "release_type": self.release_type.value,
            "last_modified_unix": None,
            "file_hash": None,
            "file_executable_hash": None,
        }


class BedrockAPI:
    BASE_URL = "https://net-secondary.web.minecraft-services.net/api/v1.0/download/links"

    def __init__(self, session: Optional[requests.Session] = None):
        self._session = session or requests.Session()
        self._cache: Optional[List[DownloadEntry]] = None

    def fetch(self, force: bool = False) -> List[DownloadEntry]:
        if self._cache is not None and not force:
            return self._cache
        r = self._session.get(self.BASE_URL, timeout=30, headers=HEADERS)
        r.raise_for_status()
        data = r.json()
        links = data.get("result", {}).get("links", [])
        self._cache = [self._to_entry(item) for item in links if self._to_entry(item)]
        return self._cache

    def all(self) -> List[DownloadEntry]:
        return list(self.fetch())

    def _to_entry(self, item: dict) -> Optional[DownloadEntry]:
        dt = item.get("downloadType", "")
        url = item.get("downloadUrl", "")
        if dt == "serverJar":
            release = ReleaseType.JAVA
            os_ = OS.ANY
        elif "Preview" in dt:
            release = ReleaseType.PREVIEW
            os_ = OS.WINDOWS if "Windows" in dt else OS.LINUX
        elif "serverBedrock" in dt:
            release = ReleaseType.RELEASE
            os_ = OS.WINDOWS if "Windows" in dt else OS.LINUX
        else:
            return None
        version = self._extract_version(url)
        return DownloadEntry(release_type=release, os=os_, version=version, url=url, raw_type=dt)

    @staticmethod
    def _extract_version(url: str) -> Optional[str]:
        m = re.search(r"bedrock-server-([0-9][0-9.\-]+)\.zip", url)
        if m:
            return m.group(1)
        m2 = re.search(r"/(\d+(?:\.\d+){1,3})", url)
        return m2.group(1) if m2 else None


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_hashes_for_entry(entry: DownloadEntry) -> Tuple[Optional[int], Optional[int], Optional[str], Optional[str]]:
    if not entry.url or IS_CI:
        return None, None, None, None

    head = requests.head(entry.url, timeout=20, headers=HEADERS)
    file_size = int(head.headers.get("Content-Length", "0") or 0)
    lm_header = head.headers.get("Last-Modified")
    last_modified_unix = None
    if lm_header:
        try:
            dt = parsedate_to_datetime(lm_header)
            last_modified_unix = int(dt.timestamp())
        except Exception:
            pass

    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = Path(tmpdir) / "server.zip"
        with requests.get(entry.url, stream=True, timeout=60, headers=HEADERS) as r:
            r.raise_for_status()
            with zip_path.open("wb") as f:
                for chunk in r.iter_content(1024 * 1024):
                    f.write(chunk)

        file_hash = sha256_file(zip_path)
        exe_hash = None
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                for name in zf.namelist():
                    if os.path.basename(name) in ("bedrock_server.exe", "bedrock_server"):
                        with zf.open(name, "r") as exe_file:
                            h = hashlib.sha256()
                            for chunk in iter(lambda: exe_file.read(1024 * 1024), b""):
                                h.update(chunk)
                            exe_hash = h.hexdigest()
                        break
        except Exception:
            exe_hash = None

    return file_size, last_modified_unix, file_hash, exe_hash


def metadata_exists(entry: DownloadEntry) -> bool:
    version = entry.version or "unknown"
    path = BEDROCK_SERVER_PATH / entry.os.value / entry.release_type.value / version / "metadata.json"
    return path.is_file()


def save_metadata(entry: DownloadEntry, meta: dict):
    base = BEDROCK_SERVER_PATH / entry.os.value / entry.release_type.value
    version_dir = base / (entry.version or "unknown")
    version_dir.mkdir(parents=True, exist_ok=True)
    with (version_dir / "metadata.json").open("w", encoding="utf-8") as f:
        json.dump(meta, f, indent=4, ensure_ascii=False)


def parse_version_number(ver: str) -> List[int]:
    return [int(x) for x in re.findall(r"\d+", ver)]


def sort_versions(versions: set[str]) -> List[str]:
    # neueste Version zuerst
    return sorted(list(versions), key=parse_version_number, reverse=True)


def collect_versions_from_disk() -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    release_versions = {"windows": set(), "linux": set()}
    preview_versions = {"windows": set(), "linux": set()}

    for os_name in ("windows", "linux"):
        for rt in (ReleaseType.RELEASE, ReleaseType.PREVIEW):
            base = BEDROCK_SERVER_PATH / os_name / rt.value
            if not base.is_dir():
                continue
            for child in base.iterdir():
                if child.is_dir():
                    (release_versions if rt == ReleaseType.RELEASE else preview_versions)[os_name].add(child.name)
    return release_versions, preview_versions


if __name__ == "__main__":
    api = BedrockAPI()
    entries = api.all()

    release_versions, preview_versions = collect_versions_from_disk()

    for entry in entries:
        if entry.release_type == ReleaseType.JAVA:
            continue

        if entry.version and entry.os in (OS.WINDOWS, OS.LINUX):
            versions = release_versions if entry.release_type == ReleaseType.RELEASE else preview_versions
            versions[entry.os.value].add(entry.version)

        if metadata_exists(entry):
            continue

        meta = entry.as_dict()
        size, mod_unix, file_hash, exe_hash = compute_hashes_for_entry(entry)
        meta["file_size"] = size
        meta["last_modified_unix"] = mod_unix
        meta["file_hash"] = file_hash
        meta["file_executable_hash"] = exe_hash

        save_metadata(entry, meta)

    release_win = sort_versions(release_versions["windows"])
    release_lin = sort_versions(release_versions["linux"])
    preview_win = sort_versions(preview_versions["windows"])
    preview_lin = sort_versions(preview_versions["linux"])

    latest = {
        "preview": {
            "windows": preview_win[0] if preview_win else "",
            "linux": preview_lin[0] if preview_lin else "",
        },
        "release": {
            "windows": release_win[0] if release_win else "",
            "linux": release_lin[0] if release_lin else "",
        },
    }

    payload = {
        "latest": latest,
        "release": {"windows": release_win, "linux": release_lin},
        "previews": {"windows": preview_win, "linux": preview_lin},
    }

    with BEDROCK_SERVER_VERSION_FILE.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=4)
