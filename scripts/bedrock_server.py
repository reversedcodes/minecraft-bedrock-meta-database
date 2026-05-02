import hashlib
import json
import os
import re
import io
import zipfile
import requests
import logging

from constant import ROOT_PATH, logging
from email.utils import parsedate_to_datetime
from typing import Optional, Tuple, Dict
from pathlib import Path

HEADERS = {"User-Agent": "TorchCS/1.1"}

SERVER_PATH = ROOT_PATH / "bedrock" / "server"
SERVER_RELEASE_PATH = SERVER_PATH / "release"
SERVER_PREVIEW_PATH = SERVER_PATH / "preview"
SERVER_VERSIONS_JSON_PATH = SERVER_PATH / "versions.json"

logger = logging.getLogger("BedrockServerFetcher")

def compute_hashes(url: str) -> Tuple[int, Optional[int], str, Optional[str]]:
    logger.info(f"Downloading & Hashing: {url}")
    
    head = requests.head(url, timeout=20, headers=HEADERS)
    size = int(head.headers.get("Content-Length", 0))
    lm = head.headers.get("Last-Modified")
    ts = int(parsedate_to_datetime(lm).timestamp()) if lm else None

    resp = requests.get(url, timeout=60, headers=HEADERS)
    resp.raise_for_status()
    data = resp.content

    file_hash = hashlib.sha256(data).hexdigest()
    exe_hash = None

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                if os.path.basename(name) in ("bedrock_server.exe", "bedrock_server"):
                    exe_hash = hashlib.sha256(zf.read(name)).hexdigest()
                    break
    except Exception as e:
        logger.error(f"ZIP Error: {e}")

    return size, ts, file_hash, exe_hash

def build_metadata_json(download_type: str, url: str) -> Optional[Dict]:
    if not download_type.startswith("serverBedrock"):
        return None

    v_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", url)
    version = v_match.group(1) if v_match else "0.0.0.0"

    os_part = download_type[len("serverBedrock"):]
    is_preview = os_part.startswith("Preview")

    os_name = (os_part[7:] if is_preview else os_part).lower()

    size, ts, f_hash, e_hash = compute_hashes(url)

    return {
        "os": os_name,
        "data": {
            "file_name": os.path.basename(url),
            "file_size": size,
            "version": version,
            "url": url,
            "os": os_name,
            "release_type": "preview" if is_preview else "release",
            "last_modified_unix": ts,
            "file_hash": f_hash,
            "file_executable_hash": e_hash
        }
    }

def patch_versions_json_path(release_type: str, version: str):

    with open(SERVER_VERSIONS_JSON_PATH, "r") as f:
        versions_metadata = json.load(f)

    versions_type = versions_metadata.get("version", {}).get("versions", []).get(release_type)

    if version in versions_type:
        logger.info(f"Version {version} already in versions.json for {release_type}. No patch needed.")
        return
    
    versions_type.append(version)
    versions_type.sort(key=lambda v: list(map(int, v.split("."))), reverse=True) 
    versions_metadata["version"]["latest"][release_type] = versions_type[0]

    with open(SERVER_VERSIONS_JSON_PATH, "w") as f:
        json.dump(versions_metadata, f, indent=4)

    logger.info(f"Patched versions.json with version {version} for {release_type}.")

def save_metadata_json(metadata: Dict, target_path: Path):
    os_type = metadata["os"]
    version = metadata["version"]
    out_file = target_path / f"{version}.json"
    
    if out_file.exists():
        with open(out_file, "r") as f:
            full_data = json.load(f)
    else:
        full_data = {"binaries": {}}

    existing_binary = full_data.get("binaries", {}).get(os_type, {})

    if existing_binary.get("file_hash") == metadata.get("file_hash"):
        logger.info(f"Metadata for {version} ({os_type}) is already up to date. Skipping.")
        return

    full_data["binaries"][os_type] = metadata
    target_path.mkdir(parents=True, exist_ok=True)

    with open(out_file, "w") as f:
        json.dump(full_data, f, indent=4)
        
    logger.info(f"Saved metadata for version {version} ({os_type}) at {out_file}")

    patch_versions_json_path(metadata["release_type"], version)

def main():
    try:
        r = requests.get("https://net-secondary.web.minecraft-services.net/api/v1.0/download/links", headers=HEADERS)
        r.raise_for_status()
        links = r.json().get("result", {}).get("links", [])
    except Exception as e:
        logger.error(f"Fetch failed: {e}")
        return

    for link in links:
        res = build_metadata_json(link["downloadType"], link["downloadUrl"])

        if res is None:
            continue

        TARGET_PATH = None

        if res["data"]["release_type"] == "preview":
            TARGET_PATH = SERVER_PREVIEW_PATH
        else:
            TARGET_PATH = SERVER_RELEASE_PATH

        save_metadata_json(res["data"], TARGET_PATH)

if __name__ == "__main__":
    main()