from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any
from enum import StrEnum
from datetime import datetime
from email.utils import parsedate_to_datetime
from httpx import HTTPStatusError

import asyncio
import json
import os
import sys
import re
import base64
import hashlib
import requests

from xbox.webapi.authentication.manager import AuthenticationManager
from xbox.webapi.authentication.models import OAuth2TokenResponse
from xbox.webapi.common.signed_session import SignedSession


class MinecraftVersionType(StrEnum):
    RELEASE = "7792d9ce-355a-493c-afbd-768f4a77c3b0"
    PREVIEW = "98bd2335-9b01-4e4c-bd05-ccc01614078b"


ROOT_PATH = Path(__file__).parent
BEDROCK_CLIENT_PATH = ROOT_PATH / "bedrock" / "client" / "gdk"
BEDROCK_CLIENT_RELEASE_PATH = BEDROCK_CLIENT_PATH / "release"
BEDROCK_CLIENT_PREVIEW_PATH = BEDROCK_CLIENT_PATH / "preview"

HEADERS = {
    "User-Agent": "TorchCS/1.1"
}

IS_CI = os.getenv("GITHUB_ACTIONS") == "true"

TOKENS_FILE = Path("tokens.json")

os.makedirs(BEDROCK_CLIENT_RELEASE_PATH, exist_ok=True)
os.makedirs(BEDROCK_CLIENT_PREVIEW_PATH, exist_ok=True)

async def CreateAuthManager() -> Tuple[AuthenticationManager, SignedSession]:
    session = SignedSession()
    await session.__aenter__()

    auth_mgr = AuthenticationManager(
        client_session=session,
        client_id="00000000402b5328",
        client_secret=None,
        redirect_uri="https://login.live.com/oauth20_desktop.srf",
    )

    tokens_env_b64 = os.getenv("TOKENS")

    if tokens_env_b64:
        try:
            tokens_json = base64.b64decode(tokens_env_b64).decode("utf-8")
            auth_mgr.oauth = OAuth2TokenResponse.model_validate_json(tokens_json)
        except Exception as e:
            print(f"Failed to parse TOKENS env: {e}")
            await session.__aexit__(None, None, None)
            sys.exit(-1)
    else:
        try:
            with TOKENS_FILE.open("r", encoding="utf-8") as f:
                tokens_raw = f.read()
            auth_mgr.oauth = OAuth2TokenResponse.model_validate_json(tokens_raw)
        except FileNotFoundError as e:
            if IS_CI:
                print("No TOKENS env and no tokens.json in CI, aborting.")
                await session.__aexit__(None, None, None)
                sys.exit(-1)
            print(f"{TOKENS_FILE} not found, doing first-time OAuth flow. err={e}")
            url = auth_mgr.generate_authorization_url()
            print(f"Open in browser and login: {url}")
            authorization_code = input("Enter authorization code> ")
            tokens = await auth_mgr.request_oauth_token(authorization_code)
            auth_mgr.oauth = tokens

    try:
        await auth_mgr.refresh_tokens()
    except HTTPStatusError as e:
        print(f"Failed to refresh tokens! err={e}")
        await session.__aexit__(None, None, None)
        sys.exit(-1)

    if not IS_CI:
        with TOKENS_FILE.open("w", encoding="utf-8") as f:
            f.write(auth_mgr.oauth.model_dump_json())

    tokens_out_file = os.getenv("TOKENS_OUT_FILE")
    if IS_CI and tokens_out_file:
        new_json = auth_mgr.oauth.model_dump_json()
        new_b64 = base64.b64encode(new_json.encode("utf-8")).decode("ascii")
        with open(tokens_out_file, "w", encoding="utf-8") as f:
            f.write(new_b64)

    return auth_mgr, session

async def getUpdateAuthorizationHeader(auth_mgr: AuthenticationManager) -> str:
    xsts_resp = await auth_mgr.request_xsts_token("http://update.xboxlive.com")
    uhs = xsts_resp.display_claims.xui[0]["uhs"]
    return f"XBL3.0 x={uhs};{xsts_resp.token}"

async def getBasePackageContent(session: SignedSession, version_type: MinecraftVersionType, authorization_header: str):
    return await session.get(
        f"https://packagespc.xboxlive.com/GetBasePackage/{version_type.value}",
        headers={"Authorization": authorization_header},
    )

def parseMsixvcFilename(file_name: str) -> Optional[Dict[str, str]]:
    lower = file_name.lower()
    if not lower.endswith(".msixvc"):
        return None
    base = file_name[:-7]
    parts = [p for p in base.split("_") if p]
    if len(parts) < 4:
        return None
    app_id = parts[0]
    version = parts[1]
    arch = parts[2]
    family = parts[3]
    return {"app_id": app_id, "version": version, "arch": arch, "family": family}

def parseXspFilename(file_name: str) -> Optional[Dict[str, str]]:
    lower = file_name.lower()
    if not lower.endswith(".xsp"):
        return None
    base = file_name[:-4]
    if not base.startswith("update-"):
        return None
    base = base[len("update-"):]
    if "." not in base:
        return None
    version, guid = base.split(".", 1)
    return {"target_version": version, "guid": guid}

def buildDownloadUrls(pkg: Dict[str, Any]) -> List[str]:
    cdn_roots = pkg.get("CdnRootPaths", [])
    rel = pkg.get("RelativeUrl", "")
    urls: List[str] = []
    for root in cdn_roots:
        full = root + rel
        urls.append(full)
        if "assets1.xboxlive.com" in root:
            urls.append(root.replace("assets1.xboxlive.com", "assets1.xboxlive.cn") + rel)
        if "assets2.xboxlive.com" in root:
            urls.append(root.replace("assets2.xboxlive.com", "assets2.xboxlive.cn") + rel)
    return urls

def resolveArchbyFilename(file_name: str) -> str:
    lower = file_name.lower()
    if "_x64_" in lower:
        return "x64"
    if "_x86_" in lower:
        return "x86"
    if "_arm_" in lower:
        return "arm"
    return "unknown"

def buildVersionbyFilename(file_name: str) -> str:
    m = re.search(r"_(\d+\.\d+\.\d+)(\d{2})\.0_", file_name)
    if not m:
        return file_name
    major = m.group(1)
    minor = m.group(2)
    return f"{major}.{minor}"

def to_unix_timestamp(value: str) -> int | None:
    if not value:
        return None
    try:
        return int(datetime.fromisoformat(value).timestamp())
    except Exception:
        try:
            dt = parsedate_to_datetime(value)
            return int(dt.timestamp())
        except Exception:
            return None

def resolvePackage(pkg: Dict[str, Any]) -> Dict[str, Any]:
    file_name = pkg.get("FileName", "")
    size = pkg.get("FileSize", 0)
    content_id = pkg.get("ContentId")
    version_id = pkg.get("VersionId")
    modified = pkg.get("ModifiedDate")
    urls = buildDownloadUrls(pkg)
    msix_info = parseMsixvcFilename(file_name)
    xsp_info = parseXspFilename(file_name)
    version_pretty = buildVersionbyFilename(file_name)
    arch = resolveArchbyFilename(file_name)
    modified_unix = to_unix_timestamp(modified)

    result: Dict[str, Any] = {
        "content_id": content_id,
        "version_id": version_id,
        "file_name": file_name,
        "file_size": size,
        "version": version_pretty,
        "modified_date": modified,
        "modified_unix": modified_unix,
        "arch": arch,
        "urls": urls,
        "file_hash": None,
    }

    if msix_info:
        result["type"] = "full"
        result["app_id"] = msix_info["app_id"]
        result["version_raw"] = msix_info["version"]
        result["arch"] = msix_info["arch"]
        result["family"] = msix_info["family"]
    elif xsp_info:
        result["type"] = "delta"
        result["delta_target_version"] = xsp_info["target_version"]
        result["delta_guid"] = xsp_info["guid"]

    return result

def write_packages_to_disk(root: Path, packages: List[Dict[str, Any]]) -> None:
    for pkg in packages:
        arch = pkg.get("arch", "unknown")
        version = pkg.get("version", "unknown")

        arch_path = root.joinpath(arch)
        if not arch_path.exists():
            os.makedirs(arch_path, exist_ok=True)

        version_path = arch_path.joinpath(version)
        if not version_path.exists():
            os.makedirs(version_path, exist_ok=True)

        metadata_path = version_path.joinpath("metadata.json")
        with metadata_path.open("w", encoding="utf-8") as f:
            f.write(json.dumps(pkg, indent=4))

def parse_version_number(ver: str) -> List[int]:
    return [int(x) for x in re.findall(r"\d+", ver)]

def collect_versions_by_arch(packages: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    buckets: Dict[str, set] = {
        "x64": set(),
        "x86": set(),
        "arm": set(),
    }
    for pkg in packages:
        arch = (pkg.get("arch") or "").lower()
        if arch not in buckets:
            continue
        v = pkg.get("version")
        if v:
            buckets[arch].add(v)
    out: Dict[str, List[str]] = {}
    for arch, s in buckets.items():
        lst = sorted(list(s), key=parse_version_number, reverse=True)
        out[arch] = lst
    return out


def latest_by_arch(arch_map: Dict[str, List[str]]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for arch in ("x64", "x86", "arm"):
        lst = arch_map.get(arch, [])
        result[arch] = lst[0] if lst else ""
    return result


def write_versions_json(release_by_arch: Dict[str, List[str]], preview_by_arch: Dict[str, List[str]], path: Path) -> None:
    data = {
        "latest": {
            "release": latest_by_arch(release_by_arch),
            "preview": latest_by_arch(preview_by_arch),
        },
        "releases": {
            "x64": release_by_arch.get("x64", []),
            "x86": release_by_arch.get("x86", []),
            "arm": release_by_arch.get("arm", []),
        },
        "previews": {
            "x64": preview_by_arch.get("x64", []),
            "x86": preview_by_arch.get("x86", []),
            "arm": preview_by_arch.get("arm", []),
        },
    }
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def sha256_from_url(url: str) -> Optional[str]:

    try:
        with requests.get(url, stream=True, timeout=60, headers=HEADERS) as r:
            r.raise_for_status()
            h = hashlib.sha256()
            for chunk in r.iter_content(1024 * 1024):
                if not chunk:
                    continue
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        print(f"Failed to hash {url}: {e}")
        return None

async def main():
    auth_mgr, session = await CreateAuthManager()
    try:
        auth_header = await getUpdateAuthorizationHeader(auth_mgr)
        release_resp = await getBasePackageContent(session, MinecraftVersionType.RELEASE, auth_header)
        preview_resp = await getBasePackageContent(session, MinecraftVersionType.PREVIEW, auth_header)

        release_resolved: List[Dict[str, Any]] = []
        preview_resolved: List[Dict[str, Any]] = []

        if release_resp and release_resp.is_success:
            release_data = release_resp.json()
            for pkg in release_data.get("PackageFiles", []):
                file_name = pkg.get("FileName", "")
                if file_name.lower().endswith(".msixvc"):
                    release_resolved.append(resolvePackage(pkg))

        if preview_resp and preview_resp.is_success:
            preview_data = preview_resp.json()
            for pkg in preview_data.get("PackageFiles", []):
                file_name = pkg.get("FileName", "")
                if file_name.lower().endswith(".msixvc"):
                    preview_resolved.append(resolvePackage(pkg))

        for pkg in release_resolved:
            urls = pkg.get("urls") or []
            if urls:
                pkg["file_hash"] = sha256_from_url(urls[0])

        for pkg in preview_resolved:
            urls = pkg.get("urls") or []
            if urls:
                pkg["file_hash"] = sha256_from_url(urls[0])

        write_packages_to_disk(BEDROCK_CLIENT_RELEASE_PATH, release_resolved)
        write_packages_to_disk(BEDROCK_CLIENT_PREVIEW_PATH, preview_resolved)

        release_by_arch = collect_versions_by_arch(release_resolved)
        preview_by_arch = collect_versions_by_arch(preview_resolved)
        versions_json_path = BEDROCK_CLIENT_PATH / "versions.json"
        write_versions_json(release_by_arch, preview_by_arch, versions_json_path)

    finally:
        await session.__aexit__(None, None, None)


if __name__ == "__main__":
    asyncio.run(main())
