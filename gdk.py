import asyncio
import json
import logging
import os
import sys
import re
import base64
import hashlib
import requests

from xbox.webapi.authentication.manager import AuthenticationManager
from xbox.webapi.authentication.models import OAuth2TokenResponse
from xbox.webapi.common.signed_session import SignedSession
from typing import List, Optional, Tuple, Dict, Any
from email.utils import parsedate_to_datetime
from httpx import HTTPStatusError
from datetime import datetime

from pathlib import Path
from enum import StrEnum

ROOT_PATH = Path(__file__).parent
CLIENT_PATH = ROOT_PATH / "bedrock" / "client"
GDK_RELEASE_PATH = CLIENT_PATH / "release" / "gdk"
GDK_PREVIEW_PATH = CLIENT_PATH / "preview" / "gdk"
CLIENT_VERSIONS_JSON_PATH = CLIENT_PATH / "versions.json"

IS_CI = os.getenv("GITHUB_ACTIONS") == "true"
HEADERS = {"User-Agent": "TorchCS/1.1"}
TOKENS_FILE = Path("tokens.json")

logger = logging.getLogger("BedrockClientFetcher")
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

class MinecraftVersionType(StrEnum):
    RELEASE = "7792d9ce-355a-493c-afbd-768f4a77c3b0"
    PREVIEW = "98bd2335-9b01-4e4c-bd05-ccc01614078b"

async def CreateAuthManager() -> Tuple[AuthenticationManager, SignedSession]:
    session = SignedSession()
    await session.__aenter__()

    auth_mgr = AuthenticationManager(client_session=session, client_id="00000000402b5328", client_secret=None, redirect_uri="https://login.live.com/oauth20_desktop.srf")

    tokens_env_b64 = os.getenv("TOKENS")

    if tokens_env_b64:
        try:
            tokens_json = base64.b64decode(tokens_env_b64).decode("utf-8")
            auth_mgr.oauth = OAuth2TokenResponse.model_validate_json(tokens_json)
        except Exception as e:
            logger.error(f"Failed to decode TOKENS env variable! err={e}")
            await session.__aexit__(None, None, None)
            sys.exit(-1)
    else:
        try:
            with TOKENS_FILE.open("r", encoding="utf-8") as f:
                tokens_raw = f.read()
            auth_mgr.oauth = OAuth2TokenResponse.model_validate_json(tokens_raw)
        except FileNotFoundError as e:
            if IS_CI:
                logger.error(f"{TOKENS_FILE} not found in CI environment! err={e}")
                await session.__aexit__(None, None, None)
                sys.exit(-1)
            logger.info(f"{TOKENS_FILE} not found, doing first-time OAuth flow. err={e}")
            url = auth_mgr.generate_authorization_url()
            logger.info(f"Open in browser and login: {url}")
            authorization_code = input("Enter authorization code> ")
            tokens = await auth_mgr.request_oauth_token(authorization_code)
            auth_mgr.oauth = tokens

    try:
        await auth_mgr.refresh_tokens()
    except HTTPStatusError as e:
        logger.error(f"Failed to refresh tokens! err={e}")
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
    return {"app_id": parts[0], "version": parts[1], "arch": parts[2], "family": parts[3]}

def buildDownloadUrls(pkg: Dict[str, Any]) -> List[str]:
    cdn_roots = pkg.get("CdnRootPaths", [])
    rel = pkg.get("RelativeUrl", "")
    urls: List[str] = []
    for root in cdn_roots:
        urls.append(root + rel)
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

def to_unix_timestamp(value: str) -> Optional[int]:
    if not value:
        return None
    try:
        return int(datetime.fromisoformat(value).timestamp())
    except Exception:
        try:
            return int(parsedate_to_datetime(value).timestamp())
        except Exception:
            return None

def get_formatted_version(version: str) -> str:
    parts = version.split(".")
    if len(parts) != 4:
        return version

    if parts[3] == "70":
        third = parts[2]
        if len(third) <= 2:
            parts[2] = "0"
            parts[3] = str(int(third))
        else:
            parts[2] = str(int(third[:-2]))
            parts[3] = third[-2:]
    elif parts[3] == "0":
        third = parts[2]
        if len(third) <= 2:
            parts[2] = "0"
            parts[3] = str(int(third))
        else:
            parts[2] = str(int(third[:-2]))
            parts[3] = str(int(third[-2:]))

    parts = [str(int(p)) if p.isdigit() else p for p in parts]
    return ".".join(parts)

def resolvePackage(pkg: Dict[str, Any], release_type: str) -> Dict[str, Any]:
    file_name = pkg.get("FileName", "")
    msix_info = parseMsixvcFilename(file_name)

    raw_version = msix_info["version"] if msix_info else ""
    decoded_version = get_formatted_version(raw_version) if raw_version else "unknown"
    arch = msix_info["arch"] if msix_info else resolveArchbyFilename(file_name)

    return {
        "content_id": pkg.get("ContentId"),
        "version_id": pkg.get("VersionId"),
        "file_name": file_name,
        "file_size": pkg.get("FileSize", 0),
        "version": decoded_version,
        "version_raw": raw_version,
        "release_type": release_type,
        "modified_date": pkg.get("ModifiedDate"),
        "modified_unix": to_unix_timestamp(pkg.get("ModifiedDate", "")),
        "arch": arch,
        "app_id": msix_info["app_id"] if msix_info else None,
        "family": msix_info["family"] if msix_info else None,
        "urls": buildDownloadUrls(pkg),
        "file_hash": None,
    }

def sha256_from_url(url: str) -> Optional[str]:
    logger.info(f"Downloading & Hashing: {url}")
    try:
        resp = requests.get(url, stream=True, timeout=60, headers=HEADERS)
        resp.raise_for_status()
        h = hashlib.sha256()
        for chunk in resp.iter_content(1024 * 1024):
            if chunk:
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        logger.error(f"Failed to hash {url}: {e}")
        return None

def load_existing_package(release_type: str, version: str, arch: str) -> Optional[Dict[str, Any]]:
    path = CLIENT_PATH / release_type / "gdk" / f"{version}.json"
    if not path.is_file():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("binaries", {}).get("arch", {}).get(arch)
    except Exception as e:
        logger.error(f"Failed to read {path}: {e}")
        return None

def patch_versions_json(release_type: str, version: str):
    if not CLIENT_VERSIONS_JSON_PATH.is_file():
        logger.warning("versions.json not found, skipping patch")
        return

    with CLIENT_VERSIONS_JSON_PATH.open("r", encoding="utf-8") as f:
        data = json.load(f)

    versions_list: List[str] = data.get("version", {}).get("versions", {}).get("gdk", {}).get(release_type, [])

    if version in versions_list:
        return

    versions_list.append(version)
    versions_list.sort(key=lambda v: [int(x) for x in re.findall(r"\d+", v)], reverse=True)

    data["version"]["versions"]["gdk"][release_type] = versions_list
    data["version"]["latest"]["gdk"][release_type] = versions_list[0] if versions_list else ""

    with CLIENT_VERSIONS_JSON_PATH.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

    logger.info(f"Patched versions.json: gdk/{release_type} += {version}")

def save_package(pkg: Dict[str, Any], release_type: str):
    version = pkg.get("version", "unknown")
    arch = (pkg.get("arch") or "unknown").lower()

    out_dir = CLIENT_PATH / release_type / "gdk"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{version}.json"

    if out_file.is_file():
        with out_file.open("r", encoding="utf-8") as f:
            full_data = json.load(f)
    else:
        full_data = {"binaries": {"arch": {}}}

    existing = full_data.get("binaries", {}).get("arch", {}).get(arch, {})
    if existing.get("file_hash") and existing.get("file_hash") == pkg.get("file_hash"):
        logger.info(f"Metadata for {version} ({arch}) already up to date. Skipping.")
        return

    full_data.setdefault("binaries", {}).setdefault("arch", {})[arch] = pkg

    with out_file.open("w", encoding="utf-8") as f:
        json.dump(full_data, f, indent=4)

    logger.info(f"Saved metadata for {version} ({arch}) at {out_file}")
    patch_versions_json(release_type, version)

async def main():
    auth_mgr, session = await CreateAuthManager()
    try:
        auth_header = await getUpdateAuthorizationHeader(auth_mgr)

        for version_type, release_type in [
            (MinecraftVersionType.RELEASE, "release"),
            (MinecraftVersionType.PREVIEW, "preview"),
        ]:
            resp = await getBasePackageContent(session, version_type, auth_header)
            if not (resp and resp.is_success):
                logger.warning(f"Failed to fetch {release_type} packages")
                continue

            packages = resp.json().get("PackageFiles", [])
            resolved = [
                resolvePackage(pkg, release_type)
                for pkg in packages
                if pkg.get("FileName", "").lower().endswith(".msixvc")
            ]

            logger.info(f"[{release_type}] {len(resolved)} packages fetched")

            for pkg in resolved:
                arch = (pkg.get("arch") or "").lower()
                version = pkg.get("version", "unknown")

                existing = load_existing_package(release_type, version, arch)
                if existing and existing.get("file_hash"):
                    pkg["file_hash"] = existing["file_hash"]
                else:
                    urls = pkg.get("urls") or []
                    if urls:
                        pkg["file_hash"] = sha256_from_url(urls[0])

                save_package(pkg, release_type)
    finally:
        await session.__aexit__(None, None, None)


if __name__ == "__main__":
    asyncio.run(main())
