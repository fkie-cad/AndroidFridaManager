#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Verified, bounded frida-server downloads.

The expected SHA-256 is the ``digest`` field (``"sha256:<hex>"``) that GitHub
computes for every release asset when it is uploaded. GitHub records it for
releases published from June 2025 on (frida >= 17.1.0); frida publishes no
checksum files of its own.

Downloads are streamed into a temp file next to the destination, hashed
while streaming, size-capped, and only renamed into place once the digest
matches. A missing digest fails closed unless unverified downloads are
explicitly allowed; a mismatching digest always fails.
"""

import collections
import hashlib
import logging
import lzma
import os
import re
import tempfile
from typing import Iterable, Optional

import requests

GITHUB_RELEASES_API = "https://api.github.com/repos/frida/frida/releases"
GITHUB_DOWNLOAD_PREFIX = "https://github.com/frida/frida/releases/download"

# (connect, read) timeout in seconds, used for every request.
HTTP_TIMEOUT = (10, 60)
CHUNK_SIZE = 1024 * 1024
MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024
MAX_DECOMPRESSED_BYTES = 512 * 1024 * 1024

ALLOW_UNVERIFIED_ENV = "AFM_ALLOW_UNVERIFIED_SERVER"
# friTap drives AFM for Android; honour its override too.
ALLOW_UNVERIFIED_ENV_ALIASES = (ALLOW_UNVERIFIED_ENV, "FRITAP_ALLOW_UNVERIFIED_SERVER")
_TRUTHY = ("1", "true", "yes", "on")
_SHA256_DIGEST_RE = re.compile(r"^sha256:([0-9a-fA-F]{64})$")

logger = logging.getLogger(__name__)

ServerAsset = collections.namedtuple("ServerAsset", ["name", "url", "sha256", "unavailable_reason"])


class FridaServerDownloadError(RuntimeError):
    """A frida-server download failed (missing asset, size cap exceeded, ...)."""


class FridaServerVerificationError(FridaServerDownloadError):
    """A frida-server download has no usable digest or its digest does not match."""


def allow_unverified_from_env() -> bool:
    """True if any of the override env vars is set to a truthy value."""
    return any(
        os.environ.get(name, "").strip().lower() in _TRUTHY
        for name in ALLOW_UNVERIFIED_ENV_ALIASES
    )


def resolve_allow_unverified(explicit: Optional[bool]) -> bool:
    """An explicit argument wins; ``None`` defers to the environment."""
    return allow_unverified_from_env() if explicit is None else bool(explicit)


def server_asset_name(version: str, arch: str) -> str:
    return "frida-server-" + version + "-android-" + arch + ".xz"


def server_asset_url(version: str, arch: str) -> str:
    return GITHUB_DOWNLOAD_PREFIX + "/" + version + "/" + server_asset_name(version, arch)


def fetch_release_metadata(version: str) -> dict:
    """Return GitHub's release JSON for *version* (a tag or ``"latest"``)."""
    suffix = "/latest" if version == "latest" else "/tags/" + version
    res = requests.get(
        GITHUB_RELEASES_API + suffix,
        timeout=HTTP_TIMEOUT,
        headers={"Accept": "application/vnd.github+json"},
    )
    res.raise_for_status()
    return res.json()


def parse_sha256_digest(digest: Optional[str]) -> Optional[str]:
    """``"sha256:<hex>"`` -> lowercase hex; anything else -> None."""
    match = _SHA256_DIGEST_RE.match(digest or "")
    return match.group(1).lower() if match else None


def release_asset_sha256(release: dict, asset_name: str) -> Optional[str]:
    """Expected SHA-256 of *asset_name* in *release*, or None if it has no digest.

    :raises FridaServerDownloadError: if the release does not contain the asset.
    """
    for asset in release.get("assets") or []:
        if asset.get("name") == asset_name:
            return parse_sha256_digest(asset.get("digest"))
    raise FridaServerDownloadError(
        "frida release {} has no asset named {}".format(release.get("tag_name", "?"), asset_name)
    )


def resolve_server_asset(version: str, arch: str) -> ServerAsset:
    """Look up name, URL and expected SHA-256 of the frida-server asset.

    The release metadata is fetched once and used for both the version
    (``"latest"``) and the digest. If it cannot be fetched for a pinned
    version, the asset is returned without a digest so that the caller's
    fail-closed check decides; ``"latest"`` cannot be resolved without it.
    """
    try:
        release = fetch_release_metadata(version)
    except (requests.RequestException, ValueError) as exc:
        if version == "latest":
            raise FridaServerDownloadError(
                "Failed to fetch Frida release information: {}".format(exc)
            ) from exc
        logger.warning("Could not fetch frida %s release metadata: %s", version, exc)
        return ServerAsset(server_asset_name(version, arch), server_asset_url(version, arch),
                           None, "release metadata unavailable ({})".format(exc))
    tag = release.get("tag_name") or version
    name = server_asset_name(tag, arch)
    sha256 = release_asset_sha256(release, name)
    reason = None if sha256 else "GitHub publishes no sha256 digest for this asset"
    return ServerAsset(name, server_asset_url(tag, arch), sha256, reason)


def enforce_digest(asset: ServerAsset, actual_sha256: str, allow_unverified: bool) -> bool:
    """Fail unless *actual_sha256* matches the asset's expected digest.

    :return: True if verified, False if accepted unverified (override set).
    :raises FridaServerVerificationError: on a mismatch, or a missing digest
        without the override.
    """
    if asset.sha256 is None:
        return _accept_unverified(asset, actual_sha256, allow_unverified)
    if asset.sha256 != actual_sha256.lower():
        raise FridaServerVerificationError(
            "SHA-256 mismatch for {}: expected {}, got {}. The download was deleted; "
            "it may be corrupted or tampered with.".format(asset.name, asset.sha256, actual_sha256)
        )
    logger.info("SHA-256 verified for %s: %s", asset.name, actual_sha256)
    return True


def _accept_unverified(asset: ServerAsset, actual_sha256: str, allow_unverified: bool) -> bool:
    reason = asset.unavailable_reason or "no digest available"
    if not allow_unverified:
        raise FridaServerVerificationError(
            "Refusing to install {}: no expected SHA-256 ({}); downloaded file had sha256 {} "
            "and was deleted. GitHub only records asset digests for releases published from "
            "June 2025 on (frida >= 17.1.0). To install an older frida-server anyway, set {}=1 "
            "or pass allow_unverified=True.".format(asset.name, reason, actual_sha256, ALLOW_UNVERIFIED_ENV)
        )
    logger.warning(
        "!!! INSTALLING UNVERIFIED frida-server %s (%s; override %s is set). sha256 of the "
        "download: %s -- check it manually. Expected for frida releases older than June 2025. !!!",
        asset.name, reason, ALLOW_UNVERIFIED_ENV, actual_sha256,
    )
    return False


def download_verified(asset: ServerAsset, dest_path: str, allow_unverified: bool = False,
                      max_bytes: int = MAX_DOWNLOAD_BYTES) -> str:
    """Stream *asset* to *dest_path*, verifying its digest before the final rename.

    On any failure the partial/unverified file is deleted.

    :return: The hex SHA-256 of the downloaded file.
    """
    fd, part_path = tempfile.mkstemp(prefix=".frida-server-", suffix=".part",
                                     dir=os.path.dirname(os.path.abspath(dest_path)))
    try:
        with os.fdopen(fd, "wb") as out:
            actual = _stream_to_file(asset, out, max_bytes)
        enforce_digest(asset, actual, allow_unverified)
        os.replace(part_path, dest_path)
    except BaseException:
        _remove_quietly(part_path)
        raise
    return actual


def _stream_to_file(asset: ServerAsset, out, max_bytes: int) -> str:
    """Write the response body to *out* without content decoding; return its SHA-256."""
    digest = hashlib.sha256()
    with requests.get(asset.url, stream=True, timeout=HTTP_TIMEOUT,
                      headers={"Accept-Encoding": "identity"}) as res:
        res.raise_for_status()
        _reject_content_encoding(res, asset.name)
        _write_capped(res.iter_content(chunk_size=CHUNK_SIZE), out, max_bytes,
                      "download of " + asset.name, digest)
    return digest.hexdigest()


def _reject_content_encoding(res, asset_name: str) -> None:
    """requests would transparently decode gzip/br/...; the binary must arrive raw."""
    encoding = (res.headers.get("Content-Encoding") or "identity").strip().lower()
    if encoding != "identity":
        raise FridaServerDownloadError(
            "Refusing {}: server sent Content-Encoding {!r} despite Accept-Encoding: identity".format(
                asset_name, encoding)
        )


def decompress_xz_bounded(src_path: str, dst_path: str,
                          max_bytes: int = MAX_DECOMPRESSED_BYTES) -> int:
    """Decompress the .xz at *src_path* to *dst_path*, aborting above *max_bytes*.

    :return: Number of decompressed bytes written.
    """
    fd, part_path = tempfile.mkstemp(prefix=".frida-server-", suffix=".part",
                                     dir=os.path.dirname(os.path.abspath(dst_path)))
    try:
        with os.fdopen(fd, "wb") as out, lzma.open(src_path, "rb") as src:
            chunks = iter(lambda: src.read(CHUNK_SIZE), b"")
            total = _write_capped(chunks, out, max_bytes, "decompressed " + os.path.basename(src_path))
        os.replace(part_path, dst_path)
    except BaseException:
        _remove_quietly(part_path)
        raise
    return total


def _write_capped(chunks: Iterable[bytes], out, max_bytes: int, what: str, digest=None) -> int:
    """Copy *chunks* to *out* (updating *digest*); raise once *max_bytes* is exceeded."""
    total = 0
    for chunk in chunks:
        total += len(chunk)
        if total > max_bytes:
            raise FridaServerDownloadError(
                "{} exceeds the size cap of {} bytes; aborted".format(what, max_bytes)
            )
        if digest is not None:
            digest.update(chunk)
        out.write(chunk)
    return total


def _remove_quietly(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass
