"""Unit tests for verified, bounded frida-server downloads.

The HTTP layer (``requests.get`` in ``AndroidFridaManager.server_download``)
is replaced by a fake; no network and no device are used. The FridaManager
instance is built via ``__new__`` (skips the ADB-touching constructor).
"""

import hashlib
import logging
import lzma
import os
from unittest.mock import Mock, patch

import pytest
import requests

from AndroidFridaManager import FridaServerDownloadError, FridaServerVerificationError
from AndroidFridaManager import server_download as sd
from AndroidFridaManager.FridaManager import FridaManager

VERSION = "17.24.3"
ASSET = "frida-server-17.24.3-android-arm64.xz"
BINARY = b"\x7fELF fake frida-server " * 64
BODY = lzma.compress(BINARY)
GET = "AndroidFridaManager.server_download.requests.get"


class _FakeResponse:
    def __init__(self, json_data=None, body=b"", headers=None, status=200):
        self._json = json_data
        self._body = body
        self.headers = headers or {}
        self.status = status

    def raise_for_status(self):
        if self.status >= 400:
            raise requests.HTTPError("HTTP {}".format(self.status))

    def json(self):
        return self._json

    def iter_content(self, chunk_size=1):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i:i + chunk_size]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _release(tag=VERSION, digest="sha256:" + hashlib.sha256(BODY).hexdigest()):
    asset = {"name": "frida-server-{}-android-arm64.xz".format(tag)}
    if digest is not None:
        asset["digest"] = digest
    return {"tag_name": tag, "assets": [{"name": "frida-gadget.so", "digest": None}, asset]}


def _fake_get(release=None, body=BODY, headers=None, api_error=None):
    """Mock for requests.get: API URLs return *release*, others stream *body*."""
    def get(url, **kwargs):
        if url.startswith(sd.GITHUB_RELEASES_API):
            if api_error is not None:
                raise api_error
            return _FakeResponse(json_data=release)
        return _FakeResponse(body=body, headers=headers)
    return Mock(side_effect=get)


def _make_fm():
    fm = FridaManager.__new__(FridaManager)
    fm.logger = logging.getLogger("test-afm-download")
    fm.verbose = False
    fm.frida_install_dst = "/data/local/tmp/"
    fm.adb = Mock()
    fm.adb.is_rooted = True
    fm._get_android_device_arch = Mock(return_value="arm64")
    fm._safe_frida_server_pids = Mock(return_value=[])
    fm._adb_remove_file_if_exist = Mock()
    fm.make_frida_server_executable = Mock()
    return fm


@pytest.fixture(autouse=True)
def _no_override_env(monkeypatch):
    for name in sd.ALLOW_UNVERIFIED_ENV_ALIASES:
        monkeypatch.delenv(name, raising=False)


def _download(fm, tmp_path, get_mock, **kwargs):
    with patch(GET, get_mock):
        return fm.download_frida_server(str(tmp_path), VERSION, **kwargs)


class TestDigestVerification:
    def test_matching_digest_writes_file(self, tmp_path):
        path = _download(_make_fm(), tmp_path, _fake_get(_release()))
        assert path == str(tmp_path) + "/frida-server"
        with open(path, "rb") as fh:
            assert fh.read() == BODY
        assert os.listdir(str(tmp_path)) == ["frida-server"]  # no .part left behind

    def test_matching_digest_installs(self, tmp_path):
        fm = _make_fm()
        pushed = {}

        def push(src, dst):
            with open(src, "rb") as fh:
                pushed.update(data=fh.read(), dst=dst)

        fm.adb.push = Mock(side_effect=push)
        with patch(GET, _fake_get(_release())):
            assert fm.install_frida_server(version=VERSION) is True
        assert pushed == {"data": BINARY, "dst": "/data/local/tmp/"}
        fm.make_frida_server_executable.assert_called_once()

    def test_mismatch_deletes_file_and_raises(self, tmp_path):
        release = _release(digest="sha256:" + "0" * 64)
        with pytest.raises(FridaServerVerificationError) as exc:
            _download(_make_fm(), tmp_path, _fake_get(release))
        msg = str(exc.value)
        assert ASSET in msg and "0" * 64 in msg and hashlib.sha256(BODY).hexdigest() in msg
        assert os.listdir(str(tmp_path)) == []

    def test_mismatch_not_overridable(self, tmp_path):
        release = _release(digest="sha256:" + "0" * 64)
        with pytest.raises(FridaServerVerificationError):
            _download(_make_fm(), tmp_path, _fake_get(release), allow_unverified=True)
        assert os.listdir(str(tmp_path)) == []

    def test_mismatch_does_not_install(self):
        fm = _make_fm()
        fm.adb.push = Mock()
        with patch(GET, _fake_get(_release(digest="sha256:" + "1" * 64))):
            with pytest.raises(FridaServerVerificationError):
                fm.install_frida_server(version=VERSION)
        fm.adb.push.assert_not_called()
        fm._adb_remove_file_if_exist.assert_not_called()

    def test_verification_error_is_runtime_error(self):
        # friTap's android.py wraps RuntimeError from install_frida_server().
        assert issubclass(FridaServerVerificationError, RuntimeError)


class TestMissingDigest:
    def test_fails_closed(self, tmp_path):
        with pytest.raises(FridaServerVerificationError) as exc:
            _download(_make_fm(), tmp_path, _fake_get(_release(digest=None)))
        msg = str(exc.value)
        assert ASSET in msg and sd.ALLOW_UNVERIFIED_ENV in msg and "June 2025" in msg
        assert os.listdir(str(tmp_path)) == []

    def test_unknown_digest_algorithm_fails_closed(self, tmp_path):
        with pytest.raises(FridaServerVerificationError):
            _download(_make_fm(), tmp_path, _fake_get(_release(digest="sha512:abcd")))

    def test_metadata_unreachable_fails_closed(self, tmp_path):
        get = _fake_get(api_error=requests.ConnectionError("offline"))
        with pytest.raises(FridaServerVerificationError) as exc:
            _download(_make_fm(), tmp_path, get)
        assert "metadata unavailable" in str(exc.value)
        assert os.listdir(str(tmp_path)) == []

    def test_override_param_proceeds_with_warning(self, tmp_path, caplog):
        with caplog.at_level(logging.WARNING, logger=sd.logger.name):
            path = _download(_make_fm(), tmp_path, _fake_get(_release(digest=None)), allow_unverified=True)
        assert os.path.isfile(path)
        assert "UNVERIFIED" in caplog.text and ASSET in caplog.text

    @pytest.mark.parametrize("env_name", sd.ALLOW_UNVERIFIED_ENV_ALIASES)
    def test_override_env_proceeds(self, tmp_path, monkeypatch, env_name):
        monkeypatch.setenv(env_name, "1")
        path = _download(_make_fm(), tmp_path, _fake_get(_release(digest=None)))
        assert os.path.isfile(path)

    def test_explicit_false_beats_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv(sd.ALLOW_UNVERIFIED_ENV, "1")
        with pytest.raises(FridaServerVerificationError):
            _download(_make_fm(), tmp_path, _fake_get(_release(digest=None)), allow_unverified=False)

    def test_override_with_metadata_unreachable(self, tmp_path):
        get = _fake_get(api_error=requests.ConnectionError("offline"))
        path = _download(_make_fm(), tmp_path, get, allow_unverified=True)
        assert os.path.isfile(path)
        assert get.call_args_list[-1][0][0] == sd.server_asset_url(VERSION, "arm64")

    def test_install_passes_override_through(self):
        fm = _make_fm()
        fm.adb.push = Mock()
        with patch(GET, _fake_get(_release(digest=None))):
            assert fm.install_frida_server(version=VERSION, allow_unverified=True) is True
        fm.adb.push.assert_called_once()


class TestTimeoutsAndTransport:
    def test_every_request_has_timeout(self, tmp_path):
        get = _fake_get(_release())
        _download(_make_fm(), tmp_path, get)
        assert get.call_count == 2
        for call in get.call_args_list:
            assert call[1]["timeout"] == sd.HTTP_TIMEOUT == (10, 60)

    def test_binary_download_streams_raw(self, tmp_path):
        get = _fake_get(_release())
        _download(_make_fm(), tmp_path, get)
        download_kwargs = get.call_args_list[-1][1]
        assert download_kwargs["stream"] is True
        assert download_kwargs["headers"]["Accept-Encoding"] == "identity"

    def test_content_encoded_response_rejected(self, tmp_path):
        get = _fake_get(_release(), headers={"Content-Encoding": "br"})
        with pytest.raises(FridaServerDownloadError, match="Content-Encoding"):
            _download(_make_fm(), tmp_path, get)
        assert os.listdir(str(tmp_path)) == []

    def test_oversize_download_aborted(self, tmp_path):
        asset = sd.ServerAsset(ASSET, "https://example.invalid/x.xz", None, None)
        with patch(GET, _fake_get(body=b"A" * 5000)):
            with pytest.raises(FridaServerDownloadError, match="size cap"):
                sd.download_verified(asset, str(tmp_path / "out.xz"), allow_unverified=True, max_bytes=4096)
        assert os.listdir(str(tmp_path)) == []

    def test_list_available_versions_timeout(self):
        fm = _make_fm()
        with patch("AndroidFridaManager.FridaManager.requests.get") as get:
            get.return_value.json.return_value = [{"tag_name": VERSION}]
            assert fm.list_available_versions() == [VERSION]
        assert get.call_args[1]["timeout"] == sd.HTTP_TIMEOUT

    def test_latest_url_resolver_timeout(self):
        fm = _make_fm()
        with patch("AndroidFridaManager.FridaManager.requests.get") as get:
            get.return_value.text = '"/download/17.24.3/frida-server-17.24.3-android-arm64.xz"'
            url = fm.get_frida_server_for_android_url("latest")
        assert url == sd.server_asset_url(VERSION, "arm64")
        assert get.call_args[1]["timeout"] == sd.HTTP_TIMEOUT


class TestReleaseResolution:
    def test_latest_uses_single_metadata_call(self, tmp_path):
        get = _fake_get(_release(tag="17.30.0", digest="sha256:" + hashlib.sha256(BODY).hexdigest()))
        with patch(GET, get):
            _make_fm().download_frida_server(str(tmp_path), "latest")
        urls = [c[0][0] for c in get.call_args_list]
        assert urls == [sd.GITHUB_RELEASES_API + "/latest", sd.server_asset_url("17.30.0", "arm64")]

    def test_latest_without_metadata_raises(self):
        with patch(GET, _fake_get(api_error=requests.Timeout("slow"))):
            with pytest.raises(FridaServerDownloadError, match="release information"):
                sd.resolve_server_asset("latest", "arm64")

    def test_asset_missing_from_release(self):
        release = {"tag_name": VERSION, "assets": [{"name": "other.xz"}]}
        with patch(GET, _fake_get(release)):
            with pytest.raises(FridaServerDownloadError, match=ASSET):
                sd.resolve_server_asset(VERSION, "arm64")

    @pytest.mark.parametrize("digest,expected", [
        ("sha256:" + "AB" * 32, "ab" * 32),
        ("sha256:" + "ab" * 31, None),
        ("md5:" + "ab" * 16, None),
        ("", None),
        (None, None),
    ])
    def test_parse_sha256_digest(self, digest, expected):
        assert sd.parse_sha256_digest(digest) == expected


class TestBoundedDecompression:
    def test_extract_roundtrip(self, tmp_path):
        xz = tmp_path / "frida-server"
        xz.write_bytes(BODY)
        out = _make_fm().extract_frida_server_comp(str(xz))
        with open(out, "rb") as fh:
            assert fh.read() == BINARY
        assert os.stat(out).st_mode & 0o777 == 0o755
        assert not xz.exists()

    def test_xz_output_cap(self, tmp_path):
        src = tmp_path / "bomb.xz"
        src.write_bytes(lzma.compress(b"\0" * (3 * sd.CHUNK_SIZE)))
        dst = tmp_path / "out" / "frida-server"
        dst.parent.mkdir()
        with pytest.raises(FridaServerDownloadError, match="size cap"):
            sd.decompress_xz_bounded(str(src), str(dst), max_bytes=sd.CHUNK_SIZE)
        assert os.listdir(str(dst.parent)) == []

    def test_extract_honours_max_bytes(self, tmp_path):
        xz = tmp_path / "frida-server"
        xz.write_bytes(BODY)
        with pytest.raises(FridaServerDownloadError):
            _make_fm().extract_frida_server_comp(str(xz), max_bytes=len(BINARY) - 1)
