# Copyright 2025 ellipse2v
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for the secopstm download-data subcommand."""
import sys
import hashlib
import tarfile
import tempfile
import io
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest


def _invoke_download_data(args, package_dir):
    """Import and run the download_data() helper directly."""
    from threat_analysis.__main__ import download_data
    return download_data(args=args, package_dir=package_dir)


def _make_fake_tarball():
    """Build a minimal tar.gz with one file inside external_data/."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        content = b"fake capec data"
        info = tarfile.TarInfo(name="external_data/capec.json")
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))
    data = buf.getvalue()
    sha256 = hashlib.sha256(data).hexdigest()
    return data, sha256


class TestDownloadData:
    def test_aborts_when_data_exists_without_force(self, tmp_path):
        """Should exit 0 with a message if external_data/ already present and non-empty."""
        ext_dir = tmp_path / "external_data"
        ext_dir.mkdir()
        (ext_dir / "placeholder.txt").write_text("exists")
        with pytest.raises(SystemExit) as exc:
            _invoke_download_data(args=[], package_dir=tmp_path)
        assert exc.value.code == 0

    def test_force_flag_overwrites_existing(self, tmp_path):
        """--force should proceed even if external_data/ already exists."""
        ext_dir = tmp_path / "external_data"
        ext_dir.mkdir()
        tarball_bytes, sha256_hex = _make_fake_tarball()

        def fake_urlopen(req, *a, **kw):
            m = MagicMock()
            url = req if isinstance(req, str) else req.full_url
            if url.endswith(".sha256"):
                m.read.return_value = (sha256_hex + "  external_data.tar.gz\n").encode()
            else:
                m.read.return_value = tarball_bytes
            m.__enter__ = lambda s: s
            m.__exit__ = MagicMock(return_value=False)
            return m

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with pytest.raises(SystemExit) as exc:
                _invoke_download_data(args=["--force"], package_dir=tmp_path)
        assert exc.value.code == 0
        assert (tmp_path / "external_data" / "capec.json").exists()

    def test_sha256_mismatch_exits_nonzero(self, tmp_path):
        """Should exit 1 if downloaded SHA-256 does not match."""
        tarball_bytes, _ = _make_fake_tarball()

        def fake_urlopen(req, *a, **kw):
            m = MagicMock()
            url = req if isinstance(req, str) else req.full_url
            if url.endswith(".sha256"):
                m.read.return_value = b"deadbeef  external_data.tar.gz\n"
            else:
                m.read.return_value = tarball_bytes
            m.__enter__ = lambda s: s
            m.__exit__ = MagicMock(return_value=False)
            return m

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with pytest.raises(SystemExit) as exc:
                _invoke_download_data(args=["--force"], package_dir=tmp_path)
        assert exc.value.code == 1

    def test_happy_path_extracts_files(self, tmp_path):
        """Should extract external_data/ and print success message."""
        tarball_bytes, sha256_hex = _make_fake_tarball()

        def fake_urlopen(req, *a, **kw):
            m = MagicMock()
            url = req if isinstance(req, str) else req.full_url
            if url.endswith(".sha256"):
                m.read.return_value = (sha256_hex + "  external_data.tar.gz\n").encode()
            else:
                m.read.return_value = tarball_bytes
            m.__enter__ = lambda s: s
            m.__exit__ = MagicMock(return_value=False)
            return m

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with pytest.raises(SystemExit) as exc:
                _invoke_download_data(args=[], package_dir=tmp_path)
        assert exc.value.code == 0
        assert (tmp_path / "external_data" / "capec.json").exists()
