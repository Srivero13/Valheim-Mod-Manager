import os
import sys
import types
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
for dependency in ("requests", "magic", "paramiko"):
    sys.modules.setdefault(dependency, types.ModuleType(dependency))

from manager import Package


def test_extract_zip_rejects_path_traversal(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    packages = tmp_path / ".cache" / "packages"
    packages.mkdir(parents=True)
    archive = packages / "example-1.0.0.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("plugins/Example/good.dll", b"safe")
        zipped.writestr("../../outside.txt", b"must not escape")

    package = object.__new__(Package)
    package.name = "Example"
    package._extract_zip(archive.name, "client")

    assert (tmp_path / ".cache/client/BepInEx/plugins/Example/good.dll").read_bytes() == b"safe"
    assert not (tmp_path / ".cache/client/BepInEx/outside.txt").exists()
    assert not (tmp_path / "outside.txt").exists()
    assert not (tmp_path.parent / "outside.txt").exists()
