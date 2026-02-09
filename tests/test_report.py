import re
import shutil
import subprocess
from pathlib import Path

import pytest


def has_pyelftools():
    try:
        import elftools  # noqa: F401
    except ImportError:
        return False
    return True


def build_demo():
    if not has_pyelftools():
        return False
    if not shutil.which("make") or not shutil.which("gcc"):
        return False
    subprocess.check_call(["make", "-C", "demo"])
    return True


def run_structcover(tmp_path):
    elf = Path("demo/build/demo.elf")
    out_dir = tmp_path / "report"
    subprocess.check_call([
        "python3",
        "structcover/structcover.py",
        str(elf),
        "--src-root",
        "demo/src",
        "--out",
        str(out_dir),
    ])
    return out_dir


def test_report_generation(tmp_path):
    if not build_demo():
        pytest.skip("Missing build tools or pyelftools")
    out_dir = run_structcover(tmp_path)
    assert (out_dir / "index.html").exists()
    assert (out_dir / "external" / "index.html").exists()
    file_pages = list((out_dir / "file").rglob("*.html"))
    type_pages = list((out_dir / "type").rglob("*.html"))
    assert file_pages
    assert type_pages


def test_type_page_contains_members(tmp_path):
    if not build_demo():
        pytest.skip("Missing build tools or pyelftools")
    out_dir = run_structcover(tmp_path)
    type_pages = list((out_dir / "type").rglob("*.html"))
    target = None
    for page in type_pages:
        text = page.read_text()
        if "holey_struct" in text:
            target = text
            break
    assert target is not None
    assert "small" in target
    assert "big" in target
    assert "mid" in target
    match = re.search(r"<td>small</td>\s*<td>uint8_t</td>\s*<td>(\d+)</td>", target)
    assert match
    assert int(match.group(1)) == 0
