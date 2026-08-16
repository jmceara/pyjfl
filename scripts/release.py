r"""Verify, build and release `pyjfl` — one command.

    python scripts/release.py                 # verify + build, publish nothing
    python scripts/release.py --push          # ... and push the commit to GitHub
    python scripts/release.py --push --tag    # ... and tag it, which fires the PyPI release

Nothing here uploads to PyPI directly. `.github/workflows/release.yaml` does that, triggered by a
GitHub release, using Trusted Publishing — so no API token exists on this machine to leak. `--tag`
pushes the tag; creating the release from it is the last click, and it is deliberately a click.

Why that split matters: everything up to the tag is reversible, and **a version uploaded to PyPI can
never be reused, even after deleting it**. 0.1.0 is already spent on a package that shipped without
its `py.typed` marker, which is exactly the kind of thing this script exists to catch first.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DIST = REPO / "dist"

GREEN, RED, YELLOW, CYAN, DIM, BOLD, RESET = (
    "\033[32m",
    "\033[31m",
    "\033[33m",
    "\033[36m",
    "\033[2m",
    "\033[1m",
    "\033[0m",
)


class ReleaseError(Exception):
    """A check failed; nothing further should run."""


def step(index: int, total: int, label: str) -> None:
    """Print a step header padded so the markers line up."""
    print(f"[{index}/{total}] {label:.<44}", end=" ", flush=True)


def ok(detail: str = "") -> None:
    """Close a step as passed."""
    print(f"{GREEN}OK{RESET}" + (f" {DIM}{detail}{RESET}" if detail else ""))


def run(cmd: list[str], what: str, cwd: Path = REPO) -> str:
    """Run a command, raising ReleaseError with its output if it fails."""
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        print(f"{RED}FAIL{RESET}")
        raise ReleaseError(f"{what} failed:\n{result.stdout}\n{result.stderr}")
    return result.stdout


def version() -> str:
    """Return the version in pyproject.toml — the one a release would publish."""
    data = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def check_pypi(target: str) -> str:
    """Refuse to build a version that PyPI already has, since it can never be replaced."""
    try:
        with urllib.request.urlopen("https://pypi.org/pypi/pyjfl/json", timeout=20) as response:
            data = json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return "name free — first release"
        return f"could not check ({error.code})"
    except OSError as error:
        return f"could not check ({error})"
    if target in data.get("releases", {}):
        raise ReleaseError(
            f"pyjfl {target} is ALREADY ON PYPI and can never be replaced.\n"
            f"Bump `version` in pyproject.toml. Latest published is {data['info']['version']}."
        )
    return f"latest published is {data['info']['version']}"


def find_python() -> str:
    """Return an interpreter that can import both `build` and `twine`."""
    for candidate in (sys.executable, "python"):
        probe = subprocess.run(
            [candidate, "-c", "import build, twine"], capture_output=True, check=False
        )
        if probe.returncode == 0:
            return candidate
    raise ReleaseError(
        f"`build` and `twine` are not importable.\n"
        f"  {sys.executable} -m pip install --upgrade build twine"
    )


def check_py_typed(wheel: Path) -> None:
    """Fail if the wheel has no PEP 561 marker.

    This is the whole reason 0.1.1 exists. Without `py.typed` every consumer's mypy reports
    `Skipping analyzing "pyjfl"` and silently drops the annotations this package is careful to
    carry — a failure that is invisible at runtime and only shows up in somebody else's type check.
    """
    names = zipfile.ZipFile(wheel).namelist()
    if not any(name.endswith("pyjfl/py.typed") for name in names):
        raise ReleaseError(
            "the wheel has no `pyjfl/py.typed`. Create an empty `src/pyjfl/py.typed`; "
            'hatchling picks it up via `packages = ["src/pyjfl"]`.'
        )


def main() -> int:
    """Run the release sequence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--push", action="store_true", help="push the commit to GitHub")
    parser.add_argument(
        "--tag", action="store_true", help="also push a v<version> tag (implies --push)"
    )
    args = parser.parse_args()
    if args.tag:
        args.push = True

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    target = version()
    total = 7 + (1 if args.push else 0) + (1 if args.tag else 0)
    index = 0
    print(f"\n{BOLD}Releasing pyjfl {target}{RESET}\n")

    index += 1
    step(index, total, "build tooling is available")
    python = find_python()
    ok(Path(python).name)

    index += 1
    step(index, total, f"{target} is not already on PyPI")
    ok(check_pypi(target))

    index += 1
    step(index, total, "test suite")
    output = run([sys.executable, "-m", "pytest", "-q"], "pytest")
    ok(output.strip().splitlines()[-1])

    index += 1
    step(index, total, "ruff")
    run([sys.executable, "-m", "ruff", "check", "."], "ruff")
    ok()

    index += 1
    step(index, total, "mypy --strict")
    run([sys.executable, "-m", "mypy"], "mypy")
    ok()

    index += 1
    step(index, total, "build sdist + wheel")
    if DIST.exists():
        shutil.rmtree(DIST)
    run([python, "-m", "build"], "python -m build")
    files = sorted(p for p in DIST.iterdir() if p.suffix in {".whl", ".gz"})
    wheels = [p for p in files if p.suffix == ".whl"]
    if not any(p.name.endswith(".tar.gz") for p in files):
        raise ReleaseError("no source distribution — Home Assistant's checklist requires one.")
    check_py_typed(wheels[0])
    ok(f"{len(files)} artefacts, py.typed present")

    index += 1
    step(index, total, "twine check")
    run([python, "-m", "twine", "check", *(str(p) for p in files)], "twine check")
    ok()

    if args.push:
        index += 1
        step(index, total, "push to GitHub")
        dirty = run(["git", "status", "--porcelain"], "git status").strip()
        if dirty:
            run(["git", "add", "-A"], "git add")
            run(["git", "commit", "-m", f"Release {target}"], "git commit")
        run(["git", "push", "origin", "HEAD:main"], "git push")
        ok()

    if args.tag:
        index += 1
        step(index, total, f"tag v{target}")
        run(["git", "tag", "-a", f"v{target}", "-m", f"pyjfl {target}"], "git tag")
        run(["git", "push", "origin", f"v{target}"], "git push tag")
        ok()

    print(f"\n  {BOLD}{target}{RESET}")
    for path in files:
        print(f"    {DIM}{path.name}  ({path.stat().st_size:,} bytes){RESET}")

    print(f"\n{BOLD}Next:{RESET}")
    if not args.push:
        print(f"  {DIM}# nothing was pushed — re-run with --push --tag when ready{RESET}")
        print("  python scripts/release.py --push --tag")
    elif not args.tag:
        print(f"  {DIM}# commit is on GitHub; the tag is what a release is cut from{RESET}")
        print("  python scripts/release.py --push --tag")
    else:
        print(f"  github.com/jmceara/pyjfl/releases/new?tag=v{target}")
        print(f"  {DIM}Publish the release — that fires .github/workflows/release.yaml,{RESET}")
        print(f"  {DIM}which uploads to PyPI via Trusted Publishing. No token involved.{RESET}")
        print(f"\n  {DIM}Then in JFL_ALARM: pin pyjfl=={target} in manifest.json.{RESET}")
    print()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseError as error:
        print(f"\n{RED}stopped:{RESET} {error}\n", file=sys.stderr)
        raise SystemExit(1) from None
    except KeyboardInterrupt:
        print(f"\n{RED}cancelled.{RESET}\n", file=sys.stderr)
        raise SystemExit(130) from None
