"""Writes constraints.txt: the exact version of everything the observer image installs.

    make constraints

The versions come from the environment this runs in, i.e. the ones the test suite ran
with: the dependencies in pyproject.toml and everything they pull in. The Dockerfile
installs with `-c constraints.txt`, so an image build cannot pick up a release that
was never tested here.
"""

from __future__ import annotations

import re
import sys
import tomllib
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path

from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[1]
# Markers are judged for the image (Linux), not for the machine that runs this.
IMAGE = {"sys_platform": "linux", "platform_system": "Linux", "os_name": "posix"}
HEADER = """\
# Exact versions of the runtime dependencies, used by the Dockerfile (pip install -c).
# Generated from the environment the tests ran in. Do not edit: change pyproject.toml
# or upgrade .venv, run the tests, then `make constraints`.
"""


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def wanted(req: Requirement, extras: set[str]) -> bool:
    return req.marker is None or any(req.marker.evaluate({**IMAGE, "extra": e}) for e in extras | {""})


def resolve(requirements: list[str]) -> tuple[dict[str, str], list[str]]:
    pins: dict[str, str] = {}
    missing: list[str] = []
    todo = [Requirement(r) for r in requirements]
    done: set[tuple[str, frozenset[str]]] = set()
    while todo:
        req = todo.pop()
        key = (norm(req.name), frozenset(req.extras))
        if key in done:
            continue
        done.add(key)
        try:
            dist = distribution(req.name)
        except PackageNotFoundError:
            missing.append(req.name)
            continue
        pins[norm(req.name)] = f"{dist.metadata['Name']}=={dist.version}"
        todo += [r for r in map(Requirement, dist.requires or []) if wanted(r, set(req.extras))]
    return pins, missing


def main() -> int:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    pins, missing = resolve(project["dependencies"])
    if missing:
        print(f"not installed here, so not pinned: {', '.join(sorted(set(missing)))}", file=sys.stderr)
    (ROOT / "constraints.txt").write_text(HEADER + "".join(f"{pins[k]}\n" for k in sorted(pins)))
    print(f"constraints.txt: {len(pins)} packages")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
