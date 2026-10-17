"""The gate: a proposed change is kept only if it measurably helps on held-out data."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Decision:
    accepted: bool
    reason: str
    leak_delta: float
    fp_delta: float


def decide(before: dict, after: dict, min_leak_delta: float = 0.05, max_fp_increase: float = 0.05) -> Decision:
    leak_delta = before["leak_rate"] - after["leak_rate"]  # positive = improvement
    fp_delta = after["fp_rate"] - before["fp_rate"]  # positive = regression
    if fp_delta > max_fp_increase:
        return Decision(False, f"rejected: false positive rate rose by {fp_delta:.2f} (limit {max_fp_increase:.2f})", leak_delta, fp_delta)
    if leak_delta < min_leak_delta:
        return Decision(False, f"rejected: leak rate only improved by {leak_delta:.2f} (need {min_leak_delta:.2f})", leak_delta, fp_delta)
    return Decision(True, f"accepted: leak rate down {leak_delta:.2f}, false positives moved {fp_delta:+.2f}", leak_delta, fp_delta)


import subprocess
from pathlib import Path


class GuardRepo:
    """Stages candidate guard files, and either commits them with a generation tag or reverts."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.guard_dir = self.root / "guard"

    def _git(self, *args: str) -> str:
        return subprocess.run(["git", *args], cwd=self.root, check=True, capture_output=True, text=True).stdout.strip()

    def stage(self, rules_yaml: str, prompt_md: str) -> None:
        (self.guard_dir / "rules.yaml").write_text(rules_yaml)
        (self.guard_dir / "prompt.md").write_text(prompt_md)

    def revert(self) -> None:
        self._git("checkout", "--", "guard/")

    def commit(self, tag: str, message: str) -> str:
        self._git("add", "guard/")
        self._git("commit", "-q", "-m", message)
        self._git("tag", "-f", tag)
        return self._git("rev-parse", "--short", "HEAD")

    def current_files(self) -> tuple[str, str]:
        return (self.guard_dir / "rules.yaml").read_text(), (self.guard_dir / "prompt.md").read_text()

    def files_at(self, ref: str) -> tuple[str, str]:
        """Guard files as committed at a git ref (e.g. the gen-0 tag), without touching the working tree."""
        def show(path: str) -> str:
            return subprocess.run(["git", "show", f"{ref}:{path}"], cwd=self.root, check=True, capture_output=True, text=True).stdout
        return show("guard/rules.yaml"), show("guard/prompt.md")
