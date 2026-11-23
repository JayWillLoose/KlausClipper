"""Gemeinsamer Laufkontext, den jeder Prüfer bekommt."""

from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from klaushackt.netz import SichererClient
from klaushackt.scope import Scope
from klaushackt.wissen import Wissen

IGNORIERTE_ORDNER = {
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__", "dist", "build", ".next",
    ".nuxt", "vendor", "target", ".idea", ".vscode", "coverage", ".pytest_cache", ".mypy_cache",
    "site-packages", ".tox", "klaushackt-daten",
}
CODE_ENDUNGEN = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".php", ".html", ".htm", ".vue", ".svelte",
    ".rb", ".go", ".java", ".kt", ".cs", ".sql", ".sh", ".yml", ".yaml", ".json", ".toml", ".ini",
    ".env", ".cfg", ".conf", ".xml", ".tf", ".dockerfile",
}
MAX_DATEI_BYTES = 1_000_000


@dataclass
class Kontext:
    scope: Scope
    wissen: Wissen
    lauf: int
    client: SichererClient | None
    deadline: float
    log: Callable[[str], None]
    min_schwere: str = "info"
    ki_aktiv: bool = False
    _dateien: list[Path] | None = field(default=None, repr=False)

    def zeit_uebrig(self) -> float:
        return self.deadline - time.monotonic()

    def zeit_um(self) -> bool:
        return self.zeit_uebrig() <= 0

    def dateien(self) -> list[Path]:
        """Alle prüfbaren Quelldateien aus den Scope-Repos (gecacht)."""
        if self._dateien is None:
            gefunden: list[Path] = []
            for repo in self.scope.repos:
                if repo.is_file():
                    gefunden.append(repo)
                    continue
                for wurzel, ordner, dateien in os.walk(repo):
                    ordner[:] = [o for o in ordner if o not in IGNORIERTE_ORDNER]
                    for d in dateien:
                        p = Path(wurzel) / d
                        endung = p.suffix.lower() or ("." + p.name.lower())
                        klein = p.name.lower()
                        if (endung in CODE_ENDUNGEN or klein in ("dockerfile", ".htaccess", "poetry.lock", "composer.lock")
                                or klein.startswith(".env") or (klein.startswith("requirements") and endung == ".txt")):
                            try:
                                if p.stat().st_size <= MAX_DATEI_BYTES:
                                    gefunden.append(p)
                            except OSError:
                                pass
            self._dateien = sorted(gefunden)
        return self._dateien

    def relativ(self, pfad: Path) -> str:
        for repo in self.scope.repos:
            try:
                return str(pfad.relative_to(repo if repo.is_dir() else repo.parent))
            except ValueError:
                continue
        return str(pfad)


def datei_hash(pfad: Path) -> str:
    return hashlib.sha256(pfad.read_bytes()).hexdigest()[:16]


def lies(pfad: Path) -> str:
    return pfad.read_text(encoding="utf-8", errors="replace")


def zeilen_mit_nummer(text: str) -> Iterator[tuple[int, str]]:
    for i, z in enumerate(text.splitlines(), start=1):
        yield i, z
