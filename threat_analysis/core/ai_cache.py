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

"""Per-component AI threat cache for SecOpsTM.

The cache maps a SHA-256 hash of a component's serialised attributes to the raw
threat dicts returned by the LLM.  It is persisted as a JSON file next to the
threat model file so it can be committed to the repository and shared across:

- **Team members** — colleagues skip re-paying the LLM cost for unchanged components.
- **CI/CD pipelines** — pull requests that modify only one component only call the
  LLM for that component; the rest are served from cache.
- **Offline / provider-down runs** — unchanged components still produce AI threats
  even when the LLM is unreachable.
- **Stable threat IDs** — because unchanged components return the same threats,
  ``ReportSerializer`` assigns the same ``T-NNNN`` IDs across analyses, keeping
  SIEM/ticketing integrations stable.

Cache key
---------
The key is the first 20 hex characters of the SHA-256 digest of the component's
``component_details`` dict (serialised as sorted-key JSON).  ``component_details``
includes the component name, type, boundary trust, inbound/outbound flows, security
controls, and all other attributes used to build the LLM prompt — so it captures
exactly what affects the threat output.

Model-level context (system description, sector, compliance) is intentionally
excluded from the key: it affects prompt tone, not the fundamental threat surface
of a component.  This allows a component to be cached once and reused across models
that describe the same topology with different narrative contexts.

Cache file
----------
``.secopstm_ai_cache.json`` — written next to the threat model file.
Can be ``.gitignore``-d for privacy or committed for team sharing.

Usage
-----
::

    cache = AIThreatCache(threat_model._model_file_path)
    h = AIThreatCache.compute_hash(component_details)
    threats = cache.get(h)          # None → miss
    if threats is None:
        threats = await llm_call()
        cache.put(h, name, provider, threats)
    ...
    cache.save()                    # once, after all components processed
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_CACHE_VERSION = 1
_CACHE_FILENAME = ".secopstm_ai_cache.json"


class AIThreatCache:
    """Persistent key-value store for AI-generated threat dicts, keyed by component hash.

    Designed to be instantiated once per analysis run, consulted per component inside
    ``AIService._enrich_with_ai_threats``, and flushed to disk after all components
    have been processed.
    """

    def __init__(self, model_file_path: Optional[Any] = None) -> None:
        """Initialise the cache and load an existing cache file if available.

        Args:
            model_file_path: Path to the threat model file (``str`` or ``Path``).
                The cache file is written to the same directory.  Passing ``None``
                or a non-path value (e.g. a MagicMock) silently disables persistence;
                the cache still works in-memory for the duration of the run.
        """
        self._entries: Dict[str, Dict[str, Any]] = {}
        self._dirty: bool = False
        self._cache_path: Optional[Path] = None
        self.hits: int = 0
        self.misses: int = 0

        if model_file_path and isinstance(model_file_path, (str, Path)):
            try:
                model_path = Path(model_file_path).resolve()
                if model_path.is_file():
                    self._cache_path = model_path.parent / _CACHE_FILENAME
                    self._load()
            except Exception as exc:
                logger.debug("AI cache: could not resolve model path — %s", exc)

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    def _load(self) -> None:
        """Load entries from the cache file (silent on missing file)."""
        if not self._cache_path or not self._cache_path.exists():
            return
        try:
            with self._cache_path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            if data.get("version") != _CACHE_VERSION:
                logger.info(
                    "AI cache: version mismatch (got %s, expected %d) — discarding stale cache",
                    data.get("version"), _CACHE_VERSION,
                )
                return
            self._entries = data.get("entries", {})
            logger.info(
                "AI cache: loaded %d entr%s from %s",
                len(self._entries),
                "y" if len(self._entries) == 1 else "ies",
                self._cache_path.name,
            )
        except Exception as exc:
            logger.warning("AI cache: failed to load %s — %s", self._cache_path, exc)

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    @staticmethod
    def compute_hash(component_details: Dict[str, Any]) -> str:
        """Return a 20-hex-char SHA-256 digest of the component's serialised attributes.

        The digest is deterministic: identical attribute dicts always produce the same
        key, regardless of dict insertion order (``sort_keys=True`` normalises order).
        20 hex chars = 80-bit prefix — collision probability negligible for typical
        model sizes (< 1 000 components).
        """
        canonical = json.dumps(component_details, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:20]

    def get(self, component_hash: str) -> Optional[List[Dict[str, Any]]]:
        """Return cached threat dicts on hit, or ``None`` on miss.

        An empty list ``[]`` is a valid cached value (component was analysed but the
        LLM returned no threats) — this prevents redundant re-calls on subsequent runs.
        """
        entry = self._entries.get(component_hash)
        if entry is not None:
            self.hits += 1
            return entry["threats"]
        self.misses += 1
        return None

    def put(
        self,
        component_hash: str,
        component_name: str,
        provider: str,
        threats: List[Dict[str, Any]],
    ) -> None:
        """Store threat dicts for a component and mark the cache as dirty.

        Args:
            component_hash: Value returned by :meth:`compute_hash`.
            component_name: Human-readable component name (for diagnostics only).
            provider: Name of the LLM provider/class used to generate the threats.
            threats: Raw threat dicts as returned by the LLM (JSON-serialisable).
        """
        self._entries[component_hash] = {
            "component_name": component_name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "provider": provider,
            "threats": threats,
        }
        self._dirty = True

    def save(self) -> None:
        """Flush dirty entries to disk.

        No-op if nothing changed since the last load, or if no cache path is
        configured (model path was not provided at construction time).
        """
        if not self._cache_path or not self._dirty:
            return
        try:
            payload: Dict[str, Any] = {
                "version": _CACHE_VERSION,
                "saved_at": datetime.now(timezone.utc).isoformat(),
                "entries": self._entries,
            }
            with self._cache_path.open("w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, ensure_ascii=False)
            logger.info(
                "AI cache: saved %d entr%s to %s",
                len(self._entries),
                "y" if len(self._entries) == 1 else "ies",
                self._cache_path.name,
            )
        except Exception as exc:
            logger.warning("AI cache: failed to save to %s — %s", self._cache_path, exc)

    # ------------------------------------------------------------------ #
    # Diagnostics                                                          #
    # ------------------------------------------------------------------ #

    @property
    def path(self) -> Optional[Path]:
        """Absolute path of the cache file, or ``None`` if persistence is disabled."""
        return self._cache_path

    @property
    def size(self) -> int:
        """Total number of entries currently in the cache (hits + new misses)."""
        return len(self._entries)

    def summary(self) -> str:
        """Return a human-readable hit/miss summary for the current run."""
        total = self.hits + self.misses
        pct = int(self.hits / total * 100) if total else 0
        return (
            f"{self.hits} hit{'s' if self.hits != 1 else ''} / "
            f"{self.misses} miss{'es' if self.misses != 1 else ''} "
            f"({pct}% served from cache)"
        )
