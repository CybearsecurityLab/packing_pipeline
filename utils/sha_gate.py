"""SHA verification gate for packed-sample production.

Both the CLI runner (``utils/packer_runner.py``) and the GUI runner
(``wrapper/gui_runner.py``) call into a single :class:`ShaGate` instance
per top-level process so a pass-through or a cross-packer duplicate is
detected at the moment of production rather than after the corpus is
already published.

State model
-----------
- ``_input_shas`` -- SHAs of every input that has been primed or registered
  in this process. Used to reject an output that equals any input other
  than the one being packed.
- ``_published_shas_other_packers`` -- SHAs already published under a
  *different* ``packer_dir`` in this process. Used to reject cross-packer
  duplicates.
- ``_published_shas_current_packer`` -- SHAs already published under the
  current ``packer_dir``. Same-packer duplicates are intentionally allowed
  by policy.
- ``published_shas.jsonl`` -- authoritative cross-process state. Reconciled
  against the on-disk tree at construction time using ``size`` + ``mtime_ns``
  so a 30k-file corpus does not require a full rehash on every launch.
- ``manifest.jsonl`` -- append-only provenance log. One row per
  ``verify_pack`` call, regardless of accept/reject. Never authoritative.

The lock guards all state mutation, manifest append, and cache append.
Hashing happens outside the lock so workers can run in parallel; the
collision check and state insertion are atomic together.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

try:
    from .binary_info import get_sha256
except ImportError:  # direct-script launch (e.g. `python utils/sha_gate.py`)
    from binary_info import get_sha256

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable=None, **_kw):
        return iterable if iterable is not None else iter([])


_log = logging.getLogger("sha_gate")


# Directories that must never enter the published-output index.
_EXCLUDED_DIRS = frozenset({
    ".qsyncclient",
    "_temp_build",
    "_audit",
    "_quarantine",
    "_diag",
    "temp",
})


def _reconcile_one(path: str, size: int, mtime_ns: int, packed_root: Path):
    """Worker for ``_reconcile_cache``: hash one file and return its row.

    Returns ``(sha, packer_dir, size, mtime_ns)`` matching the format used
    by the in-memory and on-disk cache, or ``None`` on hash failure.
    """
    try:
        sha = get_sha256(path)
    except OSError:
        return None
    try:
        rel = os.path.relpath(path, packed_root)
        packer_dir = rel.replace("\\", "/").split("/", 1)[0]
    except ValueError:
        packer_dir = ""
    return (sha, packer_dir, size, mtime_ns)


@dataclass(frozen=True)
class GateResult:
    """Outcome of a single ``verify_pack`` call."""

    accepted: bool
    code: str  # "" | "PACK_FAILED_PASSTHROUGH" | "PACK_OUTPUT_MATCHES_OTHER_INPUT" | "PACK_DUP_ACROSS_PACKERS" | "PACK_SHA_GATE_ERROR"
    message: str
    input_sha256: str | None
    output_sha256: str | None


class ShaGate:
    """Shared SHA verification gate for the packing pipelines."""

    def __init__(
        self,
        packed_root: str | Path,
        *,
        pipeline: str,
        audit_dir: str | Path | None = None,
        log_debug: bool = False,
        hash_workers: int = 8,
    ) -> None:
        self._packed_root = Path(packed_root).resolve()
        self._pipeline = pipeline
        self._hash_workers = max(int(hash_workers), 1)
        self._audit_dir = (
            Path(audit_dir).resolve()
            if audit_dir is not None
            else self._packed_root / "_audit"
        )
        self._audit_dir.mkdir(parents=True, exist_ok=True)
        self._cache_path = self._audit_dir / "published_shas.jsonl"
        self._manifest_path = self._audit_dir / "manifest.jsonl"
        self._debug_log_path = self._audit_dir / "gate.log"

        if log_debug:
            self._enable_debug_log()

        self._lock = threading.RLock()
        self._input_shas: set[str] = set()
        self._input_paths_by_sha: dict[str, set[str]] = {}
        # output_path -> (sha, packer_dir, size, mtime_ns)
        self._published_index: dict[str, tuple[str, str, int, int]] = {}

        self._reconcile_cache()

    def _enable_debug_log(self) -> None:
        """Attach one append-mode FileHandler at DEBUG level.

        Idempotent: a second call on the same instance is a no-op.
        """
        if any(isinstance(h, logging.FileHandler) and
               Path(getattr(h, "baseFilename", "")) == self._debug_log_path
               for h in _log.handlers):
            return
        handler = logging.FileHandler(self._debug_log_path, mode="a", encoding="utf-8")
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        handler.setLevel(logging.DEBUG)
        _log.addHandler(handler)
        _log.setLevel(logging.DEBUG)

    # -- public API ----------------------------------------------------------

    def prime_inputs(self, paths: Iterable[str | Path]) -> dict[str, str]:
        """Hash a batch of inputs upfront so an output cannot equal any
        input later in the batch."""
        result: dict[str, str] = {}
        for p in paths:
            sha = self.add_input(p)
            result[str(p)] = sha
        return result

    def add_input(self, path: str | Path) -> str:
        """Register one input. Returns its SHA-256."""
        path = Path(path)
        sha = get_sha256(path)
        with self._lock:
            self._input_shas.add(sha)
            self._input_paths_by_sha.setdefault(sha, set()).add(str(path))
        return sha

    def verify_pack(
        self,
        *,
        input_path: str | Path,
        output_path: str | Path,
        packer_dir: str,
        app: str,
        input_sha256: str | None = None,
    ) -> GateResult:
        """Verify one packed artifact against the gate.

        Returns a :class:`GateResult`. When ``accepted`` is ``False`` the
        caller is responsible for removing ``output_path`` (the gate also
        attempts a best-effort ``unlink`` so a missed caller cleanup does
        not leave bad artifacts on disk).
        """
        output_path = Path(output_path)
        if input_sha256 is None:
            try:
                input_sha256 = get_sha256(input_path)
            except OSError as e:
                return self._gate_error(
                    packer_dir, app, output_path, input_sha256=None,
                    output_sha256=None,
                    reason=f"input hash failed: {e}",
                )

        try:
            output_sha256 = get_sha256(output_path)
        except OSError as e:
            return self._gate_error(
                packer_dir, app, output_path, input_sha256,
                output_sha256=None,
                reason=f"output hash failed: {e}",
            )

        # Lock holds for the entire decision so two workers cannot race
        # into the same SHA being accepted under different packers.
        with self._lock:
            existing_packers = self._other_packers_for_sha(output_sha256, packer_dir)

            if output_sha256 == input_sha256:
                return self._reject(
                    "PACK_FAILED_PASSTHROUGH",
                    packer_dir, app, output_path,
                    input_sha256, output_sha256,
                    "sha_out equals sha_in",
                    None,
                )

            # The current input is in self._input_shas, so check the
            # *other* inputs explicitly to avoid the trivial self-match.
            other_inputs = self._input_shas - {input_sha256}
            if output_sha256 in other_inputs:
                return self._reject(
                    "PACK_OUTPUT_MATCHES_OTHER_INPUT",
                    packer_dir, app, output_path,
                    input_sha256, output_sha256,
                    "sha_out equals another batch input",
                    None,
                )

            if existing_packers:
                return self._reject(
                    "PACK_DUP_ACROSS_PACKERS",
                    packer_dir, app, output_path,
                    input_sha256, output_sha256,
                    "sha_out already published under a different packer",
                    sorted(existing_packers),
                )

            self._publish(output_path, output_sha256, packer_dir)
            self._append_manifest(
                accepted=True,
                packer_dir=packer_dir,
                app=app,
                output_path=output_path,
                input_sha256=input_sha256,
                output_sha256=output_sha256,
                code="",
                reason=None,
            )
            _log.debug(
                "ACCEPT packer=%s app=%s input_sha=%s output_sha=%s",
                packer_dir, app, input_sha256, output_sha256,
            )
            return GateResult(
                accepted=True,
                code="",
                message="",
                input_sha256=input_sha256,
                output_sha256=output_sha256,
            )

    # -- internals -----------------------------------------------------------

    def _other_packers_for_sha(self, sha: str, current_packer_dir: str) -> set[str]:
        out: set[str] = set()
        for path, (s, pdir, _size, _mtime) in self._published_index.items():
            if s == sha and pdir != current_packer_dir:
                out.add(pdir)
        return out

    def _publish(self, output_path: Path, sha: str, packer_dir: str) -> None:
        try:
            st = output_path.stat()
            size = st.st_size
            mtime_ns = st.st_mtime_ns
        except OSError:
            size = -1
            mtime_ns = -1
        key = str(output_path)
        self._published_index[key] = (sha, packer_dir, size, mtime_ns)
        self._append_cache_row(key, sha, packer_dir, size, mtime_ns)

    def _reject(
        self,
        code: str,
        packer_dir: str,
        app: str,
        output_path: Path,
        input_sha256: str | None,
        output_sha256: str | None,
        reason: str,
        existing_packers: list[str] | None,
    ) -> GateResult:
        # Best-effort delete; a missed cleanup is the caller's problem but
        # the gate also tries so a single-orphan artifact cannot survive.
        try:
            output_path.unlink(missing_ok=True)
        except OSError:
            pass
        if existing_packers:
            message = (
                f"{code} packer={packer_dir} app={json.dumps(app, ensure_ascii=False)} "
                f"sha={output_sha256} existing_packers={','.join(existing_packers)}"
            )
        else:
            message = (
                f"{code} packer={packer_dir} app={json.dumps(app, ensure_ascii=False)} "
                f"sha={output_sha256}"
            )
        self._append_manifest(
            accepted=False,
            packer_dir=packer_dir,
            app=app,
            output_path=output_path,
            input_sha256=input_sha256,
            output_sha256=output_sha256,
            code=code,
            reason=reason,
        )
        _log.debug(
            "REJECT code=%s packer=%s app=%s input_sha=%s output_sha=%s reason=%s",
            code, packer_dir, app, input_sha256, output_sha256, reason,
        )
        return GateResult(
            accepted=False,
            code=code,
            message=message,
            input_sha256=input_sha256,
            output_sha256=output_sha256,
        )

    def _gate_error(
        self,
        packer_dir: str,
        app: str,
        output_path: Path,
        input_sha256: str | None,
        output_sha256: str | None,
        reason: str,
    ) -> GateResult:
        try:
            output_path.unlink(missing_ok=True)
        except OSError:
            pass
        message = (
            f"PACK_SHA_GATE_ERROR packer={packer_dir} "
            f"app={json.dumps(app, ensure_ascii=False)} error={json.dumps(reason, ensure_ascii=False)}"
        )
        self._append_manifest(
            accepted=False,
            packer_dir=packer_dir,
            app=app,
            output_path=output_path,
            input_sha256=input_sha256,
            output_sha256=output_sha256,
            code="PACK_SHA_GATE_ERROR",
            reason=reason,
        )
        _log.debug(
            "GATE_ERROR packer=%s app=%s reason=%s", packer_dir, app, reason,
        )
        return GateResult(
            accepted=False,
            code="PACK_SHA_GATE_ERROR",
            message=message,
            input_sha256=input_sha256,
            output_sha256=output_sha256,
        )

    # -- cache + manifest IO -------------------------------------------------

    def _append_cache_row(
        self, path: str, sha: str, packer_dir: str, size: int, mtime_ns: int,
    ) -> None:
        row = {
            "path": path,
            "sha256": sha,
            "size": size,
            "mtime_ns": mtime_ns,
            "packer_dir": packer_dir,
        }
        with self._cache_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    def _append_manifest(
        self,
        *,
        accepted: bool,
        packer_dir: str,
        app: str,
        output_path: Path,
        input_sha256: str | None,
        output_sha256: str | None,
        code: str,
        reason: str | None,
    ) -> None:
        row = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "pipeline": self._pipeline,
            "status": "published" if accepted else "rejected",
            "reason": reason,
            "code": code,
            "packer_dir": packer_dir,
            "app": app,
            "input_sha256": input_sha256,
            "output_sha256": output_sha256,
            "output_path": str(output_path),
        }
        with self._manifest_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    # -- reconciliation ------------------------------------------------------

    def _reconcile_cache(self) -> None:
        """Load ``published_shas.jsonl``, then walk the packed tree once.
        Rows whose ``size`` and ``mtime_ns`` still match keep their cached
        SHA; changed/missing rows are rehashed or dropped. The reconciled
        cache is rewritten atomically.
        """
        cached: dict[str, tuple[str, str, int, int]] = {}
        if self._cache_path.exists():
            try:
                with self._cache_path.open("r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            row = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        path = row.get("path")
                        if not path:
                            continue
                        try:
                            cached[path] = (
                                row["sha256"],
                                row.get("packer_dir", ""),
                                int(row.get("size", -1)),
                                int(row.get("mtime_ns", -1)),
                            )
                        except (KeyError, TypeError, ValueError):
                            continue
            except OSError:
                cached = {}

        live_paths: set[str] = set()
        for root, dirs, files in os.walk(self._packed_root, followlinks=False):
            dirs[:] = sorted(
                d for d in dirs if d.lower() not in _EXCLUDED_DIRS
            )
            for fname in sorted(files):
                if not fname.lower().endswith(".exe"):
                    continue
                full = Path(root) / fname
                live_paths.add(str(full))

        # Bootstrap: if nas_cleanup's inventory.state.json exists alongside
        # the gate's own cache, pre-populate with its rows so a first run
        # on a corpus that was already inventoried does not re-hash 27k
        # files. Rows are validated against current size+mtime before use.
        cleanup_state = self._audit_dir / "inventory.state.json"
        if cleanup_state.exists():
            try:
                with cleanup_state.open("r", encoding="utf-8") as f:
                    cleanup_data = json.load(f)
                for rel, row in cleanup_data.items():
                    full = str(self._packed_root / rel.replace("/", os.sep))
                    if full not in live_paths:
                        continue
                    try:
                        cached[full] = (
                            row["sha256"],
                            row.get("packer_dir", ""),
                            int(row.get("size", -1)),
                            int(row.get("mtime_ns", -1)),
                        )
                    except (KeyError, TypeError, ValueError):
                        continue
            except (OSError, json.JSONDecodeError):
                pass

        # Stat every live file once, then split into "use cache" vs
        # "needs hash" buckets without hashing yet.
        to_hash: list[tuple[str, int, int]] = []
        from_cache = 0
        for path in live_paths:
            try:
                st = os.stat(path)
                size = st.st_size
                mtime_ns = st.st_mtime_ns
            except OSError:
                continue
            cached_row = cached.get(path)
            if (
                cached_row is not None
                and cached_row[2] == size
                and cached_row[3] == mtime_ns
            ):
                from_cache += 1
            else:
                to_hash.append((path, size, mtime_ns))

        _log.info(
            "gate reconcile  total=%d  cache_hits=%d  to_hash=%d",
            len(live_paths), from_cache, len(to_hash),
        )

        # Hash the misses in parallel so the first-time-ever reconcile on
        # a 27k-file corpus doesn't take hours. Lock is unnecessary -- each
        # result writes to its own key in `fresh` and is merged below.
        fresh: dict[str, tuple[str, str, int, int]] = {}
        if to_hash:
            with ThreadPoolExecutor(max_workers=self._hash_workers) as pool:
                futs = {
                    pool.submit(_reconcile_one, path, size, mtime_ns, self._packed_root): path
                    for path, size, mtime_ns in to_hash
                }
                with tqdm(
                    total=len(to_hash),
                    desc="gate-reconcile",
                    unit="file",
                    leave=False,
                ) as bar:
                    for fut in as_completed(futs):
                        r = fut.result()
                        if r is not None:
                            fresh[futs[fut]] = r
                        bar.update(1)
        else:
            print(f"[*] Gate cache hit on all {from_cache} file(s) (no reconcile needed).")

        reconciled: dict[str, tuple[str, str, int, int]] = {}
        for path in live_paths:
            cached_row = cached.get(path)
            try:
                st = os.stat(path)
                size = st.st_size
                mtime_ns = st.st_mtime_ns
            except OSError:
                continue
            if (
                cached_row is not None
                and cached_row[2] == size
                and cached_row[3] == mtime_ns
            ):
                reconciled[path] = cached_row
            elif path in fresh:
                reconciled[path] = fresh[path]

        self._published_index = reconciled

        # Rewrite cache atomically.
        tmp = self._cache_path.with_suffix(".jsonl.tmp")
        try:
            with tmp.open("w", encoding="utf-8") as f:
                for path, (sha, packer_dir, size, mtime_ns) in sorted(reconciled.items()):
                    f.write(json.dumps(
                        {
                            "path": path,
                            "sha256": sha,
                            "size": size,
                            "mtime_ns": mtime_ns,
                            "packer_dir": packer_dir,
                        },
                        ensure_ascii=False,
                    ) + "\n")
            os.replace(tmp, self._cache_path)
        except OSError:
            # Cache rewrite failure is non-fatal -- the in-memory index is
            # authoritative for this process; just leave the on-disk cache
            # in its previous state.
            try:
                tmp.unlink()
            except OSError:
                pass