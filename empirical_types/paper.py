from __future__ import annotations

import stat
import contextlib
import json
import logging
import os
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

import msgspec

from .model import Evidence

_LOG = logging.getLogger(__name__)


PAPER_PAGE_SIZE = 4096
PAPER_SEPARATION_PAGES = 10


@dataclass(frozen=True, slots=True)
class _Block:
    sequence: int
    pid: int
    tid: int
    address: int
    size: int
    layer: int
    frame: int

    @property
    def key(self) -> tuple[int, int, int]:
        return (self.pid, self.layer, self.address)


def _trace_lines(path: Path):
    with path.open("rb") as handle:
        previous = None
        line_no = 0
        for raw in handle:
            if previous is not None:
                yield line_no, previous, False
            line_no += 1
            previous = raw
        if previous is not None:
            yield line_no, previous, True


PAPER_CORE_ENV = "PAPER_CORE_BIN"
PAPER_CORE_DEFAULT = (
    Path(__file__).resolve().parent.parent
    / "classifier_rs" / "target" / "release" / "paper_core"
)
PAPER_NOTES = (
    "Application/packer separation uses the paper's 10-page heuristic; "
    "no original-binary role labels were consumed.",
    "Secondary processes are included only when observed IPC/file/physical "
    "provenance connects them to the protected root process.",
)


class _PaperCoreFallback(Exception):
    pass


def _paper_core_binary() -> Path | None:
    configured = os.environ.get(PAPER_CORE_ENV)
    if configured is not None:
        if configured in {"", "0", "off", "python"}:
            return None
        candidate = Path(configured)
    else:
        candidate = PAPER_CORE_DEFAULT
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return candidate
    return None


def _read_line_at(path: Path, offset: int) -> bytes:
    if stat.S_ISFIFO(path.stat().st_mode):
        raise RuntimeError(f"cannot re-read line at offset {offset} of single-pass stream {path}")
    with path.open("rb") as handle:
        handle.seek(offset)
        return handle.readline()


def _decode_like_reference(line: bytes):
    try:
        return msgspec.json.decode(line)
    except msgspec.DecodeError:
        return json.loads(line.decode("utf-8", errors="strict"))


def _confirm_undecodable(line: bytes, final: bool) -> None:
    try:
        msgspec.json.decode(line)
    except msgspec.DecodeError:
        try:
            json.loads(line.decode("utf-8", errors="strict"))
        except json.JSONDecodeError:
            if final:
                return
            raise
    raise _PaperCoreFallback("reference decoder accepts a line the core rejected")


def _evidence_from_core(path: Path, sample_id: str, report: dict) -> Evidence:
    status = report["status"]
    if status == "fallback":
        raise _PaperCoreFallback(report.get("detail", ""))
    line_no = report.get("line_no")
    if status == "json_error":
        _confirm_undecodable(_read_line_at(path, report["offset"]), False)
    if status == "unknown_event":
        event = _decode_like_reference(_read_line_at(path, report["offset"]))
        kind = event.get("event")
        raise ValueError(f"{path}:{line_no}: unknown event {kind!r}")
    if status == "non_monotonic":
        raise ValueError(f"{path}:{line_no}: non-monotonic global sequence")
    if status == "value_error":
        raise ValueError(report["detail"])
    if status == "key_error":
        raise KeyError(report["detail"])
    if status != "ok":
        raise _PaperCoreFallback(f"unexpected core status {status!r}")
    unparsed = report.get("unparsed_final")
    if unparsed is not None:
        _confirm_undecodable(_read_line_at(path, unparsed["offset"]), True)
    multiframe = report["candidate_multiframe_bytes"]
    total = report["candidate_code_bytes"]
    return Evidence(
        sample_id=sample_id,
        taxonomy_basis="paper_runtime_heuristic",
        original_match_available=False,
        layers=report["layers"],
        processes=report["processes"],
        threads=report["threads"],
        forward_transitions=report["forward_transitions"],
        backward_transitions=report["backward_transitions"],
        original_code_frames=report["original_code_frames"],
        original_multiframe_ratio=multiframe / total if total else None,
        repacked_original_bytes=report["repacked_original_bytes"],
        tail_transition=report["tail_transition"],
        interleaved=report["interleaved"],
        frame_sizes=list(report["frame_sizes"]),
        frame_basic_blocks=list(report["frame_basic_blocks"]),
        candidate_code_bytes=total,
        candidate_multiframe_bytes=multiframe,
        all_code_flagged_packer=report["all_code_flagged_packer"],
        cross_process_activity=report["cross_process_activity"],
        linear_transition_model=report["linear_transition_model"],
        packer_to_application_transitions=report["packer_to_application_transitions"],
        application_to_packer_transitions=report["application_to_packer_transitions"],
        notes=list(PAPER_NOTES),
    )


def _analyze_paper_jsonl_core(binary: Path, path: Path, sample_id: str) -> Evidence:
    completed = subprocess.run(
        [str(binary), str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise _PaperCoreFallback(
            f"core exited with {completed.returncode}: "
            f"{completed.stderr.decode('utf-8', 'replace')[-2000:]}"
        )
    try:
        report = json.loads(completed.stdout)
    except ValueError as error:
        raise _PaperCoreFallback(f"unreadable core report: {error}") from error
    if not isinstance(report, dict) or "status" not in report:
        raise _PaperCoreFallback("malformed core report")
    return _evidence_from_core(path, sample_id, report)


def analyze_paper_jsonl(path: Path, sample_id: str) -> Evidence:
    binary = _paper_core_binary() if isinstance(path, Path) else None
    if binary is not None:
        try:
            return _analyze_paper_jsonl_core(binary, path, sample_id)
        except _PaperCoreFallback as reason:
            if stat.S_ISFIFO(path.stat().st_mode):
                raise RuntimeError(f"paper core failed on single-pass stream {path}: {reason}") from None
            _LOG.warning("paper core fell back to Python for %s: %s", path, reason)
    return _analyze_paper_jsonl_python(path, sample_id)


def _analyze_paper_jsonl_python(path: Path, sample_id: str) -> Evidence:
    """Reconstruct the runtime taxonomy exactly as described by Ugarte et al.

    This path deliberately does not use an original executable or an externally
    supplied ``role`` label.  Application code is inferred using Section III-E:
    code that produces a later execution layer is packer code, and code within
    ten pages of that code in the same layer is conservatively packer code too.
    """

    writer_layer: dict[tuple[int, int], int] = {}
    writers: dict[tuple[int, int], set[tuple[int, int, int]]] = defaultdict(set)
    physical_writer_layer: dict[int, int] = {}
    physical_writers: dict[int, set[tuple[int, int, int]]] = defaultdict(set)
    physical_locations: dict[int, set[tuple[int, int, int]]] = defaultdict(set)
    file_writer_layer: dict[tuple[str, int], int] = {}
    file_writers: dict[tuple[str, int], set[tuple[int, int, int]]] = defaultdict(set)
    state: dict[tuple[int, int, int], str] = {}
    resettable: dict[tuple[int, int], set[int]] = defaultdict(set)
    state_layers: dict[tuple[int, int], set[int]] = defaultdict(set)
    new_frame: dict[tuple[int, int], set[int]] = defaultdict(set)
    frame_number: dict[tuple[int, int], int] = defaultdict(int)
    frame_written: dict[tuple[int, int, int], set[int]] = defaultdict(set)
    frame_blocks: Counter[tuple[int, int, int]] = Counter()
    repacked: set[tuple[int, int, int]] = set()
    blocks: list[_Block] = []
    executed_bytes: dict[tuple[int, int], set[int]] = defaultdict(set)
    packer_blocks: set[tuple[int, int, int]] = set()
    executed_layers: dict[tuple[int, int], set[int]] = defaultdict(set)
    strict_packer_blocks: set[tuple[int, int, int]] = set()
    last_block_by_thread: dict[tuple[int, int], _Block] = {}
    processes: set[int] = set()
    threads: set[tuple[int, int]] = set()
    process_interactions: set[tuple[int, int]] = set()
    root_pid: int | None = None
    max_layer = -1
    last_sequence = -1
    cross_process_activity = False

    def number(value: int | str) -> int:
        return int(value, 0) if isinstance(value, str) else int(value)

    def physical_keys(event: dict, size: int) -> list[int | None]:
        """Expand an exact per-byte RAM mapping, including page crossings."""

        spans = event.get("physical_spans")
        if spans is None:
            base = event.get("physical_address")
            if base is None:
                return [None] * size
            address = number(base)
            return [address + offset for offset in range(size)]

        result: list[int | None] = [None] * size
        for span in spans:
            offset = int(span["offset"])
            span_size = int(span["size"])
            address = number(span["address"])
            if offset < 0 or span_size <= 0 or offset + span_size > size:
                raise ValueError("physical span lies outside its event")
            for relative in range(span_size):
                index = offset + relative
                if result[index] is not None:
                    raise ValueError("physical spans overlap")
                result[index] = address + relative
        if any(value is None for value in result):
            raise ValueError("physical spans do not cover the complete event")
        return result

    def reset_frame(pid: int, layer: int) -> None:
        for address in resettable.pop((pid, layer), ()):
            key = (pid, layer, address)
            value = state[key]
            if value in {"U", "R"}:
                state[key] = "W"
            elif value == "X":
                state[key] = "O"

    def record_written_byte(
        target_pid: int,
        address: int,
        physical_key: int | None,
        source_layer: int,
        source_keys: set[tuple[int, int, int]],
    ) -> None:
        for source_key in source_keys:
            if source_key[0] != target_pid:
                process_interactions.add((source_key[0], target_pid))
        memory_key = (target_pid, address)
        highest = writer_layer.get(memory_key, -1)
        if physical_key is not None:
            physical_layer = physical_writer_layer.get(physical_key, -1)
            if physical_layer > highest:
                highest = physical_layer
        if source_layer > highest:
            highest = source_layer
        writer_layer[memory_key] = highest
        writers[memory_key].update(source_keys)
        affected_locations = {
            (target_pid, layer, address) for layer in state_layers[memory_key]
        }
        affected_locations.add((target_pid, highest + 1, address))
        if physical_key is not None:
            physical_writer_layer[physical_key] = highest
            physical_writers[physical_key].update(source_keys)
            affected_locations.update(physical_locations[physical_key])
        for key in affected_locations:
            if state.get(key) == "U":
                state[key] = "R"
                repacked.add(key)
            elif state.get(key) != "R":
                state[key] = "W"
                resettable[(key[0], key[1])].discard(key[2])
            state_layers[(key[0], key[2])].add(key[1])
            new_frame[(key[0], key[1])].add(key[2])

    def invalidated_physical_keys(event: dict, size: int) -> list[int | None]:
        """Return RAM identities captured before a successful unmap/free.

        Unlike a write event, an invalidation may cover demand-paged holes, so
        these spans are intentionally allowed to be partial.  The tracer
        captures them at the system-call entry while the mapping still exists
        and emits the event only if the call later succeeds.
        """

        result: list[int | None] = [None] * size
        for span in event.get("invalidated_physical_spans", []):
            offset = int(span["offset"])
            span_size = int(span["size"])
            address = number(span["address"])
            if offset < 0 or span_size <= 0 or offset + span_size > size:
                raise ValueError("invalidated physical span lies outside its event")
            for relative in range(span_size):
                index = offset + relative
                if result[index] is not None:
                    raise ValueError("invalidated physical spans overlap")
                result[index] = address + relative
        return result

    def invalidate_byte(
        target_pid: int,
        address: int,
        physical_key: int | None,
        source_key: tuple[int, int, int] | None,
    ) -> None:
        """Apply the paper's unmap/free-as-repacking semantics.

        Invalidation removes visibility; it does not manufacture new code.
        Therefore it updates the shadow states and identifies the responsible
        routine as packer code, but it must not become a writer that raises the
        layer of a later, unrelated mapping at the same address.
        """

        memory_key = (target_pid, address)
        affected_locations = {
            (target_pid, layer, address)
            for layer in state_layers.get(memory_key, set())
        }
        if physical_key is not None:
            affected_locations.update(physical_locations.get(physical_key, set()))
        for key in affected_locations:
            previous = state.get(key, "O")
            if previous == "U":
                state[key] = "R"
                repacked.add(key)
            elif previous != "R":
                state[key] = "W"
                resettable[(key[0], key[1])].discard(key[2])
            new_frame[(key[0], key[1])].add(key[2])
            if (
                source_key is not None
                and key[1] != source_key[1]
                and key[1] in executed_layers.get((key[0], key[2]), ())
            ):
                packer_blocks.add(source_key)
                strict_packer_blocks.add(source_key)

        writer_layer.pop(memory_key, None)
        writers.pop(memory_key, None)
        if physical_key is not None:
            physical_writer_layer.pop(physical_key, None)
            physical_writers.pop(physical_key, None)
            physical_locations.pop(physical_key, None)

    # A run killed at the host timeout is killed MID-WRITE, so the final line is a
    # partial JSON object. That is an artifact of terminating QEMU, not corruption,
    # and it must not discard an otherwise good multi-GB trace -- at a 600 s budget
    # essentially every malware sample ends this way, so an unguarded json.loads here
    # fails 100% of the campaign. A partial line ANYWHERE ELSE is real corruption and
    # still raises.
    decode = msgspec.json.decode
    with contextlib.nullcontext():
        file_version: dict[tuple[str, int], int] = {}
        mapped_applied: dict[tuple[int, int], tuple] = {}
        for line_no, line, final in _trace_lines(path):
            if not line.strip():
                continue
            try:
                event = decode(line)
            except msgspec.DecodeError:
                try:
                    event = json.loads(line.decode("utf-8", errors="strict"))
                except json.JSONDecodeError:
                    if final:
                        break
                    raise
            if "seq" in event:
                sequence = int(event["seq"])
                if sequence <= last_sequence:
                    raise ValueError(
                        f"{path}:{line_no}: non-monotonic global sequence"
                    )
                last_sequence = sequence
            kind = event.get("event")
            if kind == "marker" and int(event.get("action", 0)) == 1:
                root_pid = int(event["pid"])
            elif kind == "root_image":
                root_pid = int(event["pid"])
            if kind == "process" and str(event.get("reason", "")) != "root_marker":
                cross_process_activity = True
            elif (
                kind == "descendant_debug"
                and event.get("after_cutoff") is True
                and (
                    event.get("job_matches") is True
                    or (
                        root_pid is not None
                        and event.get("parent_pid") == root_pid
                    )
                )
            ):
                cross_process_activity = True
            if kind in {
                "process",
                "prestart_exec",
                "root_image",
                "sample_start",
                "trace_start",
                "marker",
                "register_handles",
                "exception_dispatch",
                "exception_recovered",
                "descendant_debug",
                "root_debug",
                "summary",
                "evasion_check",
            }:
                continue
            if kind not in {
                "exec",
                "write",
                "invalidate",
                "unmap",
                "free",
                "file_write",
                "file_read",
            }:
                raise ValueError(f"{path}:{line_no}: unknown event {kind!r}")
            if event.get("role") == "system":
                continue

            pid = int(event["pid"])
            tid = int(event["tid"])
            if kind == "file_write":
                source = last_block_by_thread.get((pid, tid))
                if source is None:
                    continue
                file_id = str(event["file_id"])
                file_offset = number(event["file_offset"])
                size = int(event.get("size", 1))
                for offset in range(size):
                    key = (file_id, file_offset + offset)
                    file_writer_layer[key] = max(
                        file_writer_layer.get(key, -1), source.layer
                    )
                    file_writers[key].add(source.key)
                    file_version[key] = file_version.get(key, 0) + 1
                continue

            address = number(event["address"])
            size = int(event.get("size", 1))
            processes.add(pid)
            threads.add((pid, tid))

            if kind in {"invalidate", "unmap", "free"}:
                target_pid = int(event.get("target_pid", pid))
                processes.add(target_pid)
                source = last_block_by_thread.get((pid, tid))
                invalidated_keys = invalidated_physical_keys(event, size)
                for offset in range(size):
                    invalidate_byte(
                        target_pid,
                        address + offset,
                        invalidated_keys[offset],
                        source.key if source is not None else None,
                    )
                continue

            event_physical_keys = physical_keys(event, size)

            if kind == "file_read":
                target_pid = int(event.get("target_pid", pid))
                file_id = str(event["file_id"])
                file_offset = number(event["file_offset"])
                for offset in range(size):
                    file_key = (file_id, file_offset + offset)
                    source_keys = file_writers.get(file_key, set())
                    if not source_keys:
                        continue
                    record_written_byte(
                        target_pid,
                        address + offset,
                        event_physical_keys[offset],
                        file_writer_layer[file_key],
                        source_keys,
                    )
                continue

            if kind == "write":
                target_pid = int(event.get("target_pid", pid))
                processes.add(target_pid)
                source = last_block_by_thread.get((pid, tid))
                source_layer = int(
                    event.get(
                        "source_layer", source.layer if source is not None else 0
                    )
                )
                source_key = source.key if source is not None else None
                for offset in range(size):
                    physical_key = event_physical_keys[offset]
                    record_written_byte(
                        target_pid,
                        address + offset,
                        physical_key,
                        source_layer,
                        {source_key} if source_key is not None else set(),
                    )
                continue

            memory_keys = [(pid, address + offset) for offset in range(size)]
            block_physical_keys = event_physical_keys
            if event.get("file_id") is not None:
                file_id = str(event["file_id"])
                file_offset = number(event["file_offset"])
                for offset in range(size):
                    file_key = (file_id, file_offset + offset)
                    source_keys = file_writers.get(file_key, set())
                    applied = (file_key, file_version.get(file_key, 0))
                    if source_keys and mapped_applied.get(
                            (pid, address + offset)) != applied:
                        mapped_applied[(pid, address + offset)] = applied
                        record_written_byte(
                            pid,
                            address + offset,
                            block_physical_keys[offset],
                            file_writer_layer[file_key],
                            source_keys,
                        )
            def _byte_layer(memory_key: tuple[int, int],
                            physical_key: int | None) -> int:
                virtual = writer_layer.get(memory_key, -1)
                physical = -1
                if physical_key is not None and any(
                    source[0] != pid
                    for source in physical_writers.get(physical_key, ())
                ):
                    physical = physical_writer_layer.get(physical_key, -1)
                return max(virtual, physical) + 1

            layer = max(
                (
                    _byte_layer(memory_key, physical_key)
                    for memory_key, physical_key in zip(
                        memory_keys, block_physical_keys, strict=True
                    )
                ),
                default=0,
            )
            max_layer = max(max_layer, layer)
            layer_key = (pid, layer)
            state_keys = [(pid, layer, address + offset) for offset in range(size)]
            starts_frame = any(
                state.get(key) in {"W", "R"} and key[2] in new_frame[layer_key]
                for key in state_keys
            )
            if starts_frame:
                frame_number[layer_key] += 1
                frame_key = (pid, layer, frame_number[layer_key])
                frame_written[frame_key].update(new_frame[layer_key])
                reset_frame(pid, layer)
                new_frame[layer_key].clear()

            block = _Block(
                sequence=len(blocks),
                pid=pid,
                tid=tid,
                address=address,
                size=size,
                layer=layer,
                frame=frame_number[layer_key],
            )
            blocks.append(block)
            last_block_by_thread[(pid, tid)] = block
            frame_blocks[(pid, layer, block.frame)] += 1
            executed_bytes[layer_key].update(range(address, address + size))
            for memory_key, physical_key, state_key in zip(
                memory_keys, block_physical_keys, state_keys, strict=True
            ):
                memory_writers = writers.get(memory_key)
                byte_writers = set(memory_writers) if memory_writers else set()
                cross_process_physical_writer = False
                if physical_key is not None:
                    for source in physical_writers.get(physical_key, set()):
                        if source[0] != pid:
                            byte_writers.add(source)
                            cross_process_physical_writer = True
                for source_key in byte_writers:
                    if source_key[0] != pid:
                        process_interactions.add((source_key[0], pid))
                if byte_writers:
                    packer_blocks.update(byte_writers)
                    strict_packer_blocks.update(byte_writers)
                state[state_key] = (
                    "U"
                    if memory_key in writer_layer or cross_process_physical_writer
                    else "X"
                )
                resettable[(pid, layer)].add(state_key[2])
                state_layers[memory_key].add(layer)
                executed_layers[memory_key].add(layer)
                if physical_key is not None:
                    physical_locations[physical_key].add(state_key)

    for memory_key, source_blocks in writers.items():
        destination_layers = executed_layers.get(memory_key, set())
        for source_key in source_blocks:
            if any(layer != source_key[1] for layer in destination_layers):
                packer_blocks.add(source_key)
                strict_packer_blocks.add(source_key)

    if root_pid is None and blocks:
        root_pid = blocks[0].pid
    relevant_pids = {root_pid} if root_pid is not None else set()
    changed = True
    while changed:
        changed = False
        for left, right in process_interactions:
            if left in relevant_pids and right not in relevant_pids:
                relevant_pids.add(right)
                changed = True
            elif right in relevant_pids and left not in relevant_pids:
                relevant_pids.add(left)
                changed = True
    relevant_blocks = [block for block in blocks if block.pid in relevant_pids]

    packer_pages: dict[tuple[int, int], set[int]] = defaultdict(set)
    for pid, layer, address in packer_blocks:
        if pid in relevant_pids:
            packer_pages[(pid, layer)].add(address // PAPER_PAGE_SIZE)

    candidate_bytes: dict[tuple[int, int], set[int]] = defaultdict(set)
    candidate_blocks: set[tuple[int, int, int]] = set()
    for block in relevant_blocks:
        if block.key in packer_blocks:
            continue
        page = block.address // PAPER_PAGE_SIZE
        too_close = any(
            abs(page - packer_page) < PAPER_SEPARATION_PAGES
            for packer_page in packer_pages[(block.pid, block.layer)]
        )
        if too_close:
            packer_blocks.add(block.key)
            continue
        candidate_blocks.add(block.key)
        candidate_bytes[(block.pid, block.layer)].update(
            range(block.address, block.address + block.size)
        )

    total_candidate = sum(len(value) for value in candidate_bytes.values())
    all_code_packer = bool(relevant_blocks) and total_candidate == 0

    transitions = [
        (left.layer, right.layer)
        for left, right in zip(relevant_blocks, relevant_blocks[1:], strict=False)
        if left.layer != right.layer
    ]
    forward = sum(right > left for left, right in transitions)
    backward = sum(right < left for left, right in transitions)
    relevant_max_layer = max(
        (block.layer for block in relevant_blocks), default=-1
    )
    raw_linear = backward == 0 and len(transitions) == max(relevant_max_layer, 0)
    tail_index = next(
        (i for i, b in enumerate(relevant_blocks) if b.layer == relevant_max_layer),
        None,
    )
    topology_tail = False
    if tail_index is not None and relevant_max_layer >= 1:
        prefix = relevant_blocks[: tail_index + 1]
        unpack_chain = [
            (left.layer, right.layer)
            for left, right in zip(prefix, prefix[1:], strict=False)
            if left.layer != right.layer
        ]
        linear_topology = unpack_chain == [
            (i, i + 1) for i in range(relevant_max_layer)
        ]
        clean = all(
            block.key not in strict_packer_blocks
            for block in relevant_blocks[tail_index:]
        )
        topology_tail = linear_topology and clean
    linear = raw_linear or topology_tail

    roles = [
        "application" if block.key in candidate_blocks else "packer"
        for block in relevant_blocks
    ]
    role_transitions = [
        (left, right)
        for left, right in zip(roles, roles[1:], strict=False)
        if left != right
    ]
    packer_to_app = role_transitions.count(("packer", "application"))
    app_to_packer = role_transitions.count(("application", "packer"))
    tail = (packer_to_app == 1 and app_to_packer == 0) or topology_tail
    interleaved = not tail and not all_code_packer

    byte_frames: dict[tuple[int, int, int], set[int]] = defaultdict(set)
    for (frame_pid, frame_layer, frame), written in frame_written.items():
        layer_candidates = candidate_bytes.get((frame_pid, frame_layer))
        if layer_candidates:
            for byte in written & layer_candidates:
                byte_frames[(frame_pid, frame_layer, byte)].add(frame)
    candidate_multiframe = 0
    for (layer_pid, layer), addresses in candidate_bytes.items():
        region: list[int] = []
        region_frames: set[int] = set()
        for byte in sorted(addresses) + [None]:
            if byte is None or (region and byte - region[-1] > 10 * 4096):
                if len(region_frames) > 1:
                    candidate_multiframe += len(region)
                region, region_frames = [], set()
            if byte is not None:
                region.append(byte)
                region_frames |= byte_frames.get((layer_pid, layer, byte), set())
    ratio = candidate_multiframe / total_candidate if total_candidate else None

    candidate_frames: set[tuple[int, int, int]] = set()
    for block in relevant_blocks:
        if block.key in candidate_blocks:
            candidate_frames.add((block.pid, block.layer, block.frame))
    executed_pages: dict[tuple[int, int], set[int]] = defaultdict(set)
    for block in blocks:
        for page in range(block.address >> 12, ((block.address + block.size - 1) >> 12) + 1):
            executed_pages[(block.pid, block.layer)].add(page)
    sizes = [
        sum(1 for byte in frame_written[key]
            if byte >> 12 in executed_pages[(key[0], key[1])])
        for key in sorted(candidate_frames)
    ]
    basic_blocks = [frame_blocks[key] for key in sorted(candidate_frames)]
    repacked_candidate = {
        key
        for key in repacked
        if key[2] in candidate_bytes.get((key[0], key[1]), set())
    }

    return Evidence(
        sample_id=sample_id,
        taxonomy_basis="paper_runtime_heuristic",
        original_match_available=False,
        layers=relevant_max_layer + 1 if relevant_blocks else 0,
        processes=len(relevant_pids),
        threads=sum(pid in relevant_pids for pid, _ in threads),
        forward_transitions=forward,
        backward_transitions=backward,
        original_code_frames=len(candidate_frames),
        original_multiframe_ratio=ratio,
        repacked_original_bytes=len(repacked_candidate),
        tail_transition=tail,
        interleaved=interleaved,
        frame_sizes=sizes,
        frame_basic_blocks=basic_blocks,
        candidate_code_bytes=total_candidate,
        candidate_multiframe_bytes=candidate_multiframe,
        all_code_flagged_packer=all_code_packer,
        cross_process_activity=cross_process_activity or bool(process_interactions),
        linear_transition_model=linear,
        packer_to_application_transitions=packer_to_app,
        application_to_packer_transitions=app_to_packer,
        notes=[
            "Application/packer separation uses the paper's 10-page heuristic; "
            "no original-binary role labels were consumed.",
            "Secondary processes are included only when observed IPC/file/physical "
            "provenance connects them to the protected root process.",
        ],
    )
