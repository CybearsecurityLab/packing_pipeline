from __future__ import annotations

from .model import Classification, Evidence, UNRESOLVED


def _granularity(e: Evidence) -> str:
    if not e.frame_sizes:
        return "F"
    page_like = sum(s >= 4096 and s % 4096 == 0 for s in e.frame_sizes)
    if page_like > len(e.frame_sizes) / 2:
        return "P"
    if e.frame_basic_blocks and sum(e.frame_basic_blocks) / len(e.frame_basic_blocks) == 1:
        return "B"
    return "F"


def _classify_paper_runtime(e: Evidence) -> Classification:
    """Section III-E decision procedure, including the Type-III fallback.

    Per Ugarte et al. III-E (docs/ugarte2014.pdf pp. 663-665, Figure 1), Types I,
    II, III, V, and VI are decided from the layer/transition TOPOLOGY alone; only
    Type-IV needs the packer/application separation.  The `all_code_flagged_packer`
    tiebreak therefore belongs ONLY where that separation is consulted (the
    interleaved / no-tail branch that distinguishes IV from V/VI), NOT ahead of the
    linear Type-I/II decision -- a 2-layer, linear, tail-terminated trace is Type I
    regardless of whether the separation succeeded.
    """
    linear = bool(e.linear_transition_model)
    if e.tail_transition:
        if linear and e.layers == 2:
            return Classification(
                "TYPE_I", 1.0, e, "one unpacking layer followed by a tail transition"
            )
        if linear and e.layers > 2:
            return Classification(
                "TYPE_II", 1.0, e, "multiple sequential layers and a tail transition"
            )
        return Classification(
            "TYPE_III", 1.0, e, "cyclic layer topology followed by a tail transition"
        )

    if e.all_code_flagged_packer:
        return Classification(
            "TYPE_III",
            1.0,
            e,
            "paper fallback: all executed code was conservatively flagged as packer code",
        )

    multi_frame = (
        e.original_multiframe_ratio is not None
        and e.original_multiframe_ratio > 0.5
    )
    if multi_frame:
        suffix = _granularity(e)
        if e.repacked_original_bytes:
            return Classification(
                f"TYPE_VI-{suffix}",
                1.0,
                e,
                "a majority of candidate application code is multi-frame and repacked",
            )
        return Classification(
            f"TYPE_V-{suffix}",
            1.0,
            e,
            "a majority of candidate application code is unpacked incrementally",
        )
    return Classification(
        "TYPE_IV",
        1.0,
        e,
        "packer and candidate application code are interleaved without majority multi-frame code",
    )


def classify(e: Evidence) -> Classification:
    """Apply the decision hierarchy from Ugarte et al. without forced labels."""
    if e.termination == "timeout":
        return Classification(UNRESOLVED["timeout"], 1.0, e, "execution timed out")
    if e.termination == "crash":
        return Classification(UNRESOLVED["crash"], 1.0, e, "sample crashed")
    if e.termination == "backend_failure":
        return Classification(
            "UNRESOLVED_BACKEND_FAILURE", 1.0, e, "analysis backend failed"
        )
    if not e.trace_complete and not e.bounded_observation:
        return Classification(
            UNRESOLVED["trace_loss"], 1.0, e, "required trace events are missing"
        )
    if not e.trace_complete and e.bounded_observation:
        # Bounded observation: fall through to the normal hierarchy. It still returns
        # trace_loss for layers==0 and no_unpacking for layers==1, so nothing is
        # invented -- only a trace that ACTUALLY exhibited W->X yields a Type, and
        # that Type is a lower bound on the sample's true complexity.
        e.notes.append(
            "bounded observation: trace cut by the host timeout while the sample was "
            "still running; the Type is a LOWER BOUND (truncation can only reduce "
            "observed layers)"
        )
    if e.cross_process_activity and not e.cross_process_certified:
        return Classification(
            UNRESOLVED["uncertified_cross_process"],
            1.0,
            e,
            "cross-process activity observed under a single-process-only backend "
            "certification",
        )
    if e.taxonomy_basis == "paper_runtime_heuristic":
        if e.layers == 0:
            return Classification(
                UNRESOLVED["trace_loss"],
                1.0,
                e,
                "paper trace contains no executed basic blocks",
            )
        if e.layers == 1:
            return Classification(
                UNRESOLVED["no_unpacking"],
                1.0,
                e,
                "no unpacking layer observed (no write-then-execute); the packed "
                "payload's unpacking was not exercised in this trace",
            )
        return _classify_paper_runtime(e)
    if not e.original_match_available:
        return Classification(
            UNRESOLVED["trace_loss"], 1.0, e, "no original-binary mapping"
        )
    if e.union_code_coverage == 0:
        return Classification(
            UNRESOLVED["no_original_code"], 1.0, e, "original code was not observed"
        )
    if e.union_code_coverage < 0.05:
        return Classification(
            UNRESOLVED["insufficient_coverage"],
            0.9,
            e,
            "less than 5% original-code coverage",
        )

    linear = e.backward_transitions == 0
    if e.tail_transition and not e.interleaved:
        if e.layers <= 2 and linear:
            return Classification(
                "TYPE_I", 0.95, e, "single unpacking layer and tail transition"
            )
        if linear:
            return Classification(
                "TYPE_II", 0.95, e, "multiple sequential layers and tail transition"
            )
        return Classification("TYPE_III", 0.95, e, "cyclic layers and tail transition")

    full_visible = e.maximum_simultaneous_code_coverage >= 0.95
    multi_frame = e.original_code_frames > 1 and (
        e.original_multiframe_ratio is None or e.original_multiframe_ratio > 0.5
    )
    if e.interleaved and multi_frame:
        suffix = _granularity(e)
        if e.repacked_original_bytes:
            return Classification(
                f"TYPE_VI-{suffix}", 0.95, e, "multi-frame original code with repacking"
            )
        return Classification(
            f"TYPE_V-{suffix}", 0.95, e, "incremental multi-frame original code"
        )
    if e.interleaved and full_visible:
        return Classification(
            "TYPE_IV", 0.9, e, "interleaved execution with full code visibility"
        )
    return Classification(
        UNRESOLVED["insufficient_coverage"],
        0.75,
        e,
        "evidence lacks required interleaving or does not distinguish Type IV from V",
    )
