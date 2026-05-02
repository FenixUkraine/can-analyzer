#!/usr/bin/env python3
"""
Offline CAN event/button scanner for TRC logs.

Directory mode expects one of these layouts:

  root/
    kia/
      1/idle.trc open.trc toggle.trc
      17/idle.trc button.trc
    mazda/
      2/idle.trc open.trc toggle.trc

or directly:

  kia/
    1/idle.trc open.trc toggle.trc
    17/idle.trc button.trc

Output rule format is compatible with the firmware text rules:
  <event_id>:B:<bus>,ID:<hex>,BY:<byte>,BI:<bit>,D:<0|1>;...

Default bit numbering is lsb0 because the firmware uses BIT(bit_index).
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import DefaultDict, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

HEX_ID_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{1,8}$")
HEX_BYTE_RE = re.compile(r"^[0-9a-fA-F]{2}$")
TIME_RE = re.compile(r"^\d+(?:[\.,]\d+)?$")

RuleKey = Tuple[int, int]  # bus, can_id


@dataclass(frozen=True)
class Frame:
    t: float
    bus: int
    can_id: int
    dlc: int
    data: Tuple[int, ...]
    line_no: int


@dataclass
class BitInfo:
    samples: int = 0
    zeros: int = 0
    ones: int = 0
    transitions: int = 0
    first_value: Optional[int] = None
    last_value: Optional[int] = None

    def add(self, value: int) -> None:
        value = 1 if value else 0
        self.samples += 1
        if value:
            self.ones += 1
        else:
            self.zeros += 1
        if self.first_value is None:
            self.first_value = value
        elif self.last_value is not None and self.last_value != value:
            self.transitions += 1
        self.last_value = value

    @property
    def values_mask(self) -> int:
        m = 0
        if self.zeros:
            m |= 1
        if self.ones:
            m |= 2
        return m

    def stable_value(self, min_samples: int) -> Optional[int]:
        if self.samples < min_samples:
            return None
        if self.zeros and not self.ones:
            return 0
        if self.ones and not self.zeros:
            return 1
        return None

    def has_value(self, value: int) -> bool:
        return self.ones > 0 if value else self.zeros > 0


@dataclass
class Candidate:
    event_id: int
    mode: str
    reason: str
    bus: int
    can_id: int
    byte: int
    bit_lsb0: int
    expected: int
    score: float
    idle_samples: int = 0
    open_samples: int = 0
    action_samples: int = 0
    action_transitions: int = 0
    press_count: Optional[int] = None
    overflow: bool = False
    suspect: bool = False
    suspect_reasons: str = ""
    suspect_score: float = 0.0
    suspect_source: str = ""

    def out_bit(self, bit_order: str) -> int:
        if bit_order == "msb0":
            return 7 - self.bit_lsb0
        return self.bit_lsb0

    def descriptor(self, bit_order: str = "lsb0") -> str:
        return (
            f"B:{self.bus},ID:{self.can_id:X},BY:{self.byte},"
            f"BI:{self.out_bit(bit_order)},D:{self.expected};"
        )

    def as_row(self, bit_order: str = "lsb0") -> Dict[str, object]:
        return {
            "event_id": self.event_id,
            "mode": self.mode,
            "reason": self.reason,
            "bus": self.bus,
            "id_hex": f"{self.can_id:X}",
            "byte": self.byte,
            "bit_lsb0": self.bit_lsb0,
            "bit_out": self.out_bit(bit_order),
            "expected": self.expected,
            "score": round(self.score, 3),
            "idle_samples": self.idle_samples,
            "open_samples": self.open_samples,
            "action_samples": self.action_samples,
            "action_transitions": self.action_transitions,
            "press_count": "" if self.press_count is None else self.press_count,
            "overflow": self.overflow,
            "suspect": self.suspect,
            "suspect_reasons": self.suspect_reasons,
            "suspect_score": round(self.suspect_score, 3),
            "suspect_source": self.suspect_source,
            "rule": self.descriptor(bit_order),
        }


@dataclass
class ActivityStats:
    samples: int = 0
    active_samples: int = 0
    inactive_samples: int = 0
    transitions: int = 0
    active_segments: int = 0
    first_active: Optional[bool] = None
    last_active: Optional[bool] = None

    def add(self, active: bool) -> None:
        active = bool(active)
        self.samples += 1
        if active:
            self.active_samples += 1
        else:
            self.inactive_samples += 1

        if self.first_active is None:
            self.first_active = active
            if active:
                self.active_segments = 1
        elif self.last_active is not None and self.last_active != active:
            self.transitions += 1
            if active:
                self.active_segments += 1
        self.last_active = active

    @property
    def active_ratio(self) -> float:
        if self.samples <= 0:
            return 0.0
        return self.active_samples / self.samples

    def as_dict(self, prefix: str) -> Dict[str, object]:
        return {
            f"{prefix}_samples": self.samples,
            f"{prefix}_active_samples": self.active_samples,
            f"{prefix}_inactive_samples": self.inactive_samples,
            f"{prefix}_transitions": self.transitions,
            f"{prefix}_active_segments": self.active_segments,
            f"{prefix}_active_ratio": round(self.active_ratio, 4),
        }


@dataclass
class RuleVariant:
    name: str
    rule_line: str
    candidates: List[Candidate]
    dropped_busy_frames: List[Dict[str, object]]
    validation_rejected: List[Dict[str, object]]
    note: str = ""


@dataclass
class EventResult:
    vehicle: str
    event_id: int
    mode: str
    event_dir: str
    rule_line: str
    candidates: List[Candidate]
    dropped_busy_frames: List[Dict[str, object]]
    event_only_debug: List[Dict[str, object]]
    validation_rejected: List[Dict[str, object]]
    dynamic_suspects: List[Dict[str, object]]
    dropped_dynamic_ids: List[Dict[str, object]]
    warnings: List[str]
    alternate_variants: List[RuleVariant] = field(default_factory=list)


class TrcParseError(Exception):
    pass


def parse_float_time(token: str) -> Optional[float]:
    if not TIME_RE.match(token):
        return None
    try:
        return float(token.replace(",", "."))
    except ValueError:
        return None


def is_hex_id(token: str) -> bool:
    return bool(HEX_ID_RE.match(token))


def parse_hex_id(token: str) -> int:
    token = token.lower()
    if token.startswith("0x"):
        token = token[2:]
    return int(token, 16)


def is_hex_byte(token: str) -> bool:
    return bool(HEX_BYTE_RE.match(token))


def parse_int_token(token: str) -> Optional[int]:
    try:
        if token.lower().startswith("0x"):
            return int(token, 16)
        return int(token, 10)
    except ValueError:
        return None


def find_frame_fields(parts: Sequence[str]) -> Optional[Tuple[int, int, int]]:
    """Return (id_idx, dlc_idx, dlc). Works with CAN Hacker-like and many TRC-like lines."""
    candidates: List[Tuple[int, int, int, int]] = []

    # Find a DLC token followed by DLC bytes, then choose nearest previous hex token as CAN ID.
    for dlc_idx in range(1, len(parts)):
        dlc = parse_int_token(parts[dlc_idx])
        if dlc is None or dlc < 0 or dlc > 64:
            continue
        if dlc_idx + dlc >= len(parts):
            continue
        byte_tokens = parts[dlc_idx + 1 : dlc_idx + 1 + dlc]
        if len(byte_tokens) != dlc or not all(is_hex_byte(x) for x in byte_tokens):
            continue

        id_idx: Optional[int] = None
        for j in range(dlc_idx - 1, 0, -1):
            if is_hex_id(parts[j]):
                # Avoid using obvious 2-byte data fields accidentally in very odd formats.
                id_idx = j
                break
        if id_idx is None:
            continue

        # Score: prefer id immediately before dlc, but allow "ID Rx d DLC" variants.
        distance = dlc_idx - id_idx
        candidates.append((distance, id_idx, dlc_idx, dlc))

    if not candidates:
        return None
    candidates.sort(key=lambda x: (x[0], x[1]))
    _, id_idx, dlc_idx, dlc = candidates[0]
    return id_idx, dlc_idx, dlc


def infer_bus(parts: Sequence[str], id_idx: int, channel_base: int) -> int:
    # In the user's CAN Hacker-like example:
    #   time  channel  flags  id  dlc  data...
    # We intentionally skip long zero-padded fields like 00000004 because those are flags.
    for token in parts[1:id_idx]:
        if len(token) > 2 and token.startswith("0"):
            continue
        v = parse_int_token(token)
        if v is not None and 0 <= v <= 16:
            bus = v - channel_base
            return bus if bus >= 0 else v
    return 0


def parse_trc(path: Path, *, channel_base: int = 1, force_bus: Optional[int] = None, max_dlc: int = 8) -> List[Frame]:
    frames: List[Frame] = []
    prev_raw_t: Optional[float] = None
    t_offset = 0.0

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_no, raw_line in enumerate(f, 1):
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("//") or line.startswith(";"):
                continue
            if line.startswith("@") or line.startswith("$"):
                continue

            parts = line.split()
            if len(parts) < 5:
                continue

            raw_t = parse_float_time(parts[0])
            if raw_t is None:
                # Some Vector TRC files may start with frame number before time. Try second token as time.
                raw_t = parse_float_time(parts[1]) if len(parts) > 1 else None
                if raw_t is None:
                    continue

            fields = find_frame_fields(parts)
            if fields is None:
                continue
            id_idx, dlc_idx, dlc = fields

            if dlc > max_dlc:
                dlc = max_dlc

            if prev_raw_t is not None and raw_t + t_offset < (prev_raw_t + t_offset) - 30.0:
                # Logs often wrap seconds from 59.xxx to 00.xxx.
                t_offset += 60.0
            prev_raw_t = raw_t

            try:
                can_id = parse_hex_id(parts[id_idx])
                data = tuple(int(x, 16) for x in parts[dlc_idx + 1 : dlc_idx + 1 + dlc])
            except ValueError:
                continue

            bus = force_bus if force_bus is not None else infer_bus(parts, id_idx, channel_base)
            frames.append(Frame(t=raw_t + t_offset, bus=bus, can_id=can_id, dlc=dlc, data=data, line_no=line_no))

    return frames


def group_frames(frames: Iterable[Frame]) -> Dict[RuleKey, List[Frame]]:
    grouped: DefaultDict[RuleKey, List[Frame]] = defaultdict(list)
    for fr in frames:
        grouped[(fr.bus, fr.can_id)].append(fr)
    for flist in grouped.values():
        flist.sort(key=lambda x: x.t)
    return dict(grouped)


def max_len_for_key(*groups: Dict[RuleKey, List[Frame]], key: RuleKey, max_dlc: int) -> int:
    n = 0
    for g in groups:
        for fr in g.get(key, []):
            n = max(n, min(fr.dlc, max_dlc))
    return n


def bit_value(data: Tuple[int, ...], byte_idx: int, bit_lsb0: int) -> int:
    if byte_idx >= len(data):
        return 0
    return 1 if (data[byte_idx] & (1 << bit_lsb0)) else 0


def bit_info(frames: Sequence[Frame], byte_idx: int, bit_lsb0: int) -> BitInfo:
    info = BitInfo()
    for fr in frames:
        if byte_idx >= fr.dlc:
            continue
        info.add(bit_value(fr.data, byte_idx, bit_lsb0))
    return info


def first_payloads(frames: Sequence[Frame], limit: int = 5) -> List[str]:
    out: List[str] = []
    seen = set()
    for fr in frames:
        s = " ".join(f"{b:02X}" for b in fr.data[: fr.dlc])
        if s not in seen:
            seen.add(s)
            out.append(s)
            if len(out) >= limit:
                break
    return out


def byte_values(frames: Sequence[Frame], byte_idx: int) -> List[int]:
    return [fr.data[byte_idx] for fr in frames if byte_idx < fr.dlc]


def transition_count(values: Sequence[int]) -> int:
    if len(values) < 2:
        return 0
    return sum(1 for a, b in zip(values, values[1:]) if a != b)


def sequential_counter_score(values: Sequence[int], *, mask: int, shift: int = 0) -> float:
    """Return how often masked values increment by 1 modulo the field size.

    Repeated values are ignored because some TRC logs may contain duplicated frames.
    A high value is a strong hint of a rolling counter nibble/byte, not a proof.
    """
    if len(values) < 3:
        return 0.0
    seq = [((v >> shift) & mask) for v in values]
    compact: List[int] = []
    for v in seq:
        if not compact or compact[-1] != v:
            compact.append(v)
    if len(compact) < 3:
        return 0.0
    modulo = mask + 1
    pairs = len(compact) - 1
    good = sum(1 for a, b in zip(compact, compact[1:]) if ((a + 1) % modulo) == b)
    return good / pairs if pairs > 0 else 0.0


def entropy_score(values: Sequence[int]) -> float:
    if not values:
        return 0.0
    counts: DefaultDict[int, int] = defaultdict(int)
    for v in values:
        counts[v] += 1
    n = len(values)
    h = 0.0
    for count in counts.values():
        p = count / n
        h -= p * math.log2(p)
    max_h = math.log2(min(256, max(1, len(counts))))
    return h / max_h if max_h > 0 else 0.0


def analyze_dynamic_byte(
    *,
    bus: int,
    can_id: int,
    byte_idx: int,
    source: str,
    frames: Sequence[Frame],
    args: argparse.Namespace,
) -> Optional[Dict[str, object]]:
    values = byte_values(frames, byte_idx)
    samples = len(values)
    if samples < args.dynamic_min_samples:
        return None

    unique_values = len(set(values))
    transitions = transition_count(values)
    transition_ratio = transitions / max(1, samples - 1)
    entropy = entropy_score(values)
    low_nibble_score = sequential_counter_score(values, mask=0x0F, shift=0)
    high_nibble_score = sequential_counter_score(values, mask=0x0F, shift=4)
    byte_counter_score = sequential_counter_score(values, mask=0xFF, shift=0)

    bit_transitions: List[int] = []
    for bit in range(8):
        info = BitInfo()
        for v in values:
            info.add(1 if (v & (1 << bit)) else 0)
        bit_transitions.append(info.transitions)

    reasons: List[str] = []
    max_counter_score = max(low_nibble_score, high_nibble_score, byte_counter_score)
    counter_kind = ""
    if max_counter_score >= args.counter_score_threshold:
        if byte_counter_score == max_counter_score:
            counter_kind = "byte_counter"
        elif high_nibble_score == max_counter_score:
            counter_kind = "high_nibble_counter"
        else:
            counter_kind = "low_nibble_counter"
        reasons.append(counter_kind)

    # This is intentionally heuristic: a real checksum is not decoded here. The goal is to mark
    # bytes that look too dynamic/random to be a clean state bit, without dropping them.
    if unique_values >= args.checksum_min_unique and transition_ratio >= args.checksum_transition_ratio:
        if entropy >= args.checksum_entropy_threshold:
            reasons.append("checksum_or_crc_suspect")
        else:
            reasons.append("dynamic_byte")
    elif unique_values >= args.dynamic_byte_min_unique or transition_ratio >= args.dynamic_transition_ratio:
        reasons.append("dynamic_byte")

    if not reasons:
        return None

    return {
        "bus": bus,
        "id_hex": f"{can_id:X}",
        "byte": byte_idx,
        "source": source,
        "samples": samples,
        "unique_values": unique_values,
        "transitions": transitions,
        "transition_ratio": round(transition_ratio, 4),
        "entropy_score": round(entropy, 4),
        "counter_score": round(max_counter_score, 4),
        "counter_kind": counter_kind,
        "bit_transitions": bit_transitions,
        "reasons": ",".join(sorted(set(reasons))),
        "first_values_hex": " ".join(f"{v:02X}" for v in values[: min(12, len(values))]),
    }


def build_dynamic_suspects(
    grouped_sources: Dict[str, Dict[RuleKey, List[Frame]]],
    *,
    max_dlc: int,
    args: argparse.Namespace,
) -> Tuple[Dict[Tuple[int, int, int], Dict[str, object]], List[Dict[str, object]]]:
    """Detect rolling-counter/checksum/dynamic-looking bytes.

    The returned profile is keyed by (bus, can_id, byte). It is used only to annotate candidates.
    It does not reject candidates, because those frames may still contain useful state bits.
    """
    per_candidate_byte: Dict[Tuple[int, int, int], Dict[str, object]] = {}
    rows: List[Dict[str, object]] = []
    all_keys = set()
    for source_group in grouped_sources.values():
        all_keys |= set(source_group.keys())

    for key in sorted(all_keys):
        bus, can_id = key
        combined_frames: List[Frame] = []
        nbytes = 0
        for source_group in grouped_sources.values():
            frames = source_group.get(key, [])
            combined_frames.extend(frames)
            for fr in frames:
                nbytes = max(nbytes, min(fr.dlc, max_dlc))
        if nbytes <= 0:
            continue

        sources_to_check: List[Tuple[str, Sequence[Frame]]] = [("all", sorted(combined_frames, key=lambda x: x.t))]
        for source_name, source_group in grouped_sources.items():
            source_frames = source_group.get(key, [])
            if source_frames:
                sources_to_check.append((source_name, source_frames))

        for by in range(nbytes):
            profiles: List[Dict[str, object]] = []
            for source_name, frames in sources_to_check:
                profile = analyze_dynamic_byte(bus=bus, can_id=can_id, byte_idx=by, source=source_name, frames=frames, args=args)
                if profile is not None:
                    profiles.append(profile)

            if not profiles:
                continue

            # Prefer idle/button-local evidence when present; otherwise use the strongest combined signal.
            def rank_profile(row: Dict[str, object]) -> Tuple[int, float, float, int]:
                source = str(row.get("source", ""))
                source_priority = {"idle": 4, "button": 3, "open": 2, "toggle": 2, "all": 1}.get(source, 0)
                return (
                    source_priority,
                    float(row.get("counter_score", 0.0)),
                    float(row.get("transition_ratio", 0.0)),
                    int(row.get("unique_values", 0)),
                )

            best = max(profiles, key=rank_profile)
            per_candidate_byte[(bus, can_id, by)] = best
            rows.extend(profiles)

    rows.sort(key=lambda r: (r["bus"], str(r["id_hex"]), int(r["byte"]), str(r["source"])))
    return per_candidate_byte, rows[: args.max_dynamic_suspects]


def parse_source_filter(value: str) -> set[str]:
    sources = {x.strip().lower() for x in value.split(",") if x.strip()}
    if not sources:
        return {"idle", "open", "toggle", "button"}
    if "all" in sources:
        sources.update({"idle", "open", "toggle", "button"})
    return sources


def changed_bits_for_frames(frames: Sequence[Frame], *, max_dlc: int) -> Tuple[int, List[str]]:
    """Count payload bits that take both 0 and 1 values inside one recording/source."""
    if not frames:
        return 0, []

    nbytes = 0
    for fr in frames:
        nbytes = max(nbytes, min(fr.dlc, max_dlc))
    changed: List[str] = []

    for by in range(nbytes):
        for bit in range(8):
            info = bit_info(frames, by, bit)
            if info.values_mask == 3:
                changed.append(f"BY:{by}/BI:{bit}")

    return len(changed), changed


def build_too_dynamic_id_drops(
    grouped_sources: Dict[str, Dict[RuleKey, List[Frame]]],
    *,
    max_dlc: int,
    args: argparse.Namespace,
) -> Tuple[set[RuleKey], List[Dict[str, object]]]:
    """Optionally drop whole CAN IDs whose payload changes too much.

    This is intentionally a hard filter only when the user passes
    --drop-ids-with-too-many-changing-bits. The earlier counter/checksum logic remains
    soft annotation and does not reject candidates by itself.
    """
    if not args.drop_ids_with_too_many_changing_bits:
        return set(), []

    source_filter = parse_source_filter(args.dynamic_id_check_sources)
    all_keys: set[RuleKey] = set()
    for source_group in grouped_sources.values():
        all_keys |= set(source_group.keys())

    dropped_keys: set[RuleKey] = set()
    dropped_rows: List[Dict[str, object]] = []

    for key in sorted(all_keys):
        bus, can_id = key

        sources_to_check: List[Tuple[str, Sequence[Frame]]] = []
        for source_name, source_group in grouped_sources.items():
            if source_name.lower() in source_filter:
                frames = source_group.get(key, [])
                if frames:
                    sources_to_check.append((source_name, frames))

        if args.dynamic_id_include_combined:
            combined: List[Frame] = []
            for source_group in grouped_sources.values():
                combined.extend(source_group.get(key, []))
            if combined:
                sources_to_check.append(("combined", sorted(combined, key=lambda x: x.t)))

        for source_name, frames in sources_to_check:
            if len(frames) < args.dynamic_id_min_samples:
                continue
            changing_bits, changed_list = changed_bits_for_frames(frames, max_dlc=max_dlc)
            if changing_bits > args.max_changing_bits_per_id:
                dropped_keys.add(key)
                dropped_rows.append(
                    {
                        "bus": bus,
                        "id_hex": f"{can_id:X}",
                        "source": source_name,
                        "frames": len(frames),
                        "changing_bits": changing_bits,
                        "limit": args.max_changing_bits_per_id,
                        "reason": "too_many_changing_bits",
                        "changed_bits_preview": " ".join(changed_list[: args.dynamic_id_changed_bits_preview]),
                    }
                )
                # One source is enough to drop this ID; continue gathering rows for transparency.

    dropped_rows.sort(key=lambda r: (r["bus"], str(r["id_hex"]), str(r["source"])))
    return dropped_keys, dropped_rows[: args.max_dynamic_id_drops]


def annotate_candidates_with_dynamic_suspects(
    candidates: List[Candidate],
    dynamic_by_byte: Dict[Tuple[int, int, int], Dict[str, object]],
) -> None:
    for c in candidates:
        row = dynamic_by_byte.get((c.bus, c.can_id, c.byte))
        if row is None:
            continue
        c.suspect = True
        c.suspect_reasons = str(row.get("reasons", ""))
        c.suspect_score = max(float(row.get("counter_score", 0.0)), float(row.get("transition_ratio", 0.0)))
        c.suspect_source = str(row.get("source", ""))
        if c.suspect_reasons and c.suspect_reasons not in c.reason:
            c.reason = f"{c.reason}|suspect:{c.suspect_reasons}"


def apply_busy_filter(
    candidates: List[Candidate],
    *,
    max_bits_per_frame: int,
) -> Tuple[List[Candidate], List[Dict[str, object]]]:
    by_frame: DefaultDict[Tuple[int, int], List[Candidate]] = defaultdict(list)
    for c in candidates:
        by_frame[(c.bus, c.can_id)].append(c)

    keep: List[Candidate] = []
    dropped: List[Dict[str, object]] = []
    for (bus, can_id), items in by_frame.items():
        if max_bits_per_frame > 0 and len(items) > max_bits_per_frame:
            dropped.append(
                {
                    "bus": bus,
                    "id_hex": f"{can_id:X}",
                    "bits": len(items),
                    "limit": max_bits_per_frame,
                    "reason": "busy_frame",
                }
            )
        else:
            keep.extend(items)
    return keep, dropped


def sort_candidates(candidates: List[Candidate]) -> List[Candidate]:
    return sorted(candidates, key=lambda c: (-c.score, c.bus, c.can_id, c.byte, c.bit_lsb0, c.reason))


def candidate_key(candidate: Candidate) -> RuleKey:
    return candidate.bus, candidate.can_id


def candidate_activity_stats(frames: Sequence[Frame], candidate: Candidate) -> ActivityStats:
    """Count how often a candidate bit is in its active state.

    candidate.expected is treated as the active value:
      - state: value that must be present in open.trc
      - button: value that must be present while the button is pressed
    """
    stats = ActivityStats()
    for fr in frames:
        if candidate.byte >= fr.dlc:
            continue
        active = bit_value(fr.data, candidate.byte, candidate.bit_lsb0) == candidate.expected
        stats.add(active)
    return stats


def validation_reject_row(
    candidate: Candidate,
    *,
    reason: str,
    bit_order: str,
    idle_stats: Optional[ActivityStats] = None,
    open_stats: Optional[ActivityStats] = None,
    action_stats: Optional[ActivityStats] = None,
) -> Dict[str, object]:
    row = candidate.as_row(bit_order)
    row["validation"] = "rejected"
    row["validation_reason"] = reason
    if idle_stats is not None:
        row.update(idle_stats.as_dict("idle"))
    if open_stats is not None:
        row.update(open_stats.as_dict("open"))
    if action_stats is not None:
        row.update(action_stats.as_dict("action"))
    return row


def validate_state_candidate(
    candidate: Candidate,
    *,
    idle_frames: Sequence[Frame],
    open_frames: Sequence[Frame],
    toggle_frames: Sequence[Frame],
    args: argparse.Namespace,
) -> Tuple[bool, Optional[str], ActivityStats, ActivityStats, ActivityStats]:
    idle_stats = candidate_activity_stats(idle_frames, candidate)
    open_stats = candidate_activity_stats(open_frames, candidate)
    toggle_stats = candidate_activity_stats(toggle_frames, candidate)

    # ID/bit must be inactive in idle.trc. By default "missing in idle" is not accepted,
    # because it is unknown, not a confirmed inactive state. It can be enabled explicitly.
    if idle_stats.samples < args.min_stable_samples:
        if not (args.allow_missing_idle_as_inactive and idle_stats.samples == 0):
            return False, "idle_missing_or_too_few_samples", idle_stats, open_stats, toggle_stats
    if idle_stats.active_samples > args.max_idle_active_samples:
        return False, "idle_is_active", idle_stats, open_stats, toggle_stats

    # ID/bit must be active in open.trc.
    if open_stats.samples < args.min_stable_samples:
        return False, "open_missing_or_too_few_samples", idle_stats, open_stats, toggle_stats
    if open_stats.active_ratio < args.min_open_active_ratio:
        return False, "open_not_active_enough", idle_stats, open_stats, toggle_stats

    # In toggle.trc it must really switch: there must be both active and inactive samples,
    # at least one active segment, and enough active/inactive transitions.
    if toggle_stats.samples < args.min_stable_samples:
        return False, "toggle_missing_or_too_few_samples", idle_stats, open_stats, toggle_stats
    if toggle_stats.active_samples <= 0:
        return False, "toggle_never_active", idle_stats, open_stats, toggle_stats
    if toggle_stats.inactive_samples <= 0:
        return False, "toggle_never_inactive", idle_stats, open_stats, toggle_stats
    if toggle_stats.transitions < args.min_state_transitions:
        return False, "toggle_not_switching", idle_stats, open_stats, toggle_stats
    if toggle_stats.active_segments < args.min_toggle_activations:
        return False, "toggle_too_few_active_segments", idle_stats, open_stats, toggle_stats

    return True, None, idle_stats, open_stats, toggle_stats


def validate_state_candidates(
    candidates: List[Candidate],
    *,
    idle: Dict[RuleKey, List[Frame]],
    opened: Dict[RuleKey, List[Frame]],
    toggle: Dict[RuleKey, List[Frame]],
    args: argparse.Namespace,
) -> Tuple[List[Candidate], List[Dict[str, object]]]:
    valid: List[Candidate] = []
    rejected: List[Dict[str, object]] = []

    for c in candidates:
        key = candidate_key(c)
        ok, reason, idle_stats, open_stats, toggle_stats = validate_state_candidate(
            c,
            idle_frames=idle.get(key, []),
            open_frames=opened.get(key, []),
            toggle_frames=toggle.get(key, []),
            args=args,
        )
        if ok:
            c.idle_samples = idle_stats.samples
            c.open_samples = open_stats.samples
            c.action_samples = toggle_stats.samples
            c.action_transitions = toggle_stats.transitions
            c.press_count = toggle_stats.active_segments
            valid.append(c)
        else:
            rejected.append(
                validation_reject_row(
                    c,
                    reason=reason or "unknown",
                    bit_order=args.bit_order,
                    idle_stats=idle_stats,
                    open_stats=open_stats,
                    action_stats=toggle_stats,
                )
            )

    return valid, rejected[: args.max_validation_rejected]


def validate_button_candidate(
    candidate: Candidate,
    *,
    idle_frames: Sequence[Frame],
    button_frames: Sequence[Frame],
    args: argparse.Namespace,
) -> Tuple[bool, Optional[str], ActivityStats, ActivityStats]:
    idle_stats = candidate_activity_stats(idle_frames, candidate)
    button_stats = candidate_activity_stats(button_frames, candidate)

    # Candidate must be inactive in idle.trc.
    if idle_stats.samples < args.min_stable_samples:
        if not (args.allow_missing_idle_as_inactive and idle_stats.samples == 0):
            return False, "idle_missing_or_too_few_samples", idle_stats, button_stats
    if idle_stats.active_samples > args.max_idle_active_samples:
        return False, "idle_is_active", idle_stats, button_stats

    # Button mode is intentionally strict: exactly N active segments == exactly N presses.
    # This is stricter and more useful than only checking that the bit changed.
    if button_stats.samples < args.min_stable_samples:
        return False, "button_missing_or_too_few_samples", idle_stats, button_stats
    if button_stats.active_segments != args.expected_presses:
        return False, "button_press_count_not_exact", idle_stats, button_stats
    if button_stats.active_samples < args.expected_presses:
        return False, "button_too_few_active_samples", idle_stats, button_stats
    if button_stats.inactive_samples <= 0 and not args.allow_unreleased_last_press:
        return False, "button_never_returns_inactive", idle_stats, button_stats

    return True, None, idle_stats, button_stats


def validate_button_candidates(
    candidates: List[Candidate],
    *,
    idle: Dict[RuleKey, List[Frame]],
    pressed: Dict[RuleKey, List[Frame]],
    args: argparse.Namespace,
) -> Tuple[List[Candidate], List[Dict[str, object]]]:
    valid: List[Candidate] = []
    rejected: List[Dict[str, object]] = []

    for c in candidates:
        key = candidate_key(c)
        ok, reason, idle_stats, button_stats = validate_button_candidate(
            c,
            idle_frames=idle.get(key, []),
            button_frames=pressed.get(key, []),
            args=args,
        )
        if ok:
            c.idle_samples = idle_stats.samples
            c.action_samples = button_stats.active_samples
            c.action_transitions = button_stats.transitions
            c.press_count = button_stats.active_segments
            c.overflow = button_stats.active_segments > args.expected_presses
            valid.append(c)
        else:
            rejected.append(
                validation_reject_row(
                    c,
                    reason=reason or "unknown",
                    bit_order=args.bit_order,
                    idle_stats=idle_stats,
                    action_stats=button_stats,
                )
            )

    return valid, rejected[: args.max_validation_rejected]


def build_state_rule_variant(
    *,
    name: str,
    event_id: int,
    idle: Dict[RuleKey, List[Frame]],
    opened: Dict[RuleKey, List[Frame]],
    toggle: Dict[RuleKey, List[Frame]],
    keys: Iterable[RuleKey],
    dynamic_by_byte: Dict[Tuple[int, int, int], Dict[str, object]],
    args: argparse.Namespace,
    note: str = "",
) -> RuleVariant:
    """Build and validate one state-analysis variant.

    The default variant uses the normal key set. The idle_ids_only variant uses only
    CAN IDs that already existed in idle.trc, which is useful when open.trc contains
    extra event-only traffic and you want a conservative rule set for comparison.
    """
    strict: List[Candidate] = []
    fallback: List[Candidate] = []
    event_only: List[Candidate] = []

    for key in sorted(set(keys)):
        bus, can_id = key
        idle_list = idle.get(key, [])
        open_list = opened.get(key, [])
        toggle_list = toggle.get(key, [])
        nbytes = max_len_for_key(idle, opened, toggle, key=key, max_dlc=args.max_dlc)
        if nbytes <= 0:
            continue

        # Main strict/per-bit mode: stable in idle, stable in open, different, confirmed in toggle.
        for by in range(nbytes):
            for bit in range(8):
                idle_info = bit_info(idle_list, by, bit)
                open_info = bit_info(open_list, by, bit)
                tog_info = bit_info(toggle_list, by, bit)

                base_val = idle_info.stable_value(args.min_stable_samples)
                open_val = open_info.stable_value(args.min_stable_samples)
                if base_val is not None and open_val is not None and base_val != open_val:
                    if tog_info.has_value(base_val) and tog_info.has_value(open_val) and tog_info.transitions >= args.min_state_transitions:
                        balance = min(tog_info.zeros, tog_info.ones)
                        score = 1000.0 + tog_info.transitions * 20.0 + balance
                        strict.append(
                            Candidate(
                                event_id=event_id,
                                mode="state",
                                reason="idle_open_diff_confirmed_by_toggle",
                                bus=bus,
                                can_id=can_id,
                                byte=by,
                                bit_lsb0=bit,
                                expected=open_val,
                                score=score,
                                idle_samples=idle_info.samples,
                                open_samples=open_info.samples,
                                action_samples=tog_info.samples,
                                action_transitions=tog_info.transitions,
                            )
                        )
                        continue

                # Fallback: stable in idle, toggles away and back during action.
                if base_val is not None and toggle_list:
                    if tog_info.has_value(base_val) and tog_info.has_value(1 - base_val) and tog_info.transitions >= args.min_state_transitions:
                        expected = open_val if open_val is not None else (1 - base_val)
                        score = 100.0 + tog_info.transitions * 10.0 + min(tog_info.zeros, tog_info.ones)
                        fallback.append(
                            Candidate(
                                event_id=event_id,
                                mode="state",
                                reason="fallback_idle_vs_toggle",
                                bus=bus,
                                can_id=can_id,
                                byte=by,
                                bit_lsb0=bit,
                                expected=expected,
                                score=score,
                                idle_samples=idle_info.samples,
                                open_samples=open_info.samples,
                                action_samples=tog_info.samples,
                                action_transitions=tog_info.transitions,
                            )
                        )

                # Event-only: no stable idle, stable open value == 1, appears during toggle.
                if args.include_event_only or args.event_only_if_empty:
                    if base_val is None and open_val == 1 and tog_info.ones > 0:
                        score = 10.0 + tog_info.ones + tog_info.transitions
                        event_only.append(
                            Candidate(
                                event_id=event_id,
                                mode="state",
                                reason="event_only_open_snapshot",
                                bus=bus,
                                can_id=can_id,
                                byte=by,
                                bit_lsb0=bit,
                                expected=1,
                                score=score,
                                idle_samples=idle_info.samples,
                                open_samples=open_info.samples,
                                action_samples=tog_info.samples,
                                action_transitions=tog_info.transitions,
                            )
                        )

    # Prefer strict candidates. Use fallback only if strict is empty.
    selected = strict if strict else fallback
    if not selected and (args.include_event_only or args.event_only_if_empty):
        selected = event_only
    elif args.include_event_only:
        selected = selected + event_only

    annotate_candidates_with_dynamic_suspects(selected, dynamic_by_byte)
    selected, validation_rejected = validate_state_candidates(
        selected,
        idle=idle,
        opened=opened,
        toggle=toggle,
        args=args,
    )
    selected, dropped = apply_busy_filter(selected, max_bits_per_frame=args.max_bits_per_frame)
    selected = sort_candidates(selected)[: args.max_signals_per_event]

    rule_line = f"{event_id}:" + "".join(c.descriptor(args.bit_order) for c in selected)
    if not selected:
        rule_line = f"{event_id}:error:No changes found"

    return RuleVariant(
        name=name,
        rule_line=rule_line,
        candidates=selected,
        dropped_busy_frames=dropped,
        validation_rejected=validation_rejected,
        note=note,
    )


def analyze_state_event(
    *,
    vehicle: str,
    event_id: int,
    event_dir: Path,
    idle_path: Path,
    open_path: Path,
    toggle_path: Path,
    args: argparse.Namespace,
) -> EventResult:
    warnings: List[str] = []
    idle_frames = parse_trc(idle_path, channel_base=args.trc_channel_base, force_bus=args.force_bus, max_dlc=args.max_dlc)
    open_frames = parse_trc(open_path, channel_base=args.trc_channel_base, force_bus=args.force_bus, max_dlc=args.max_dlc)
    toggle_frames = parse_trc(toggle_path, channel_base=args.trc_channel_base, force_bus=args.force_bus, max_dlc=args.max_dlc)

    if not idle_frames:
        warnings.append(f"idle file has no parsed frames: {idle_path}")
    if not open_frames:
        warnings.append(f"open file has no parsed frames: {open_path}")
    if not toggle_frames:
        warnings.append(f"toggle file has no parsed frames: {toggle_path}")

    idle = group_frames(idle_frames)
    opened = group_frames(open_frames)
    toggle = group_frames(toggle_frames)
    dynamic_by_byte, dynamic_suspects = build_dynamic_suspects(
        {"idle": idle, "open": opened, "toggle": toggle},
        max_dlc=args.max_dlc,
        args=args,
    )

    dynamic_id_drop_keys, dropped_dynamic_ids = build_too_dynamic_id_drops(
        {"idle": idle, "open": opened, "toggle": toggle},
        max_dlc=args.max_dlc,
        args=args,
    )
    default_keys_all = set(idle) | set(opened) | set(toggle)
    default_keys = default_keys_all - dynamic_id_drop_keys
    if dropped_dynamic_ids:
        warnings.append(
            f"dropped {len(dynamic_id_drop_keys)} CAN IDs because more than "
            f"{args.max_changing_bits_per_id} bits changed inside selected TRC source(s)"
        )

    default_variant = build_state_rule_variant(
        name="default",
        event_id=event_id,
        idle=idle,
        opened=opened,
        toggle=toggle,
        keys=default_keys,
        dynamic_by_byte=dynamic_by_byte,
        args=args,
        note="normal analysis: idle/open/toggle key union",
    )

    debug_event_only: List[Dict[str, object]] = []
    for key in sorted(default_keys_all):
        bus, can_id = key
        idle_list = idle.get(key, [])
        open_list = opened.get(key, [])
        toggle_list = toggle.get(key, [])
        if not idle_list and (open_list or toggle_list):
            debug_event_only.append(
                {
                    "bus": bus,
                    "id_hex": f"{can_id:X}",
                    "open_frames": len(open_list),
                    "toggle_frames": len(toggle_list),
                    "open_payloads": first_payloads(open_list),
                    "toggle_payloads": first_payloads(toggle_list),
                }
            )

    alternate_variants: List[RuleVariant] = []
    open_extra_ids = set(opened) - set(idle)
    should_make_idle_ids_only = args.idle_ids_only_variant and (
        len(open_frames) > len(idle_frames) or bool(open_extra_ids)
    )
    if should_make_idle_ids_only:
        note = (
            f"open_frames={len(open_frames)} idle_frames={len(idle_frames)}; "
            f"open_extra_ids={len(open_extra_ids)}; only CAN IDs present in idle.trc are analyzed"
        )
        idle_only_variant = build_state_rule_variant(
            name="idle_ids_only",
            event_id=event_id,
            idle=idle,
            opened=opened,
            toggle=toggle,
            keys=set(idle) - dynamic_id_drop_keys,
            dynamic_by_byte=dynamic_by_byte,
            args=args,
            note=note,
        )
        alternate_variants.append(idle_only_variant)
        warnings.append(f"created idle_ids_only variant: {note}")

    return EventResult(
        vehicle=vehicle,
        event_id=event_id,
        mode="state",
        event_dir=str(event_dir),
        rule_line=default_variant.rule_line,
        candidates=default_variant.candidates,
        dropped_busy_frames=default_variant.dropped_busy_frames,
        event_only_debug=debug_event_only,
        validation_rejected=default_variant.validation_rejected,
        dynamic_suspects=dynamic_suspects,
        dropped_dynamic_ids=dropped_dynamic_ids,
        warnings=warnings,
        alternate_variants=alternate_variants,
    )

def analyze_button_event(
    *,
    vehicle: str,
    event_id: int,
    event_dir: Path,
    idle_path: Path,
    button_path: Path,
    args: argparse.Namespace,
) -> EventResult:
    warnings: List[str] = []
    idle_frames = parse_trc(idle_path, channel_base=args.trc_channel_base, force_bus=args.force_bus, max_dlc=args.max_dlc)
    button_frames = parse_trc(button_path, channel_base=args.trc_channel_base, force_bus=args.force_bus, max_dlc=args.max_dlc)

    if not idle_frames:
        warnings.append(f"idle file has no parsed frames: {idle_path}")
    if not button_frames:
        warnings.append(f"button file has no parsed frames: {button_path}")

    idle = group_frames(idle_frames)
    pressed = group_frames(button_frames)
    dynamic_by_byte, dynamic_suspects = build_dynamic_suspects(
        {"idle": idle, "button": pressed},
        max_dlc=args.max_dlc,
        args=args,
    )
    dynamic_id_drop_keys, dropped_dynamic_ids = build_too_dynamic_id_drops(
        {"idle": idle, "button": pressed},
        max_dlc=args.max_dlc,
        args=args,
    )
    keys = (set(idle) | set(pressed)) - dynamic_id_drop_keys
    if dropped_dynamic_ids:
        warnings.append(
            f"dropped {len(dynamic_id_drop_keys)} CAN IDs because more than "
            f"{args.max_changing_bits_per_id} bits changed inside selected TRC source(s)"
        )

    candidates: List[Candidate] = []
    debug_event_only: List[Dict[str, object]] = []

    for key in sorted(keys):
        bus, can_id = key
        idle_list = idle.get(key, [])
        press_list = pressed.get(key, [])
        nbytes = max_len_for_key(idle, pressed, key=key, max_dlc=args.max_dlc)
        if nbytes <= 0:
            continue

        if not idle_list and press_list:
            debug_event_only.append(
                {
                    "bus": bus,
                    "id_hex": f"{can_id:X}",
                    "button_frames": len(press_list),
                    "button_payloads": first_payloads(press_list),
                    "note": "ID was not present in idle; treated as debug only, not a bit rule",
                }
            )
            continue

        for by in range(nbytes):
            for bit in range(8):
                idle_info = bit_info(idle_list, by, bit)
                base_val = idle_info.stable_value(args.min_stable_samples)
                if base_val is None:
                    continue

                expected = 0 if base_val else 1
                probe = Candidate(
                    event_id=event_id,
                    mode="button",
                    reason="button_activity_probe",
                    bus=bus,
                    can_id=can_id,
                    byte=by,
                    bit_lsb0=bit,
                    expected=expected,
                    score=0.0,
                    idle_samples=idle_info.samples,
                    open_samples=0,
                )
                button_stats = candidate_activity_stats(press_list, probe)

                # Keep every bit that becomes active at least once, then the validator below
                # will accept only bits with exactly args.expected_presses active segments.
                if button_stats.active_segments > 0:
                    probe.reason = "button_activity_checked_by_validator"
                    probe.score = 1000.0 + button_stats.active_segments * 100.0 + button_stats.transitions * 10.0 + button_stats.active_samples
                    probe.action_samples = button_stats.active_samples
                    probe.action_transitions = button_stats.transitions
                    probe.press_count = button_stats.active_segments
                    probe.overflow = button_stats.active_segments > args.expected_presses
                    candidates.append(probe)

    annotate_candidates_with_dynamic_suspects(candidates, dynamic_by_byte)
    candidates, validation_rejected = validate_button_candidates(
        candidates,
        idle=idle,
        pressed=pressed,
        args=args,
    )
    candidates, dropped = apply_busy_filter(candidates, max_bits_per_frame=args.button_max_bits_per_frame)
    candidates = sort_candidates(candidates)[: args.max_signals_per_event]
    rule_line = f"{event_id}:" + "".join(c.descriptor(args.bit_order) for c in candidates)
    if not candidates:
        rule_line = f"{event_id}:error:No changes found"

    return EventResult(
        vehicle=vehicle,
        event_id=event_id,
        mode="button",
        event_dir=str(event_dir),
        rule_line=rule_line,
        candidates=candidates,
        dropped_busy_frames=dropped,
        event_only_debug=debug_event_only,
        validation_rejected=validation_rejected,
        dynamic_suspects=dynamic_suspects,
        dropped_dynamic_ids=dropped_dynamic_ids,
        warnings=warnings,
    )


def file_ci(directory: Path, *names: str) -> Optional[Path]:
    wanted = {n.lower() for n in names}
    if not directory.is_dir():
        return None
    for p in directory.iterdir():
        if p.is_file() and p.name.lower() in wanted:
            return p
    return None


def discover_event_dirs(root: Path) -> List[Tuple[str, int, Path]]:
    root = root.resolve()
    out: List[Tuple[str, int, Path]] = []

    direct_numeric = [p for p in root.iterdir() if p.is_dir() and p.name.isdigit()] if root.is_dir() else []
    if direct_numeric:
        for p in direct_numeric:
            out.append((root.name, int(p.name), p))
        return sorted(out, key=lambda x: (x[0], x[1]))

    for vehicle_dir in sorted([p for p in root.iterdir() if p.is_dir()]):
        for event_dir in sorted([p for p in vehicle_dir.iterdir() if p.is_dir() and p.name.isdigit()], key=lambda x: int(x.name)):
            out.append((vehicle_dir.name, int(event_dir.name), event_dir))
    return out


def write_event_outputs(result: EventResult, out_dir: Path, bit_order: str) -> None:
    vehicle_dir = out_dir / result.vehicle
    vehicle_dir.mkdir(parents=True, exist_ok=True)

    base = vehicle_dir / f"{result.event_id}_{result.mode}"

    with (base.with_suffix(".csv")).open("w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "event_id",
            "mode",
            "reason",
            "bus",
            "id_hex",
            "byte",
            "bit_lsb0",
            "bit_out",
            "expected",
            "score",
            "idle_samples",
            "open_samples",
            "action_samples",
            "action_transitions",
            "press_count",
            "overflow",
            "suspect",
            "suspect_reasons",
            "suspect_score",
            "suspect_source",
            "rule",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for c in result.candidates:
            writer.writerow(c.as_row(bit_order))

    for v in result.alternate_variants:
        variant_base = vehicle_dir / f"{result.event_id}_{result.mode}__{v.name}"
        with (variant_base.with_suffix(".csv")).open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for c in v.candidates:
                writer.writerow(c.as_row(bit_order))

    with (base.with_suffix(".json")).open("w", encoding="utf-8") as f:
        json.dump(
            {
                "vehicle": result.vehicle,
                "event_id": result.event_id,
                "mode": result.mode,
                "event_dir": result.event_dir,
                "rule_line": result.rule_line,
                "candidates": [c.as_row(bit_order) for c in result.candidates],
                "dropped_busy_frames": result.dropped_busy_frames,
                "event_only_debug": result.event_only_debug,
                "validation_rejected": result.validation_rejected,
                "dynamic_suspects": result.dynamic_suspects,
                "dropped_dynamic_ids": result.dropped_dynamic_ids,
                "alternate_variants": [
                    {
                        "name": v.name,
                        "note": v.note,
                        "rule_line": v.rule_line,
                        "candidates": [c.as_row(bit_order) for c in v.candidates],
                        "dropped_busy_frames": v.dropped_busy_frames,
                        "validation_rejected": v.validation_rejected,
                    }
                    for v in result.alternate_variants
                ],
                "warnings": result.warnings,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )


def write_combined_outputs(results: List[EventResult], out_dir: Path, bit_order: str) -> None:
    by_vehicle: DefaultDict[str, List[EventResult]] = defaultdict(list)
    for r in results:
        by_vehicle[r.vehicle].append(r)

    out_dir.mkdir(parents=True, exist_ok=True)
    for vehicle, items in by_vehicle.items():
        vehicle_dir = out_dir / vehicle
        vehicle_dir.mkdir(parents=True, exist_ok=True)
        items = sorted(items, key=lambda r: r.event_id)

        with (vehicle_dir / "scan_data.txt").open("w", encoding="utf-8") as f:
            for r in items:
                f.write(r.rule_line + "\n")

        variant_names = sorted({v.name for r in items for v in r.alternate_variants})
        for variant_name in variant_names:
            with (vehicle_dir / f"scan_data_{variant_name}.txt").open("w", encoding="utf-8") as f:
                for r in items:
                    variant = next((v for v in r.alternate_variants if v.name == variant_name), None)
                    # Keep the file complete: if this event did not need the variant, reuse default rule.
                    f.write((variant.rule_line if variant is not None else r.rule_line) + "\n")

        with (vehicle_dir / "summary_variants.csv").open("w", newline="", encoding="utf-8") as f:
            fieldnames = [
                "vehicle",
                "event_id",
                "mode",
                "variant",
                "candidate_count",
                "suspect_candidates",
                "dropped_busy_frames",
                "dropped_dynamic_ids",
                "validation_rejected",
                "note",
                "rule_line",
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in items:
                writer.writerow(
                    {
                        "vehicle": r.vehicle,
                        "event_id": r.event_id,
                        "mode": r.mode,
                        "variant": "default",
                        "candidate_count": len(r.candidates),
                        "suspect_candidates": sum(1 for c in r.candidates if c.suspect),
                        "dropped_busy_frames": len(r.dropped_busy_frames),
                        "dropped_dynamic_ids": len(r.dropped_dynamic_ids),
                        "validation_rejected": len(r.validation_rejected),
                        "note": "normal analysis: idle/open/toggle key union" if r.mode == "state" else "",
                        "rule_line": r.rule_line,
                    }
                )
                for v in r.alternate_variants:
                    writer.writerow(
                        {
                            "vehicle": r.vehicle,
                            "event_id": r.event_id,
                            "mode": r.mode,
                            "variant": v.name,
                            "candidate_count": len(v.candidates),
                            "suspect_candidates": sum(1 for c in v.candidates if c.suspect),
                            "dropped_busy_frames": len(v.dropped_busy_frames),
                            "dropped_dynamic_ids": len(r.dropped_dynamic_ids),
                            "validation_rejected": len(v.validation_rejected),
                            "note": v.note,
                            "rule_line": v.rule_line,
                        }
                    )

        with (vehicle_dir / "summary.csv").open("w", newline="", encoding="utf-8") as f:
            fieldnames = [
                "vehicle",
                "event_id",
                "mode",
                "candidate_count",
                "suspect_candidates",
                "dynamic_suspects",
                "dropped_busy_frames",
                "dropped_dynamic_ids",
                "validation_rejected",
                "alternate_variants",
                "idle_ids_only_candidate_count",
                "idle_ids_only_rule_line",
                "warnings",
                "rule_line",
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in items:
                writer.writerow(
                    {
                        "vehicle": r.vehicle,
                        "event_id": r.event_id,
                        "mode": r.mode,
                        "candidate_count": len(r.candidates),
                        "suspect_candidates": sum(1 for c in r.candidates if c.suspect),
                        "dynamic_suspects": len(r.dynamic_suspects),
                        "dropped_busy_frames": len(r.dropped_busy_frames),
                        "dropped_dynamic_ids": len(r.dropped_dynamic_ids),
                        "validation_rejected": len(r.validation_rejected),
                        "alternate_variants": ",".join(v.name for v in r.alternate_variants),
                        "idle_ids_only_candidate_count": next((len(v.candidates) for v in r.alternate_variants if v.name == "idle_ids_only"), ""),
                        "idle_ids_only_rule_line": next((v.rule_line for v in r.alternate_variants if v.name == "idle_ids_only"), ""),
                        "warnings": " | ".join(r.warnings),
                        "rule_line": r.rule_line,
                    }
                )

        with (vehicle_dir / "dynamic_suspects.csv").open("w", newline="", encoding="utf-8") as f:
            fieldnames = [
                "event_id",
                "mode",
                "bus",
                "id_hex",
                "byte",
                "source",
                "samples",
                "unique_values",
                "transitions",
                "transition_ratio",
                "entropy_score",
                "counter_score",
                "counter_kind",
                "reasons",
                "first_values_hex",
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for r in items:
                for row in r.dynamic_suspects:
                    out_row = dict(row)
                    out_row["event_id"] = r.event_id
                    out_row["mode"] = r.mode
                    writer.writerow(out_row)

        with (vehicle_dir / "dropped_dynamic_ids.csv").open("w", newline="", encoding="utf-8") as f:
            fieldnames = [
                "event_id",
                "mode",
                "bus",
                "id_hex",
                "source",
                "frames",
                "changing_bits",
                "limit",
                "reason",
                "changed_bits_preview",
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for r in items:
                for row in r.dropped_dynamic_ids:
                    out_row = dict(row)
                    out_row["event_id"] = r.event_id
                    out_row["mode"] = r.mode
                    writer.writerow(out_row)


def analyze_event_dir(vehicle: str, event_id: int, event_dir: Path, args: argparse.Namespace) -> Optional[EventResult]:
    idle = file_ci(event_dir, "idle.trc")
    opened = file_ci(event_dir, "open.trc")
    toggle = file_ci(event_dir, "toggle.trc")
    button = file_ci(event_dir, "button.trc")

    if idle and button:
        return analyze_button_event(
            vehicle=vehicle,
            event_id=event_id,
            event_dir=event_dir,
            idle_path=idle,
            button_path=button,
            args=args,
        )

    if idle and opened and toggle:
        return analyze_state_event(
            vehicle=vehicle,
            event_id=event_id,
            event_dir=event_dir,
            idle_path=idle,
            open_path=opened,
            toggle_path=toggle,
            args=args,
        )

    print(f"WARN: skip {event_dir}: expected idle+open+toggle or idle+button", file=sys.stderr)
    return None


def add_common_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--out", default="out_can_scan", help="Output directory")
    p.add_argument("--bit-order", choices=["lsb0", "msb0"], default="lsb0", help="Output BI numbering. Firmware uses lsb0.")
    p.add_argument("--trc-channel-base", type=int, default=1, help="TRC channel 1 -> firmware bus 0 by default")
    p.add_argument("--force-bus", type=int, default=None, help="Force all parsed frames to this firmware bus index, e.g. 0 or 1")
    p.add_argument("--max-dlc", type=int, default=8, help="Analyze first N data bytes. Firmware rules currently use 8 bytes.")
    p.add_argument("--min-stable-samples", type=int, default=2, help="Min frames of the same ID required to call a bit stable in idle/open")
    p.add_argument("--min-state-transitions", type=int, default=1, help="Min active/inactive transitions in toggle.trc for state events")
    p.add_argument("--min-toggle-activations", type=int, default=1, help="State mode: min active segments in toggle.trc")
    p.add_argument("--max-idle-active-samples", type=int, default=0, help="Reject a candidate if idle.trc has more active samples than this")
    p.add_argument("--min-open-active-ratio", type=float, default=1.0, help="State mode: required active ratio in open.trc; 1.0 means every sample must be active")
    p.add_argument("--allow-missing-idle-as-inactive", action="store_true", help="Treat a candidate missing from idle.trc as inactive instead of rejecting it")
    p.add_argument("--max-validation-rejected", type=int, default=200, help="Max rejected candidates to store in per-event JSON")
    p.add_argument("--dynamic-min-samples", type=int, default=8, help="Min byte samples before marking counter/checksum/dynamic suspects")
    p.add_argument("--dynamic-byte-min-unique", type=int, default=8, help="Mark byte dynamic if it has at least this many unique values")
    p.add_argument("--dynamic-transition-ratio", type=float, default=0.70, help="Mark byte dynamic if byte value changes this often between consecutive frames")
    p.add_argument("--counter-score-threshold", type=float, default=0.70, help="Mark byte/nibble as counter-like if sequential increment score reaches this")
    p.add_argument("--checksum-min-unique", type=int, default=12, help="Checksum/CRC suspect: min unique byte values")
    p.add_argument("--checksum-transition-ratio", type=float, default=0.80, help="Checksum/CRC suspect: min byte transition ratio")
    p.add_argument("--checksum-entropy-threshold", type=float, default=0.70, help="Checksum/CRC suspect: normalized entropy threshold")
    p.add_argument("--max-dynamic-suspects", type=int, default=300, help="Max dynamic byte suspect rows to store per event JSON and combined CSV")
    p.add_argument("--drop-ids-with-too-many-changing-bits", action="store_true", help="Hard-drop whole CAN IDs when too many payload bits change inside selected TRC source(s)")
    p.add_argument("--max-changing-bits-per-id", type=int, default=16, help="Used with --drop-ids-with-too-many-changing-bits: drop ID if more than this many bits change")
    p.add_argument("--dynamic-id-min-samples", type=int, default=8, help="Min frames of an ID in a source before checking too-many-changing-bits")
    p.add_argument("--dynamic-id-check-sources", default="idle,open,toggle,button", help="Comma-separated sources for ID-level dynamic drop: idle,open,toggle,button,all")
    p.add_argument("--dynamic-id-include-combined", action="store_true", help="Also check changing bits on all sources combined; stricter and can drop valid state IDs")
    p.add_argument("--dynamic-id-changed-bits-preview", type=int, default=48, help="How many changed bit names to store in dropped_dynamic_ids.csv/JSON")
    p.add_argument("--max-dynamic-id-drops", type=int, default=300, help="Max ID-level dynamic drop rows to store per event")
    p.add_argument("--max-bits-per-frame", type=int, default=6, help="Drop state frames with more candidate bits than this; 0 disables")
    p.add_argument("--button-max-bits-per-frame", type=int, default=16, help="Drop button frames with more candidate bits than this; 0 disables")
    p.add_argument("--max-signals-per-event", type=int, default=60, help="Limit output rules per event")
    p.add_argument("--expected-presses", type=int, default=3, help="Button mode expects exactly this many complete press-release cycles")
    p.add_argument("--allow-unreleased-last-press", action="store_true", help="Button mode: allow the recording to end while the last press is still active")
    p.add_argument("--include-event-only", action="store_true", help="Include frames absent in idle as rules, not only debug suggestions")
    p.add_argument("--event-only-if-empty", action="store_true", default=True, help="Use event-only candidates only if normal state detection found nothing")
    p.add_argument("--idle-ids-only-variant", action=argparse.BooleanOptionalAction, default=True, help="State mode: when open.trc has more frames or extra IDs, also log/write an idle_ids_only variant that analyzes only CAN IDs present in idle.trc")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Offline CAN state/button scanner for TRC recordings")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_auto = sub.add_parser("auto", help="Analyze a root directory containing vehicle/event folders")
    p_auto.add_argument("--root", required=True, help="Root directory, e.g. kia or .")
    add_common_args(p_auto)

    p_state = sub.add_parser("state", help="Analyze one state event: idle + open + toggle")
    p_state.add_argument("--event-id", type=int, required=True)
    p_state.add_argument("--vehicle", default="manual")
    p_state.add_argument("--idle", required=True)
    p_state.add_argument("--open", required=True)
    p_state.add_argument("--toggle", required=True)
    add_common_args(p_state)

    p_button = sub.add_parser("button", help="Analyze one button event: idle + button")
    p_button.add_argument("--event-id", type=int, required=True)
    p_button.add_argument("--vehicle", default="manual")
    p_button.add_argument("--idle", required=True)
    p_button.add_argument("--button", required=True)
    add_common_args(p_button)

    return parser


def print_summary(results: List[EventResult]) -> None:
    if not results:
        print("No events analyzed")
        return
    print("\nSummary:")
    print(f"{'vehicle':12} {'event':>5} {'mode':20} {'rules':>5} {'susp':>5} {'dyn':>5} {'drop_id':>7} {'dropped':>7} {'reject':>7}  rule")
    print("-" * 146)
    for r in sorted(results, key=lambda x: (x.vehicle, x.event_id)):
        print(f"{r.vehicle:12} {r.event_id:5d} {r.mode:20} {len(r.candidates):5d} {sum(1 for c in r.candidates if c.suspect):5d} {len(r.dynamic_suspects):5d} {len(r.dropped_dynamic_ids):7d} {len(r.dropped_busy_frames):7d} {len(r.validation_rejected):7d}  {r.rule_line}")
        for v in r.alternate_variants:
            mode_name = f"{r.mode}/{v.name}"
            print(f"{r.vehicle:12} {r.event_id:5d} {mode_name:20} {len(v.candidates):5d} {sum(1 for c in v.candidates if c.suspect):5d} {len(r.dynamic_suspects):5d} {len(r.dropped_dynamic_ids):7d} {len(v.dropped_busy_frames):7d} {len(v.validation_rejected):7d}  {v.rule_line}")
            if v.note:
                print(f"  NOTE: {v.note}")
        for w in r.warnings:
            print(f"  WARN: {w}")

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    out_dir = Path(args.out)
    results: List[EventResult] = []

    if args.cmd == "auto":
        root = Path(args.root)
        for vehicle, event_id, event_dir in discover_event_dirs(root):
            result = analyze_event_dir(vehicle, event_id, event_dir, args)
            if result is None:
                continue
            results.append(result)
            write_event_outputs(result, out_dir, args.bit_order)

    elif args.cmd == "state":
        result = analyze_state_event(
            vehicle=args.vehicle,
            event_id=args.event_id,
            event_dir=Path(args.idle).resolve().parent,
            idle_path=Path(args.idle),
            open_path=Path(args.open),
            toggle_path=Path(args.toggle),
            args=args,
        )
        results.append(result)
        write_event_outputs(result, out_dir, args.bit_order)

    elif args.cmd == "button":
        result = analyze_button_event(
            vehicle=args.vehicle,
            event_id=args.event_id,
            event_dir=Path(args.idle).resolve().parent,
            idle_path=Path(args.idle),
            button_path=Path(args.button),
            args=args,
        )
        results.append(result)
        write_event_outputs(result, out_dir, args.bit_order)

    write_combined_outputs(results, out_dir, args.bit_order)
    print_summary(results)
    print(f"\nOutput written to: {out_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
