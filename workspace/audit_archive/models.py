"""Segment model helpers and a source-node simulator used by tests and demos."""
from __future__ import annotations

from . import crypto

SEGMENT_FIELDS = ("source", "seq", "prev_digest", "payload_digest", "signature")
_HEX64 = set("0123456789abcdef")


def _is_hex64(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in _HEX64 for c in value.lower())


def validate_segment_shape(seg) -> str | None:
    """Return None if the segment is structurally valid, else an error string."""
    if not isinstance(seg, dict):
        return "segment must be a JSON object"
    for field in SEGMENT_FIELDS:
        if field not in seg:
            return f"missing field: {field}"
    if not isinstance(seg["source"], str) or not seg["source"]:
        return "source must be a non-empty string"
    if not isinstance(seg["seq"], int) or isinstance(seg["seq"], bool) or seg["seq"] < 1:
        return "seq must be a positive integer"
    if not _is_hex64(seg["prev_digest"]):
        return "prev_digest must be 64 hex chars"
    if not _is_hex64(seg["payload_digest"]):
        return "payload_digest must be 64 hex chars"
    if not _is_hex64(seg["signature"]):
        return "signature must be 64 hex chars"
    return None


def digest_of(seg: dict) -> str:
    return crypto.segment_digest(seg["source"], seg["seq"], seg["prev_digest"], seg["payload_digest"])


class SourceNode:
    """Simulates a key-ceremony region/node exporting a signed segment chain."""

    def __init__(self, source: str, key_hex: str, seq: int = 0, head: str | None = None):
        self.source = source
        self.key_hex = key_hex
        self.seq = seq
        self.head = head if head is not None else crypto.genesis_digest(source)

    def fork(self) -> "SourceNode":
        """Clone at the current position; used to model equivocating sources."""
        return SourceNode(self.source, self.key_hex, self.seq, self.head)

    def emit(self, payload: str) -> dict:
        self.seq += 1
        seg = {
            "source": self.source,
            "seq": self.seq,
            "prev_digest": self.head,
            "payload_digest": crypto.hash_obj({"payload": payload}),
        }
        seg["signature"] = crypto.sign_segment(
            self.key_hex, seg["source"], seg["seq"], seg["prev_digest"], seg["payload_digest"]
        )
        self.head = digest_of(seg)
        return seg
