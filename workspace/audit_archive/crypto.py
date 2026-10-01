"""Cryptographic and canonicalization primitives for the audit archive.

Signatures are HMAC-SHA256 over the canonical JSON of the segment header.
In this offline audit setting the key-ceremony system provisions one secret
per source and the auditor holds the full registry; the module boundary is
deliberately narrow so an asymmetric scheme (Ed25519 etc.) can be dropped in
by replacing ``sign_segment`` / ``verify_segment_signature`` without touching
any chain, aggregation or publication logic.
"""
from __future__ import annotations

import hashlib
import hmac
import json

BUNDLE_FORMAT = "audit-archive-bundle/v1"
_ROOT_DOMAIN = "audit-archive/root/v1"
_GENESIS_DOMAIN = "audit-archive/genesis/v1:"
_KEY_DOMAIN = "audit-archive/key/v1:"


def canonical_bytes(obj) -> bytes:
    """Deterministic JSON encoding used for every hashed/signed structure."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj) -> str:
    return sha256_hex(canonical_bytes(obj))


def genesis_digest(source: str) -> str:
    """Virtual predecessor of sequence number 1 for a source chain."""
    return sha256_hex((_GENESIS_DOMAIN + source).encode("utf-8"))


def segment_signing_payload(source: str, seq: int, prev_digest: str, payload_digest: str) -> bytes:
    return canonical_bytes(
        {
            "source": source,
            "seq": seq,
            "prev_digest": prev_digest,
            "payload_digest": payload_digest,
        }
    )


def segment_digest(source: str, seq: int, prev_digest: str, payload_digest: str) -> str:
    return sha256_hex(segment_signing_payload(source, seq, prev_digest, payload_digest))


def sign_segment(key_hex: str, source: str, seq: int, prev_digest: str, payload_digest: str) -> str:
    key = bytes.fromhex(key_hex)
    return hmac.new(key, segment_signing_payload(source, seq, prev_digest, payload_digest), hashlib.sha256).hexdigest()


def verify_segment_signature(key_hex: str, seg: dict) -> bool:
    try:
        expected = sign_segment(key_hex, seg["source"], int(seg["seq"]), seg["prev_digest"], seg["payload_digest"])
    except (KeyError, ValueError, TypeError):
        return False
    return hmac.compare_digest(expected, str(seg.get("signature", "")))


def compute_aggregate_root(manifest: dict) -> str:
    """Archive root over the confirmed heads of all included sources.

    ``manifest`` maps source id -> {"last_seq": int, "head": hex digest}.
    Canonical JSON makes the root a pure function of the confirmed state, so
    independent workers processing the same segments converge to the same root.
    """
    return hash_obj({"domain": _ROOT_DOMAIN, "manifest": manifest})


def make_key(seed: str) -> str:
    """Derive a per-source key from a ceremony seed (demo/provisioning helper)."""
    return sha256_hex((_KEY_DOMAIN + seed).encode("utf-8"))
