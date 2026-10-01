"""Offline verifier.

Recomputes every source chain and the aggregate root from an exported bundle
(segments + checkpoint + conflict dispositions + publication manifest) and
reports any of: deleted segments, swapped segments, forged signatures, chain
breaks, double-counted segments, skipped gaps, publications made while a
conflict was pending, and tampered publication roots.

Usage: ``python -m audit_archive.verifier bundle.json`` (exit code 0 = clean).
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict

from . import crypto
from .models import digest_of


def verify_bundle(bundle: dict) -> list[dict]:
    """Return a list of findings; an empty list means the bundle is clean."""
    findings: list[dict] = []

    def fail(code: str, message: str):
        findings.append({"code": code, "message": message})

    if not isinstance(bundle, dict) or bundle.get("format") != crypto.BUNDLE_FORMAT:
        return [{"code": "bad-format", "message": "not an audit-archive-bundle/v1 document"}]

    keys = bundle.get("keys") or {}
    threshold = (bundle.get("config") or {}).get("threshold")
    sources_state = bundle.get("sources") or {}
    confirmed = bundle.get("confirmed") or []
    candidates = bundle.get("candidates") or []
    conflicts = bundle.get("conflicts") or []
    resolutions = bundle.get("resolutions") or []
    publications = bundle.get("publications") or []

    # ---- 1. per-segment integrity of the confirmed log -----------------------
    by_source: dict[str, list[dict]] = defaultdict(list)
    seen: set[tuple[str, int]] = set()
    for seg in confirmed:
        where = f"confirmed {seg.get('source')}#{seg.get('seq')}"
        try:
            recomputed = digest_of(seg)
        except Exception:
            fail("segment-digest-mismatch", f"{where}: cannot recompute digest")
            continue
        if recomputed != seg.get("digest"):
            fail("segment-digest-mismatch", f"{where}: stored digest does not match content")
        key = keys.get(seg.get("source"))
        if key is None:
            fail("unknown-source", f"{where}: source has no registered key")
        elif not crypto.verify_segment_signature(key, seg):
            fail("bad-signature", f"{where}: signature does not verify")
        pair = (seg.get("source"), seg.get("seq"))
        if pair in seen:
            fail("double-count", f"{where}: segment counted more than once")
        seen.add(pair)
        by_source[seg.get("source")].append(seg)

    # ---- 2. per-source chain continuity and linkage --------------------------
    heads: dict[str, dict] = {}
    for source, segs in by_source.items():
        segs.sort(key=lambda s: s["seq"])
        seqs = [s["seq"] for s in segs]
        expected_seqs = list(range(1, len(segs) + 1))
        if seqs != expected_seqs:
            fail(
                "chain-gap",
                f"{source}: confirmed sequence numbers {seqs} are not a contiguous "
                f"prefix 1..{len(segs)} (deleted segment or skipped gap)",
            )
        expected_prev = crypto.genesis_digest(source)
        for seg in segs:
            if seg["prev_digest"] != expected_prev:
                fail(
                    "chain-break",
                    f"{source}#{seg['seq']}: prev_digest does not match the digest of "
                    f"the preceding confirmed segment",
                )
            expected_prev = seg["digest"]
        heads[source] = {"last_seq": seqs[-1], "head": expected_prev}

    # ---- 3. checkpoint (sources table) matches the recomputed chains ---------
    for source, st in sources_state.items():
        last = st.get("last_confirmed_seq", 0)
        if last > 0 and source not in heads:
            fail("missing-source-data", f"{source}: checkpoint claims {last} confirmed "
                                        f"segments but the log has none")
            continue
        if source in heads:
            if heads[source]["last_seq"] != last:
                fail("head-mismatch", f"{source}: checkpoint last_confirmed_seq={last} "
                                      f"but recomputed chain ends at {heads[source]['last_seq']}")
            if heads[source]["head"] != st.get("head_digest"):
                fail("head-mismatch", f"{source}: checkpoint head digest does not match "
                                      f"the recomputed chain head")

    # ---- 4. candidates must be authentic and must not overlap confirmed ------
    for seg in candidates:
        where = f"candidate {seg.get('source')}#{seg.get('seq')}"
        try:
            if digest_of(seg) != seg.get("digest"):
                fail("candidate-digest-mismatch", f"{where}: stored digest does not match content")
        except Exception:
            fail("candidate-digest-mismatch", f"{where}: cannot recompute digest")
        key = keys.get(seg.get("source"))
        if key is None:
            fail("unknown-source", f"{where}: source has no registered key")
        elif not crypto.verify_segment_signature(key, seg):
            fail("bad-signature", f"{where}: signature does not verify")
        if (seg.get("source"), seg.get("seq")) in seen:
            fail("confirmed-candidate-overlap", f"{where}: present in both confirmed and candidates")

    # ---- 5. conflict dispositions are well formed ----------------------------
    conflict_by_id = {c.get("id"): c for c in conflicts}
    for res in resolutions:
        crow = conflict_by_id.get(res.get("conflict_id"))
        if crow is None:
            fail("resolution-unknown-conflict", f"resolution #{res.get('id')} references "
                                                f"unknown conflict {res.get('conflict_id')}")
            continue
        if res.get("accepted_digest") not in (json.loads(crow["digests"]) if isinstance(crow.get("digests"), str) else crow.get("digests", [])):
            fail("resolution-accepted-not-in-conflict",
                 f"resolution #{res.get('id')}: accepted digest was never part of the conflict")
        if not res.get("reason"):
            fail("resolution-missing-reason", f"resolution #{res.get('id')} has no reason")

    for source, st in sources_state.items():
        if st.get("quarantined"):
            has_pending = any(c.get("source") == source and c.get("status") == "pending" for c in conflicts)
            if not has_pending:
                fail("quarantine-without-conflict", f"{source}: quarantined but no pending conflict recorded")

    # ---- 6. current aggregate root -------------------------------------------
    manifest_now = {
        s: {"last_seq": st["last_confirmed_seq"], "head": st["head_digest"]}
        for s, st in sources_state.items()
        if not st.get("quarantined") and st.get("last_confirmed_seq", 0) > 0
    }
    recomputed_root = crypto.compute_aggregate_root(manifest_now)
    if bundle.get("aggregate_root") is not None and bundle["aggregate_root"] != recomputed_root:
        fail("aggregate-root-mismatch", "exported aggregate root does not match the recomputed one")

    # ---- 7. publications ------------------------------------------------------
    rounds = sorted(p.get("round") for p in publications)
    if rounds != list(range(1, len(rounds) + 1)):
        fail("round-sequence", f"publication rounds {rounds} are not contiguous from 1")
    for pub in sorted(publications, key=lambda p: p.get("round", 0)):
        rnd = pub.get("round")
        manifest = pub.get("manifest")
        if isinstance(manifest, str):
            manifest = json.loads(manifest)
        manifest = manifest or {}
        if threshold is not None and len(manifest) < threshold:
            fail("threshold-violation",
                 f"round {rnd}: published with {len(manifest)} sources below threshold {threshold}")
        if pub.get("source_count") is not None and pub["source_count"] != len(manifest):
            fail("publish-root-mismatch", f"round {rnd}: source_count does not match manifest")
        if crypto.compute_aggregate_root(manifest) != pub.get("root"):
            fail("publish-root-mismatch", f"round {rnd}: published root does not match its manifest")
        for source, entry in manifest.items():
            segs = by_source.get(source)
            if segs is None or len(segs) < entry["last_seq"]:
                fail("published-history-missing",
                     f"round {rnd}: manifest references {source} up to seq {entry['last_seq']} "
                     f"but the confirmed log does not contain it")
            elif segs[entry["last_seq"] - 1]["digest"] != entry["head"]:
                fail("published-history-mismatch",
                     f"round {rnd}: published head of {source} at seq {entry['last_seq']} "
                     f"does not match the confirmed log (history rewritten)")
        published_at = pub.get("published_at") or ""
        for crow in conflicts:
            detected = crow.get("detected_at") or ""
            resolved_at = crow.get("resolved_at")
            if detected and detected <= published_at:
                if crow.get("status") == "pending" or not resolved_at or resolved_at > published_at:
                    fail("publish-with-pending-conflict",
                         f"round {rnd}: conflict #{crow.get('id')} "
                         f"({crow.get('source')}#{crow.get('seq')}) was unresolved at publish time")

    return findings


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 1:
        print("usage: python -m audit_archive.verifier <bundle.json>", file=sys.stderr)
        return 2
    with open(argv[0], "r", encoding="utf-8") as fh:
        bundle = json.load(fh)
    findings = verify_bundle(bundle)
    if not findings:
        print("OK: bundle verifies cleanly")
        return 0
    print(f"FAILED: {len(findings)} finding(s)")
    for f in findings:
        print(f"  [{f['code']}] {f['message']}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
