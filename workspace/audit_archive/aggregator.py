"""Recoverable aggregation engine.

Per source the aggregator persists: the confirmed chain prefix
(``last_confirmed_seq`` + head digest), queued candidate segments, pending
conflicts and quarantine state. Confirmation is a deterministic function of
the stored candidates, so any number of workers applying the same segment set
converge to the same confirmed positions and the same archive root.

Safety invariants enforced here:
  * signatures are verified before a segment can influence any state;
  * a source confirms sequence numbers strictly in order from genesis — a
    missing predecessor is never skipped;
  * an already-confirmed segment is never counted twice;
  * two different contents for the same (source, seq) quarantine the source
    and are preserved as evidence without touching confirmed state;
  * lifting a quarantine requires a human decision with a reason, after which
    the follow-on chain is re-validated; rejected versions stay in evidence.
"""
from __future__ import annotations

import json

from . import crypto
from .models import digest_of, validate_segment_shape
from .store import Store, utcnow_iso


def _row_to_segment(row) -> dict:
    return {
        "source": row["source"],
        "seq": row["seq"],
        "prev_digest": row["prev_digest"],
        "payload_digest": row["payload_digest"],
        "signature": row["signature"],
    }


def _compute_gaps(last_confirmed: int, candidate_seqs: list[int]) -> list[int]:
    """Sequence numbers missing between the confirmed head and queued candidates."""
    gaps: list[int] = []
    expected = last_confirmed + 1
    for seq in sorted(candidate_seqs):
        while expected < seq:
            gaps.append(expected)
            expected += 1
        expected = max(expected, seq + 1)
    return gaps


class Aggregator:
    def __init__(self, store: Store, keys: dict[str, str], threshold: int):
        if threshold < 1:
            raise ValueError("threshold must be >= 1")
        self.store = store
        self.keys = dict(keys)
        self.threshold = threshold

    # ------------------------------------------------------------------ ingest

    def ingest(self, seg: dict) -> dict:
        """Validate and apply one segment; safe to call concurrently."""
        err = validate_segment_shape(seg)
        if err:
            return {"status": "rejected", "reason": err}
        source, seq = seg["source"], seg["seq"]
        digest = digest_of(seg)
        key = self.keys.get(source)
        if key is None:
            return {"status": "rejected", "reason": "unknown-source"}
        if not crypto.verify_segment_signature(key, seg):
            return {"status": "rejected", "reason": "bad-signature"}
        with self.store.tx() as conn:
            return self._ingest_locked(conn, seg, digest)

    def ingest_many(self, segments) -> list[dict]:
        """Apply a batch; each segment commits separately so an interrupted
        batch leaves the store consistent and can simply be resumed/replayed."""
        return [self.ingest(seg) for seg in segments]

    def _ingest_locked(self, conn, seg: dict, digest: str) -> dict:
        source, seq = seg["source"], seg["seq"]
        self._ensure_source(conn, source)
        srow = self._source_row(conn, source)

        if srow["quarantined"]:
            cid = self._pending_conflict_id(conn, source)
            self._add_evidence(conn, source, seq, digest, seg, "source-quarantined", cid)
            return {"status": "quarantined", "digest": digest}

        conf = conn.execute(
            "SELECT * FROM confirmed WHERE source=? AND seq=?", (source, seq)
        ).fetchone()
        if conf is not None:
            if conf["digest"] == digest:
                return {"status": "duplicate", "where": "confirmed", "digest": digest}
            cid = self._register_conflict(conn, source, seq, [conf["digest"], digest])
            self._add_evidence(conn, source, seq, digest, seg, "conflict-with-confirmed", cid)
            return {"status": "conflict", "conflict_id": cid, "digest": digest}

        cands = conn.execute(
            "SELECT * FROM candidates WHERE source=? AND seq=?", (source, seq)
        ).fetchall()
        if any(c["digest"] == digest for c in cands):
            return {"status": "duplicate", "where": "candidates", "digest": digest}
        if cands:
            cid = self._register_conflict(conn, source, seq, [c["digest"] for c in cands] + [digest])
            self._add_evidence(conn, source, seq, digest, seg, "conflict-with-candidate", cid)
            return {"status": "conflict", "conflict_id": cid, "digest": digest}

        conn.execute(
            "INSERT INTO candidates(source, seq, prev_digest, payload_digest, digest, signature, received_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (source, seq, seg["prev_digest"], seg["payload_digest"], digest, seg["signature"], utcnow_iso()),
        )
        confirmed_now = self._confirm_loop(conn, source)
        confirmed_seqs = [c["seq"] for c in confirmed_now]
        status = "confirmed" if any(c["digest"] == digest for c in confirmed_now) else "queued"
        return {"status": status, "digest": digest, "confirmed_seqs": confirmed_seqs}

    # -------------------------------------------------------------- confirmation

    def _confirm_loop(self, conn, source: str) -> list[dict]:
        """Greedily confirm queued candidates in chain order. Deterministic."""
        confirmed_now: list[dict] = []
        while True:
            srow = self._source_row(conn, source)
            if srow["quarantined"]:
                break
            nxt = srow["last_confirmed_seq"] + 1
            rows = conn.execute(
                "SELECT * FROM candidates WHERE source=? AND seq=? ORDER BY digest", (source, nxt)
            ).fetchall()
            if not rows:
                break
            if len(rows) > 1:  # defensive; ingest normally prevents this
                self._register_conflict(conn, source, nxt, [r["digest"] for r in rows])
                break
            row = rows[0]
            if row["prev_digest"] != srow["head_digest"]:
                # Chain-broken candidate can never confirm; park it as evidence.
                self._add_evidence(conn, source, nxt, row["digest"], _row_to_segment(row), "chain-break", None)
                conn.execute(
                    "DELETE FROM candidates WHERE source=? AND seq=? AND digest=?",
                    (source, nxt, row["digest"]),
                )
                continue
            conn.execute(
                "INSERT INTO confirmed(source, seq, prev_digest, payload_digest, digest, signature, confirmed_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (source, nxt, row["prev_digest"], row["payload_digest"], row["digest"], row["signature"], utcnow_iso()),
            )
            conn.execute(
                "DELETE FROM candidates WHERE source=? AND seq=? AND digest=?",
                (source, nxt, row["digest"]),
            )
            conn.execute(
                "UPDATE sources SET last_confirmed_seq=?, head_digest=? WHERE source=?",
                (nxt, row["digest"], source),
            )
            confirmed_now.append({"seq": nxt, "digest": row["digest"]})
        return confirmed_now

    def _revalidate_candidates(self, conn, source: str) -> list[dict]:
        """Re-check every queued candidate against the confirmed chain and the
        already-validated candidates below it; evict unlinkable ones to evidence.
        Called after a conflict resolution picks a new chain version."""
        confirmed = {
            r["seq"]: r["digest"]
            for r in conn.execute("SELECT seq, digest FROM confirmed WHERE source=?", (source,))
        }
        rows = conn.execute(
            "SELECT * FROM candidates WHERE source=? ORDER BY seq", (source,)
        ).fetchall()
        valid_prev: dict[int, str] = {}
        evicted: list[dict] = []
        for row in rows:
            seq = row["seq"]
            if seq == 1:
                expected = crypto.genesis_digest(source)
            elif (seq - 1) in confirmed:
                expected = confirmed[seq - 1]
            elif (seq - 1) in valid_prev:
                expected = valid_prev[seq - 1]
            else:
                continue  # predecessor unknown yet; cannot judge, keep queued
            if row["prev_digest"] == expected:
                valid_prev[seq] = row["digest"]
            else:
                evicted.append(row)
        for row in evicted:
            self._add_evidence(
                conn, source, row["seq"], row["digest"], _row_to_segment(row),
                "chain-revalidation-failed", None,
            )
            conn.execute(
                "DELETE FROM candidates WHERE source=? AND seq=? AND digest=?",
                (source, row["seq"], row["digest"]),
            )
        return [{"seq": r["seq"], "digest": r["digest"]} for r in evicted]

    # ----------------------------------------------------------------- conflicts

    def _register_conflict(self, conn, source: str, seq: int, digests: list[str]) -> int:
        row = conn.execute(
            "SELECT id, digests FROM conflicts WHERE source=? AND seq=? AND status='pending'",
            (source, seq),
        ).fetchone()
        if row is not None:
            merged = sorted(set(json.loads(row["digests"])) | set(digests))
            conn.execute("UPDATE conflicts SET digests=? WHERE id=?", (json.dumps(merged), row["id"]))
            cid = row["id"]
        else:
            cur = conn.execute(
                "INSERT INTO conflicts(source, seq, digests, status, detected_at) VALUES (?,?,?,'pending',?)",
                (source, seq, json.dumps(sorted(set(digests))), utcnow_iso()),
            )
            cid = cur.lastrowid
        conn.execute(
            "UPDATE sources SET quarantined=1, quarantine_reason=? WHERE source=?",
            (f"conflict #{cid} at seq {seq}", source),
        )
        return cid

    def resolve_conflict(self, source: str, seq: int, accepted_digest: str,
                         reason: str, decided_by: str) -> dict:
        """Human decision lifting a quarantine. Requires a non-empty reason and
        a decider; the follow-on chain is re-validated and held segments are
        reprocessed. Rejected versions remain in the evidence log."""
        if not reason or not reason.strip():
            return {"status": "error", "error": "a reason is required to lift a quarantine"}
        if not decided_by or not decided_by.strip():
            return {"status": "error", "error": "decided_by is required"}
        accepted_digest = (accepted_digest or "").strip().lower()
        with self.store.tx() as conn:
            crow = conn.execute(
                "SELECT * FROM conflicts WHERE source=? AND seq=? AND status='pending'",
                (source, seq),
            ).fetchone()
            if crow is None:
                return {"status": "error", "error": f"no pending conflict for {source} seq {seq}"}
            digests = json.loads(crow["digests"])
            if accepted_digest not in digests:
                return {"status": "error", "error": "accepted digest is not part of the conflict"}
            rejected = [d for d in digests if d != accepted_digest]

            conf = conn.execute(
                "SELECT * FROM confirmed WHERE source=? AND seq=?", (source, seq)
            ).fetchone()
            if conf is not None and conf["digest"] != accepted_digest:
                return {
                    "status": "error",
                    "error": "confirmed history cannot be rewritten; the accepted "
                             "version must be the already-confirmed one",
                }

            if conf is None:
                # Make sure the accepted version is queued as the single candidate.
                have = conn.execute(
                    "SELECT 1 FROM candidates WHERE source=? AND seq=? AND digest=?",
                    (source, seq, accepted_digest),
                ).fetchone()
                if have is None:
                    ev = conn.execute(
                        "SELECT segment_json FROM evidence WHERE source=? AND seq=? AND digest=? ORDER BY id",
                        (source, seq, accepted_digest),
                    ).fetchone()
                    if ev is None:
                        return {"status": "error", "error": "accepted version body is not available"}
                    seg = json.loads(ev["segment_json"])
                    conn.execute(
                        "INSERT OR IGNORE INTO candidates"
                        "(source, seq, prev_digest, payload_digest, digest, signature, received_at)"
                        " VALUES (?,?,?,?,?,?,?)",
                        (source, seq, seg["prev_digest"], seg["payload_digest"],
                         accepted_digest, seg["signature"], utcnow_iso()),
                    )
                for row in conn.execute(
                    "SELECT * FROM candidates WHERE source=? AND seq=? AND digest<>?",
                    (source, seq, accepted_digest),
                ).fetchall():
                    self._add_evidence(
                        conn, source, seq, row["digest"], _row_to_segment(row),
                        "rejected-by-resolution", crow["id"],
                    )
                    conn.execute(
                        "DELETE FROM candidates WHERE source=? AND seq=? AND digest=?",
                        (source, seq, row["digest"]),
                    )

            conn.execute(
                "INSERT INTO resolutions(conflict_id, source, seq, accepted_digest, rejected_digests,"
                " reason, decided_by, decided_at) VALUES (?,?,?,?,?,?,?,?)",
                (crow["id"], source, seq, accepted_digest, json.dumps(rejected),
                 reason.strip(), decided_by.strip(), utcnow_iso()),
            )
            conn.execute(
                "UPDATE conflicts SET status='resolved', resolved_at=? WHERE id=?",
                (utcnow_iso(), crow["id"]),
            )
            remaining = conn.execute(
                "SELECT COUNT(*) AS c FROM conflicts WHERE source=? AND status='pending'", (source,)
            ).fetchone()["c"]
            if remaining == 0:
                conn.execute(
                    "UPDATE sources SET quarantined=0, quarantine_reason=NULL WHERE source=?", (source,)
                )

            evicted = self._revalidate_candidates(conn, source)
            confirmed_now = self._confirm_loop(conn, source)

            # Segments that arrived while the source was quarantined were parked
            # in evidence; replay them through the normal ingest path now.
            reprocessed = []
            held = conn.execute(
                "SELECT * FROM evidence WHERE source=? AND reason='source-quarantined' ORDER BY id",
                (source,),
            ).fetchall()
            for row in held:
                seg = json.loads(row["segment_json"])
                res = self._ingest_locked(conn, seg, row["digest"])
                reprocessed.append({"digest": row["digest"], "status": res["status"]})

            return {
                "status": "resolved",
                "conflict_id": crow["id"],
                "accepted_digest": accepted_digest,
                "rejected_digests": rejected,
                "evicted": evicted,
                "confirmed_seqs": [c["seq"] for c in confirmed_now],
                "reprocessed": reprocessed,
            }

    # ------------------------------------------------------------------ publish

    def publish(self, publisher: str = "") -> dict:
        """Attempt to publish a witness for the current confirmed state.

        Single-commit semantics: the transaction serializes concurrent
        publishers, and a state that already has a published root yields
        ``already_published`` with that root instead of a new round. At most
        one concurrent publisher wins; published rounds are append-only and
        are never rewritten by late segments.
        """
        with self.store.tx() as conn:
            pending = conn.execute(
                "SELECT id, source, seq FROM conflicts WHERE status='pending' ORDER BY id"
            ).fetchall()
            if pending:
                return {
                    "status": "refused",
                    "reason": "pending-conflicts",
                    "pending": [{"conflict_id": r["id"], "source": r["source"], "seq": r["seq"]} for r in pending],
                }
            active = conn.execute(
                "SELECT source, last_confirmed_seq, head_digest FROM sources"
                " WHERE quarantined=0 AND last_confirmed_seq>0 ORDER BY source"
            ).fetchall()
            if len(active) < self.threshold:
                return {
                    "status": "refused",
                    "reason": "threshold",
                    "active_sources": len(active),
                    "threshold": self.threshold,
                }
            manifest = {}
            for row in active:
                count = conn.execute(
                    "SELECT COUNT(*) AS c FROM confirmed WHERE source=?", (row["source"],)
                ).fetchone()["c"]
                if count != row["last_confirmed_seq"]:
                    return {"status": "refused", "reason": "chain-discontinuity", "source": row["source"]}
                manifest[row["source"]] = {"last_seq": row["last_confirmed_seq"], "head": row["head_digest"]}

            root = crypto.compute_aggregate_root(manifest)
            last = conn.execute(
                "SELECT round, root FROM publications ORDER BY round DESC LIMIT 1"
            ).fetchone()
            if last is not None and last["root"] == root:
                return {"status": "already_published", "round": last["round"], "root": root}
            rnd = (last["round"] if last is not None else 0) + 1
            conn.execute(
                "INSERT INTO publications(round, root, manifest, source_count, publisher, published_at)"
                " VALUES (?,?,?,?,?,?)",
                (rnd, root, json.dumps(manifest, sort_keys=True), len(manifest), publisher, utcnow_iso()),
            )
            return {"status": "published", "round": rnd, "root": root, "manifest": manifest}

    # ------------------------------------------------------------------- status

    def status(self) -> dict:
        with self.store.tx() as conn:
            sources = {}
            for srow in conn.execute("SELECT * FROM sources ORDER BY source"):
                cand = conn.execute(
                    "SELECT seq, digest FROM candidates WHERE source=? ORDER BY seq", (srow["source"],)
                ).fetchall()
                conflicts = conn.execute(
                    "SELECT id, seq, digests, status, detected_at FROM conflicts"
                    " WHERE source=? AND status='pending' ORDER BY id",
                    (srow["source"],),
                ).fetchall()
                sources[srow["source"]] = {
                    "last_confirmed_seq": srow["last_confirmed_seq"],
                    "head_digest": srow["head_digest"],
                    "quarantined": bool(srow["quarantined"]),
                    "quarantine_reason": srow["quarantine_reason"],
                    "queued": [{"seq": c["seq"], "digest": c["digest"]} for c in cand],
                    "gaps": _compute_gaps(srow["last_confirmed_seq"], [c["seq"] for c in cand]),
                    "conflicts": [
                        {"id": c["id"], "seq": c["seq"], "digests": json.loads(c["digests"]),
                         "detected_at": c["detected_at"]}
                        for c in conflicts
                    ],
                }
            pubs = [
                {
                    "round": r["round"],
                    "root": r["root"],
                    "manifest": json.loads(r["manifest"]),
                    "source_count": r["source_count"],
                    "publisher": r["publisher"],
                    "published_at": r["published_at"],
                }
                for r in conn.execute("SELECT * FROM publications ORDER BY round")
            ]
            pending = conn.execute(
                "SELECT COUNT(*) AS c FROM conflicts WHERE status='pending'"
            ).fetchone()["c"]
            active = conn.execute(
                "SELECT COUNT(*) AS c FROM sources WHERE quarantined=0 AND last_confirmed_seq>0"
            ).fetchone()["c"]
            manifest = {
                s: {"last_seq": st["last_confirmed_seq"], "head": st["head_digest"]}
                for s, st in sources.items()
                if not st["quarantined"] and st["last_confirmed_seq"] > 0
            }
            return {
                "threshold": self.threshold,
                "configured_sources": sorted(self.keys),
                "current_round": pubs[-1]["round"] if pubs else 0,
                "published_root": pubs[-1]["root"] if pubs else None,
                "aggregate_root": crypto.compute_aggregate_root(manifest),
                "active_sources": active,
                "pending_conflicts": pending,
                "publishable": pending == 0 and active >= self.threshold,
                "sources": sources,
                "publications": pubs,
            }

    # ------------------------------------------------------------------- export

    def export_bundle(self) -> dict:
        """Full audit bundle consumed by the offline verifier."""
        with self.store.tx() as conn:
            dump = lambda q: [dict(r) for r in conn.execute(q)]
            sources = {
                r["source"]: {
                    "last_confirmed_seq": r["last_confirmed_seq"],
                    "head_digest": r["head_digest"],
                    "quarantined": bool(r["quarantined"]),
                    "quarantine_reason": r["quarantine_reason"],
                }
                for r in conn.execute("SELECT * FROM sources ORDER BY source")
            }
            manifest = {
                s: {"last_seq": st["last_confirmed_seq"], "head": st["head_digest"]}
                for s, st in sources.items()
                if not st["quarantined"] and st["last_confirmed_seq"] > 0
            }
            return {
                "format": crypto.BUNDLE_FORMAT,
                "exported_at": utcnow_iso(),
                "keys": dict(self.keys),
                "config": {"threshold": self.threshold},
                "sources": sources,
                "aggregate_root": crypto.compute_aggregate_root(manifest),
                "confirmed": dump("SELECT * FROM confirmed ORDER BY source, seq"),
                "candidates": dump("SELECT * FROM candidates ORDER BY source, seq"),
                "conflicts": dump("SELECT * FROM conflicts ORDER BY id"),
                "resolutions": dump("SELECT * FROM resolutions ORDER BY id"),
                "evidence": dump("SELECT * FROM evidence ORDER BY id"),
                "publications": dump("SELECT * FROM publications ORDER BY round"),
            }

    # ------------------------------------------------------------------ helpers

    def _ensure_source(self, conn, source: str):
        conn.execute(
            "INSERT OR IGNORE INTO sources(source, quarantined, quarantine_reason,"
            " last_confirmed_seq, head_digest) VALUES (?,0,NULL,0,?)",
            (source, crypto.genesis_digest(source)),
        )

    def _source_row(self, conn, source: str):
        return conn.execute("SELECT * FROM sources WHERE source=?", (source,)).fetchone()

    def _pending_conflict_id(self, conn, source: str):
        row = conn.execute(
            "SELECT id FROM conflicts WHERE source=? AND status='pending' ORDER BY id LIMIT 1",
            (source,),
        ).fetchone()
        return row["id"] if row else None

    def _add_evidence(self, conn, source, seq, digest, seg, reason, conflict_id):
        conn.execute(
            "INSERT INTO evidence(source, seq, digest, segment_json, reason, conflict_id, recorded_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (source, seq, digest, json.dumps(seg, sort_keys=True), reason, conflict_id, utcnow_iso()),
        )
