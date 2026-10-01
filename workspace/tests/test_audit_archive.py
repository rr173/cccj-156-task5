"""End-to-end tests for the audit archive module.

Run: python -m unittest discover -s tests -v
"""
from __future__ import annotations

import copy
import json
import multiprocessing
import os
import random
import shutil
import tempfile
import threading
import unittest

from audit_archive import crypto
from audit_archive.aggregator import Aggregator
from audit_archive.models import SourceNode, digest_of
from audit_archive.store import Store
from audit_archive.verifier import verify_bundle


# --------------------------------------------------------------------------- helpers

def make_world(n=3):
    names = [f"region-{chr(97 + i)}" for i in range(n)]
    keys = {s: crypto.make_key("test-key-" + s) for s in names}
    nodes = {s: SourceNode(s, keys[s]) for s in names}
    return keys, nodes


def shuffled(items, seed):
    out = list(items)
    random.Random(seed).shuffle(out)
    return out


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="audit-archive-test-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def db(self, name="audit.db"):
        return os.path.join(self.dir, name)

    def aggregator(self, keys, threshold=2, name="audit.db"):
        return Aggregator(Store(self.db(name)), keys, threshold)


def positions(agg):
    st = agg.status()
    return {s: st["sources"][s]["last_confirmed_seq"] for s in st["sources"]}


def build_rich_bundle(test: TempDirTest):
    """A bundle with out-of-order traffic, duplicates, a resolved conflict and
    two publication rounds — expected to verify cleanly."""
    keys, nodes = make_world(3)
    agg = test.aggregator(keys, threshold=2)

    segs_a = [nodes["region-a"].emit(f"a-{i}") for i in range(5)]
    segs_b = [nodes["region-b"].emit(f"b-{i}") for i in range(4)]
    segs_c = [nodes["region-c"].emit(f"c-{i}") for i in range(3)]
    traffic = shuffled(segs_a + segs_b + segs_c, seed=11)
    traffic += [segs_a[0], segs_b[1]]  # duplicates must be idempotent
    agg.ingest_many(traffic)

    # region-b equivocates at seq 5: fork before the honest emit so both
    # versions share the same predecessor but carry different content
    fork = nodes["region-b"].fork()
    b5_good = nodes["region-b"].emit("b-4-good")
    b5_bad = fork.emit("b-4-evil")
    agg.ingest(b5_good)                      # confirms (chain is intact)
    r = agg.ingest(b5_bad)                   # conflicts with confirmed
    assert r["status"] == "conflict", r
    res = agg.resolve_conflict(
        "region-b", 5, digest_of(b5_good),
        reason="ceremony transcript attests b-4-good", decided_by="auditor-1",
    )
    assert res["status"] == "resolved", res

    pub1 = agg.publish("publisher-1")
    assert pub1["status"] == "published", pub1

    # late segments -> second round
    late = [nodes["region-a"].emit("a-5"), nodes["region-c"].emit("c-3")]
    agg.ingest_many(late)
    pub2 = agg.publish("publisher-1")
    assert pub2["status"] == "published" and pub2["round"] == 2, pub2

    return agg.export_bundle(), {"keys": keys, "nodes": nodes, "agg": agg}


def codes(findings):
    return {f["code"] for f in findings}


def tamper_confirmed_segment(bundle, source, seq, **changes):
    """Apply changes to a confirmed segment, recomputing digest+signature like
    an insider with key access would."""
    for seg in bundle["confirmed"]:
        if seg["source"] == source and seg["seq"] == seq:
            seg.update(changes)
            seg["digest"] = digest_of(seg)
            seg["signature"] = crypto.sign_segment(
                bundle["keys"][source], seg["source"], seg["seq"],
                seg["prev_digest"], seg["payload_digest"],
            )
            return seg
    raise AssertionError("segment not found")


# --------------------------------------------------------------------------- aggregator

class AggregatorTests(TempDirTest):
    def test_out_of_order_backfill(self):
        keys, nodes = make_world(2)
        agg = self.aggregator(keys)
        segs = [nodes["region-a"].emit(f"p{i}") for i in range(5)]
        for seg in shuffled(segs, seed=3):
            agg.ingest(seg)
        self.assertEqual(positions(agg)["region-a"], 5)

        # a second aggregator ingesting in order must reach the identical root
        agg2 = self.aggregator(keys, name="ref.db")
        for seg in segs:
            agg2.ingest(seg)
        self.assertEqual(agg.status()["aggregate_root"], agg2.status()["aggregate_root"])

    def test_gap_not_crossed_until_predecessor_arrives(self):
        keys, nodes = make_world(1)
        node = nodes["region-a"]
        s1, s2, s3 = (node.emit(f"p{i}") for i in range(3))
        agg = self.aggregator(keys, threshold=1)
        self.assertEqual(agg.ingest(s3)["status"], "queued")
        self.assertEqual(agg.ingest(s2)["status"], "queued")
        self.assertEqual(positions(agg)["region-a"], 0)  # nothing may jump the gap
        r = agg.ingest(s1)
        self.assertEqual(r["status"], "confirmed")
        self.assertEqual(positions(agg)["region-a"], 3)  # backfill cascades
        self.assertEqual(agg.status()["sources"]["region-a"]["gaps"], [])

    def test_duplicate_upload_idempotent(self):
        keys, nodes = make_world(1)
        node = nodes["region-a"]
        segs = [node.emit(f"p{i}") for i in range(3)]
        agg = self.aggregator(keys, threshold=1)
        agg.ingest_many(segs)
        root_before = agg.status()["aggregate_root"]
        for seg in segs + segs:  # replay everything twice
            r = agg.ingest(seg)
            self.assertEqual(r["status"], "duplicate")
        st = agg.status()
        self.assertEqual(st["aggregate_root"], root_before)
        bundle = agg.export_bundle()
        self.assertEqual(len(bundle["confirmed"]), 3)  # counted exactly once

    def test_bad_signature_and_unknown_source_rejected(self):
        keys, nodes = make_world(1)
        node = nodes["region-a"]
        seg = node.emit("p0")
        agg = self.aggregator(keys, threshold=1)
        forged = dict(seg, signature="0" * 64)
        self.assertEqual(agg.ingest(forged)["reason"], "bad-signature")
        stranger = SourceNode("region-z", crypto.make_key("stranger")).emit("x")
        self.assertEqual(agg.ingest(stranger)["reason"], "unknown-source")
        # rejected segments never create or advance source state
        self.assertNotIn("region-a", agg.status()["sources"])

    def test_conflict_quarantine_preserves_confirmed_state(self):
        keys, nodes = make_world(1)
        node = nodes["region-a"]
        s1, s2 = node.emit("p1"), node.emit("p2")
        fork = node.fork()                # fork before the honest emit: same predecessor
        good3 = node.emit("honest-3")
        bad3 = fork.emit("evil-3")        # same seq, same prev, different content
        bad4 = fork.emit("evil-4")        # builds on the rejected version

        agg = self.aggregator(keys, threshold=1)
        agg.ingest(good3)          # queued: seq 1..2 missing
        agg.ingest(bad4)           # queued: predecessor unknown
        r = agg.ingest(bad3)       # different content at seq 3 -> conflict
        self.assertEqual(r["status"], "conflict")

        st = agg.status()["sources"]["region-a"]
        self.assertTrue(st["quarantined"])
        self.assertEqual(st["last_confirmed_seq"], 0)
        self.assertEqual(len(st["conflicts"]), 1)
        self.assertEqual(
            set(st["conflicts"][0]["digests"]), {digest_of(good3), digest_of(bad3)}
        )

        # while quarantined, even valid segments are held, not processed
        self.assertEqual(agg.ingest(s1)["status"], "quarantined")
        self.assertEqual(agg.ingest(s2)["status"], "quarantined")
        self.assertEqual(positions(agg)["region-a"], 0)

        # resolution requires a reason and a digest that is part of the conflict
        self.assertEqual(
            agg.resolve_conflict("region-a", 3, digest_of(good3), "", "op")["status"], "error")
        self.assertEqual(
            agg.resolve_conflict("region-a", 3, "ab" * 32, "r", "op")["status"], "error")

        res = agg.resolve_conflict(
            "region-a", 3, digest_of(good3),
            reason="ceremony log attests honest-3", decided_by="operator-1")
        self.assertEqual(res["status"], "resolved")
        # held segments were replayed after the quarantine lifted
        self.assertEqual(positions(agg)["region-a"], 3)

        # rejected version and its descendant remain in the evidence log; the
        # descendant was evicted when the follow-on chain was re-validated
        bundle = agg.export_bundle()
        ev = {(e["digest"], e["reason"]) for e in bundle["evidence"]}
        self.assertIn((digest_of(bad3), "conflict-with-candidate"), ev)
        self.assertTrue(
            any(d == digest_of(bad4) and r.startswith("chain-") for d, r in ev),
            f"bad4 must be evicted to evidence: {ev}",
        )
        self.assertEqual(len(bundle["resolutions"]), 1)
        self.assertEqual(bundle["resolutions"][0]["reason"], "ceremony log attests honest-3")

        # chain continues normally on the accepted version
        good4 = node.emit("honest-4")
        self.assertEqual(agg.ingest(good4)["status"], "confirmed")
        self.assertEqual(positions(agg)["region-a"], 4)

    def test_conflict_against_confirmed_cannot_rewrite_history(self):
        keys, nodes = make_world(1)
        node = nodes["region-a"]
        segs = [node.emit(f"p{i}") for i in range(3)]
        fork = nodes["region-a"].fork()
        fork.seq, fork.head = 2, digest_of(segs[1])
        alt3 = fork.emit("rewritten-3")

        agg = self.aggregator(keys, threshold=1)
        agg.ingest_many(segs)
        confirmed_before = [c["digest"] for c in agg.export_bundle()["confirmed"]]
        r = agg.ingest(alt3)
        self.assertEqual(r["status"], "conflict")
        # confirmed state is not polluted by the conflicting upload
        confirmed_after = [c["digest"] for c in agg.export_bundle()["confirmed"]]
        self.assertEqual(confirmed_before, confirmed_after)
        self.assertEqual(positions(agg)["region-a"], 3)

        # accepting the non-confirmed version is refused
        err = agg.resolve_conflict("region-a", 3, digest_of(alt3), "try rewrite", "op")
        self.assertEqual(err["status"], "error")
        # accepting the confirmed version lifts the quarantine
        ok = agg.resolve_conflict("region-a", 3, digest_of(segs[2]), "original stands", "op")
        self.assertEqual(ok["status"], "resolved")
        self.assertEqual(positions(agg)["region-a"], 3)
        # rejected version preserved as evidence
        digests = {e["digest"] for e in agg.export_bundle()["evidence"]}
        self.assertIn(digest_of(alt3), digests)

    def test_resume_after_crash_no_double_count_no_gap_skip(self):
        keys, nodes = make_world(2)
        segs = {s: [nodes[s].emit(f"{s}-{i}") for i in range(6)] for s in nodes}
        path = self.db()

        agg1 = Aggregator(Store(path), keys, threshold=2)
        # partial, gappy traffic before the "crash"
        agg1.ingest(segs["region-a"][0])
        agg1.ingest(segs["region-a"][2])  # queued behind a gap
        agg1.ingest_many(shuffled(segs["region-b"], seed=5))
        agg1.store.close()                # simulate process death

        # restart from the checkpoint and continue
        agg2 = Aggregator(Store(path), keys, threshold=2)
        self.assertEqual(positions(agg2)["region-a"], 1)   # confirmed state survived
        self.assertEqual(positions(agg2)["region-b"], 6)
        r = agg2.ingest(segs["region-a"][0])
        self.assertEqual(r["status"], "duplicate")         # no double counting
        self.assertEqual(positions(agg2)["region-a"], 1)   # gap still blocks
        agg2.ingest(segs["region-a"][1])                   # fill the gap
        self.assertEqual(positions(agg2)["region-a"], 3)
        agg2.ingest_many(segs["region-a"][3:])

        # equals a from-scratch sequential run
        ref = self.aggregator(keys, name="ref.db")
        ref.ingest_many(segs["region-a"] + segs["region-b"])
        self.assertEqual(agg2.status()["aggregate_root"], ref.status()["aggregate_root"])
        self.assertEqual(len(agg2.export_bundle()["confirmed"]), 12)


# --------------------------------------------------------------------------- concurrency

def _process_worker(db_path, keys, segments, queue):
    agg = Aggregator(Store(db_path), keys, threshold=1)
    for seg in segments:
        agg.ingest(seg)
    queue.put(True)


class ConcurrencyTests(TempDirTest):
    def _traffic(self, n_sources=3, per_source=8):
        keys, nodes = make_world(n_sources)
        segs = [nodes[s].emit(f"{s}-{i}") for s in nodes for i in range(per_source)]
        return keys, segs

    def _reference(self, keys, segs, name="ref.db"):
        ref = self.aggregator(keys, threshold=1, name=name)
        ref.ingest_many(shuffled(segs, seed=99))
        st = ref.status()
        return st["aggregate_root"], positions(ref)

    def test_concurrent_threads_converge(self):
        keys, segs = self._traffic()
        ref_root, ref_pos = self._reference(keys, segs)

        path = self.db("shared.db")
        # every segment is handed to two different workers (duplicates on purpose)
        assignments = [[] for _ in range(8)]
        for i, seg in enumerate(shuffled(segs, seed=1) + shuffled(segs, seed=2)):
            assignments[i % 8].append(seg)

        barrier = threading.Barrier(8)

        def worker(chunk):
            agg = Aggregator(Store(path), keys, threshold=1)
            barrier.wait()
            for seg in chunk:
                agg.ingest(seg)

        threads = [threading.Thread(target=worker, args=(c,)) for c in assignments]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        final = Aggregator(Store(path), keys, threshold=1).status()
        self.assertEqual(final["aggregate_root"], ref_root)
        self.assertEqual(positions(Aggregator(Store(path), keys, threshold=1)), ref_pos)

    @unittest.skipUnless(hasattr(os, "fork"), "requires fork")
    def test_concurrent_processes_converge(self):
        keys, segs = self._traffic(n_sources=2, per_source=6)
        ref_root, ref_pos = self._reference(keys, segs)

        path = self.db("procs.db")
        ctx = multiprocessing.get_context("fork")
        queue = ctx.Queue()
        chunks = [shuffled(segs, seed=s) for s in (1, 2, 3, 4)]  # 4x duplicated traffic
        procs = [ctx.Process(target=_process_worker, args=(path, keys, chunk, queue))
                 for chunk in chunks]
        for p in procs:
            p.start()
        for p in procs:
            p.join(60)
            self.assertEqual(p.exitcode, 0)

        final = Aggregator(Store(path), keys, threshold=1)
        self.assertEqual(final.status()["aggregate_root"], ref_root)
        self.assertEqual(positions(final), ref_pos)

    def test_concurrent_publish_single_winner(self):
        keys, segs = self._traffic(n_sources=2, per_source=4)
        path = self.db("pub.db")
        setup = Aggregator(Store(path), keys, threshold=2)
        setup.ingest_many(segs)

        results, lock = [], threading.Lock()
        barrier = threading.Barrier(6)

        def worker(i):
            agg = Aggregator(Store(path), keys, threshold=2)
            barrier.wait()
            res = agg.publish(publisher=f"pub-{i}")
            with lock:
                results.append(res)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        winners = [r for r in results if r["status"] == "published"]
        losers = [r for r in results if r["status"] == "already_published"]
        self.assertEqual(len(winners), 1, results)
        self.assertEqual(len(losers), 5, results)
        for r in results:
            self.assertEqual(r["root"], winners[0]["root"])
            self.assertEqual(r["round"], 1)
        self.assertEqual(len(setup.export_bundle()["publications"]), 1)


# --------------------------------------------------------------------------- publish

class PublishTests(TempDirTest):
    def test_threshold_insufficient_refused(self):
        keys, nodes = make_world(3)
        agg = self.aggregator(keys, threshold=3)
        agg.ingest_many([nodes["region-a"].emit("a0"), nodes["region-b"].emit("b0")])
        r = agg.publish("op")
        self.assertEqual(r["status"], "refused")
        self.assertEqual(r["reason"], "threshold")
        self.assertEqual(r["active_sources"], 2)
        agg.ingest(nodes["region-c"].emit("c0"))
        self.assertEqual(agg.publish("op")["status"], "published")

    def test_pending_conflict_blocks_publish(self):
        keys, nodes = make_world(2)
        node = nodes["region-a"]
        s1 = node.emit("a0")
        fork = node.fork()
        fork.seq, fork.head = 0, crypto.genesis_digest("region-a")
        alt1 = fork.emit("a0-alt")
        agg = self.aggregator(keys, threshold=1)
        agg.ingest(s1)
        self.assertEqual(agg.ingest(alt1)["status"], "conflict")
        r = agg.publish("op")
        self.assertEqual(r["status"], "refused")
        self.assertEqual(r["reason"], "pending-conflicts")
        agg.resolve_conflict("region-a", 1, digest_of(s1), "original attested", "op")
        self.assertEqual(agg.publish("op")["status"], "published")

    def test_late_segments_next_round_history_immutable(self):
        keys, nodes = make_world(2)
        agg = self.aggregator(keys, threshold=2)
        agg.ingest_many([nodes["region-a"].emit("a0"), nodes["region-b"].emit("b0")])
        p1 = agg.publish("op")
        self.assertEqual(p1["status"], "published")
        self.assertEqual(p1["round"], 1)

        # republishing unchanged state returns the existing root, no new round
        again = agg.publish("op")
        self.assertEqual(again["status"], "already_published")
        self.assertEqual(again["root"], p1["root"])

        # late segments confirm into the running state and form the next round
        agg.ingest_many([nodes["region-a"].emit("a1"), nodes["region-b"].emit("b1")])
        p2 = agg.publish("op")
        self.assertEqual(p2["status"], "published")
        self.assertEqual(p2["round"], 2)
        self.assertNotEqual(p2["root"], p1["root"])

        pubs = agg.export_bundle()["publications"]
        self.assertEqual([p["round"] for p in pubs], [1, 2])
        self.assertEqual(pubs[0]["root"], p1["root"])  # history not rewritten
        self.assertEqual(json.loads(pubs[0]["manifest"])["region-a"]["last_seq"], 1)

        # the offline verifier confirms both rounds against the final log
        self.assertEqual(verify_bundle(agg.export_bundle()), [])


# --------------------------------------------------------------------------- verifier

class VerifierTests(TempDirTest):
    def test_valid_bundle_passes(self):
        bundle, _ = build_rich_bundle(self)
        self.assertEqual(verify_bundle(bundle), [])

    def _tampered(self):
        bundle, _ = build_rich_bundle(self)
        return copy.deepcopy(bundle)

    def test_detect_deleted_segment(self):
        bundle = self._tampered()
        bundle["confirmed"] = [
            s for s in bundle["confirmed"]
            if not (s["source"] == "region-a" and s["seq"] == 3)
        ]
        self.assertIn("chain-gap", codes(verify_bundle(bundle)))

    def test_detect_swapped_segment(self):
        bundle = self._tampered()
        a2 = next(s for s in bundle["confirmed"] if s["source"] == "region-a" and s["seq"] == 2)
        a3 = next(s for s in bundle["confirmed"] if s["source"] == "region-a" and s["seq"] == 3)
        a2["seq"], a3["seq"] = 3, 2  # swap positions without re-signing
        self.assertIn("segment-digest-mismatch", codes(verify_bundle(bundle)))

    def test_detect_forged_signature(self):
        bundle = self._tampered()
        seg = next(s for s in bundle["confirmed"] if s["source"] == "region-a" and s["seq"] == 1)
        seg["signature"] = ("0" if seg["signature"][0] != "0" else "1") + seg["signature"][1:]
        self.assertIn("bad-signature", codes(verify_bundle(bundle)))

    def test_detect_chain_break(self):
        bundle = self._tampered()
        # insider re-links seq 3 to a fake predecessor and re-signs
        tamper_confirmed_segment(bundle, "region-a", 3, prev_digest="ab" * 32)
        self.assertIn("chain-break", codes(verify_bundle(bundle)))

    def test_detect_double_count(self):
        bundle = self._tampered()
        dup = copy.deepcopy(bundle["confirmed"][2])
        bundle["confirmed"].append(dup)
        self.assertIn("double-count", codes(verify_bundle(bundle)))

    def test_detect_gap_skip(self):
        bundle = self._tampered()
        # a well-equipped insider deletes region-c seq 2 and consistently
        # re-links the suffix (valid signatures, updated checkpoint, updated
        # publication manifests) — the sequence numbers still reveal the gap
        segs = sorted((s for s in bundle["confirmed"] if s["source"] == "region-c"),
                      key=lambda s: s["seq"])
        others = [s for s in bundle["confirmed"] if s["source"] != "region-c"]
        segs = [s for s in segs if s["seq"] != 2]
        prev = crypto.genesis_digest("region-c")
        for s in segs:
            s["prev_digest"] = prev
            s["digest"] = digest_of(s)
            s["signature"] = crypto.sign_segment(
                bundle["keys"]["region-c"], "region-c", s["seq"],
                s["prev_digest"], s["payload_digest"])
            prev = s["digest"]
        bundle["confirmed"] = others + segs
        bundle["sources"]["region-c"]["head_digest"] = segs[-1]["digest"]
        for pub in bundle["publications"]:
            manifest = json.loads(pub["manifest"])
            entry = manifest.get("region-c")
            if entry:
                match = next(s for s in segs if s["seq"] == entry["last_seq"])
                entry["head"] = match["digest"]
                pub["manifest"] = manifest
                pub["root"] = crypto.compute_aggregate_root(manifest)
        manifest_now = {
            s: {"last_seq": st["last_confirmed_seq"], "head": st["head_digest"]}
            for s, st in bundle["sources"].items()
            if not st["quarantined"] and st["last_confirmed_seq"] > 0
        }
        bundle["aggregate_root"] = crypto.compute_aggregate_root(manifest_now)
        findings = verify_bundle(bundle)
        self.assertIn("chain-gap", codes(findings))
        self.assertNotIn("chain-break", codes(findings))  # linkage is fine; the gap is the crime

    def test_detect_publish_with_pending_conflict(self):
        bundle = self._tampered()
        for c in bundle["conflicts"]:
            c["status"] = "pending"
            c["resolved_at"] = None
        self.assertIn("publish-with-pending-conflict", codes(verify_bundle(bundle)))

    def test_detect_tampered_publish_root(self):
        bundle = self._tampered()
        root = bundle["publications"][-1]["root"]
        bundle["publications"][-1]["root"] = ("f" if root[0] != "f" else "e") + root[1:]
        self.assertIn("publish-root-mismatch", codes(verify_bundle(bundle)))

    def test_detect_tampered_checkpoint_head(self):
        bundle = self._tampered()
        head = bundle["sources"]["region-a"]["head_digest"]
        bundle["sources"]["region-a"]["head_digest"] = ("0" if head[0] != "0" else "1") + head[1:]
        self.assertIn("head-mismatch", codes(verify_bundle(bundle)))


# --------------------------------------------------------------------------- HTTP

class ServerTests(TempDirTest):
    def _serve(self, name="srv.db", threshold=2):
        from audit_archive.server import make_server
        keys, nodes = make_world(2)
        agg = Aggregator(Store(self.db(name)), keys, threshold)
        server = make_server(agg, "127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server, keys, nodes

    def _url(self, server, path):
        return f"http://127.0.0.1:{server.server_address[1]}{path}"

    def _post(self, server, path, obj):
        import urllib.request
        req = urllib.request.Request(
            self._url(server, path), data=json.dumps(obj).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def _get(self, server, path):
        import urllib.request
        with urllib.request.urlopen(self._url(server, path), timeout=10) as resp:
            return resp.status, resp.read()

    def test_http_end_to_end(self):
        server, keys, nodes = self._serve()
        segs_a = [nodes["region-a"].emit(f"a{i}") for i in range(3)]
        segs_b = [nodes["region-b"].emit(f"b{i}") for i in range(3)]

        code, out = self._post(server, "/api/segments", shuffled(segs_a + segs_b, seed=4))
        self.assertEqual(code, 200)
        self.assertEqual(len(out["results"]), 6)

        code, body = self._get(server, "/api/status")
        self.assertEqual(code, 200)
        status = json.loads(body)
        self.assertTrue(status["publishable"])
        self.assertEqual(status["sources"]["region-a"]["last_confirmed_seq"], 3)

        code, pub = self._post(server, "/api/publish", {"publisher": "web-op"})
        self.assertEqual(code, 200)
        self.assertEqual(pub["status"], "published")

        code, bundle_bytes = self._get(server, "/api/export")
        self.assertEqual(verify_bundle(json.loads(bundle_bytes)), [])

        code, html = self._get(server, "/")
        self.assertEqual(code, 200)
        self.assertIn("Audit Archive".encode(), html)

        # conflict over the API, then resolution over the API
        fork = nodes["region-a"].fork()
        fork.seq, fork.head = 0, crypto.genesis_digest("region-a")
        alt1 = fork.emit("a0-alt")
        code, out = self._post(server, "/api/segments", alt1)
        self.assertEqual(out["results"][0]["status"], "conflict")
        code, pub = self._post(server, "/api/publish", {"publisher": "web-op"})
        self.assertEqual(code, 409)  # pending conflict blocks
        good1 = segs_a[0]
        code, res = self._post(server, "/api/resolve", {
            "source": "region-a", "seq": 1, "accepted_digest": digest_of(good1),
            "reason": "attested by ceremony log", "decided_by": "web-op"})
        self.assertEqual(code, 200, res)
        self.assertEqual(res["status"], "resolved")

    def test_restart_recovery_via_http(self):
        server1, keys, nodes = self._serve("restart.db")
        segs = [nodes["region-a"].emit(f"a{i}") for i in range(2)]
        segs += [nodes["region-b"].emit(f"b{i}") for i in range(2)]
        self._post(server1, "/api/segments", segs)
        self._post(server1, "/api/publish", {"publisher": "op"})
        server1.shutdown()
        server1.server_close()

        # new server process on the same database file picks up the checkpoint
        from audit_archive.server import make_server
        agg2 = Aggregator(Store(self.db("restart.db")), keys, 2)
        server2 = make_server(agg2, "127.0.0.1", 0)
        threading.Thread(target=server2.serve_forever, daemon=True).start()
        self.addCleanup(server2.server_close)
        self.addCleanup(server2.shutdown)
        code, body = self._get(server2, "/api/status")
        status = json.loads(body)
        self.assertEqual(status["current_round"], 1)
        self.assertEqual(status["sources"]["region-a"]["last_confirmed_seq"], 2)
        # late data goes to the next round after restart
        self._post(server2, "/api/segments",
                   [nodes["region-a"].emit("a2"), nodes["region-b"].emit("b2")])
        code, pub = self._post(server2, "/api/publish", {"publisher": "op2"})
        self.assertEqual(pub["status"], "published")
        self.assertEqual(pub["round"], 2)


if __name__ == "__main__":
    unittest.main()
