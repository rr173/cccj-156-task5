"""Command line entry point.

  python -m audit_archive serve --db audit.db --port 8080 --threshold 2 --keys keys.json
  python -m audit_archive genkeys region-a region-b region-c --out keys.json
  python -m audit_archive verify bundle.json
  python -m audit_archive demo --db demo.db --bundle bundle.json
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys

from . import crypto
from .aggregator import Aggregator
from .models import SourceNode, digest_of
from .server import make_server
from .store import Store
from .verifier import verify_bundle


def _load_keys(path: str | None, demo_sources: int) -> dict:
    if path:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    if demo_sources:
        return {f"region-{chr(97 + i)}": crypto.make_key(f"demo-{chr(97 + i)}") for i in range(demo_sources)}
    raise SystemExit("serve requires --keys <file> or --demo-sources N")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="audit_archive")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_serve = sub.add_parser("serve", help="run the HTTP API + dashboard")
    p_serve.add_argument("--db", required=True)
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8080)
    p_serve.add_argument("--threshold", type=int, default=2)
    p_serve.add_argument("--keys", help="JSON file mapping source id -> key hex")
    p_serve.add_argument("--demo-sources", type=int, default=0,
                         help="generate N demo sources (keys printed to stdout)")

    p_gen = sub.add_parser("genkeys", help="create a key registry file")
    p_gen.add_argument("sources", nargs="+")
    p_gen.add_argument("--out")

    p_verify = sub.add_parser("verify", help="verify an exported bundle offline")
    p_verify.add_argument("bundle")

    p_demo = sub.add_parser("demo", help="run a scripted end-to-end scenario")
    p_demo.add_argument("--db", default="demo-audit.db")
    p_demo.add_argument("--bundle", default="demo-bundle.json")

    args = parser.parse_args(argv)

    if args.cmd == "genkeys":
        keys = {s: crypto.make_key("ceremony:" + s) for s in args.sources}
        text = json.dumps(keys, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
            print(f"wrote {args.out}")
        else:
            print(text)
        return 0

    if args.cmd == "verify":
        from .verifier import main as verify_main
        return verify_main([args.bundle])

    if args.cmd == "serve":
        keys = _load_keys(args.keys, args.demo_sources)
        if args.demo_sources and not args.keys:
            print("demo key registry (keep for the verifier):")
            print(json.dumps(keys, indent=2))
        agg = Aggregator(Store(args.db), keys, threshold=args.threshold)
        server = make_server(agg, args.host, args.port)
        print(f"serving on http://{args.host}:{args.port}  (db={args.db}, threshold={args.threshold})")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return 0

    if args.cmd == "demo":
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(args.db + suffix):
                os.remove(args.db + suffix)
        keys = {s: crypto.make_key("demo-" + s) for s in ("region-a", "region-b", "region-c")}
        nodes = {s: SourceNode(s, k) for s, k in keys.items()}
        agg = Aggregator(Store(args.db), keys, threshold=2)

        # round 1: out-of-order traffic with a duplicate
        segs = [nodes[s].emit(f"payload-{i}") for i in range(4) for s in nodes]
        random.Random(7).shuffle(segs)
        segs.append(segs[0])
        agg.ingest_many(segs)
        print("publish round 1:", agg.publish("demo-operator")["status"])

        # equivocation on region-c seq 5 -> quarantine -> human resolution
        fork = nodes["region-c"].fork()
        good = nodes["region-c"].emit("honest-5")
        bad = fork.emit("tampered-5")
        print("ingest honest seq5:", agg.ingest(good)["status"])
        print("ingest forged seq5:", agg.ingest(bad)["status"])
        print("resolve:", agg.resolve_conflict(
            "region-c", 5, digest_of(good),
            reason="key-ceremony log confirms payload honest-5", decided_by="operator-1",
        )["status"])

        # late segments -> next round
        more = [nodes[s].emit("late-5") for s in ("region-a", "region-b")]
        agg.ingest_many(more)
        print("publish round 2:", agg.publish("demo-operator")["status"])

        bundle = agg.export_bundle()
        with open(args.bundle, "w", encoding="utf-8") as fh:
            json.dump(bundle, fh, ensure_ascii=False, indent=2)
        findings = verify_bundle(bundle)
        status = agg.status()
        print(f"round={status['current_round']} root={status['published_root']}")
        print(f"bundle written to {args.bundle}; verifier findings: {len(findings)}")
        return 0 if not findings else 1

    return 2  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
