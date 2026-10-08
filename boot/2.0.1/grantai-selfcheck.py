#!/usr/bin/env python3
"""GrantAi self-check: proves a deployed server records, recalls and verifies.

Runs at the end of first boot and on demand (`grantai-ctl selfcheck`). Exits
non-zero with a named step so the Custom Script Extension, and therefore the
Azure deployment, shows Failed when the record is not working.

Standard library only. Steps and exit codes:
  20 health       /health reachable, status healthy, dataset_loaded, backend
  21 auth         no token -> 401
  22 teach        one record sealed into source selfcheck/<utc stamp>
  23 infer        the record comes back verbatim with that source
  24 verify       verify_chain intact, count >= 1
  25 cold         (if --cold) cold status enabled and the test record archived
  26 tombstone    delete_source leaves a tombstone; verify_chain accounted

Usage: grantai-selfcheck.py --base https://127.0.0.1:8443 --token-file /opt/grantai/etc/grantai.env
         [--cacert /opt/grantai/etc/tls.crt] [--install-id inst-...] [--backend postgres] [--cold]
         [--json /opt/grantai/var/selfcheck.json]
"""
import argparse, datetime, json, ssl, sys, time, urllib.request, urllib.error


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--token")
    ap.add_argument("--token-file", help="env file holding GRANTAI_HTTP_TOKEN=...")
    ap.add_argument("--cacert")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (tests only)")
    ap.add_argument("--install-id")
    ap.add_argument("--backend", default="postgres")
    ap.add_argument("--cold", action="store_true")
    ap.add_argument("--json")
    ap.add_argument("--timeout", type=int, default=90)
    a = ap.parse_args()

    token = a.token
    if not token and a.token_file:
        for line in open(a.token_file):
            if line.startswith("GRANTAI_HTTP_TOKEN="):
                token = line.strip().split("=", 1)[1]
    if not token:
        sys.exit("no token")

    ctx = ssl.create_default_context(cafile=a.cacert) if a.cacert else (ssl._create_unverified_context() if a.insecure else ssl.create_default_context())
    steps, t0 = [], time.time()

    def call(path, body=None, auth=True, timeout=60):
        req = urllib.request.Request(a.base + path, data=json.dumps(body).encode() if body is not None else None,
                                     method="POST" if body is not None else "GET")
        if auth: req.add_header("Authorization", "Bearer " + token)
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json, text/event-stream")
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, json.loads(r.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read().decode() or "{}")
            except Exception:
                return e.code, {}

    def tool(name, args):
        st, r = call("/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}})
        if st != 200 or "result" not in r:
            return st, None
        txt = r["result"]["content"][0]["text"].split("\n---")[0]
        try:
            return st, json.loads(txt)
        except Exception:
            return st, {"raw": txt}

    created = {"source": None}

    def cleanup():
        if created["source"]:
            try: tool("grantai_delete_source", {"source": created["source"]})
            except Exception: pass
            created["source"] = None

    def fail(code, step, detail):
        steps.append({"step": step, "ok": False, "detail": detail})
        cleanup()
        finish(False)
        print(f"SELFCHECK FAILED at {step}: {detail}", file=sys.stderr)
        sys.exit(code)

    def finish(ok):
        out = {"ok": ok, "steps": steps, "duration_ms": int((time.time() - t0) * 1000),
               "finished_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}
        if a.json:
            with open(a.json, "w") as f:
                json.dump(out, f, indent=2)
        print(json.dumps(out))

    # 20 health, waiting for the service to come up
    deadline = time.time() + a.timeout
    h = None
    last_err = None
    while time.time() < deadline:
        try:
            st, h = call("/health", timeout=10)
            if st == 200 and h:
                break
        except urllib.error.URLError as e:   # connection refused while the service starts, TLS errors
            last_err = e.reason
        time.sleep(2)
    if h is None and last_err is not None:
        fail(20, "health", f"unreachable: {last_err}")
    if not h or h.get("status") != "healthy":
        fail(20, "health", f"status={h.get('status') if h else 'unreachable'} {h}")
    if not h.get("dataset_loaded"):
        fail(20, "health", "dataset_loaded is false")
    if a.backend and h.get("backend") != a.backend:
        fail(20, "health", f"backend={h.get('backend')} expected {a.backend}")
    if a.install_id and h.get("install_id") != a.install_id:
        fail(20, "health", f"install_id={h.get('install_id')} expected {a.install_id}")
    lic = h.get("licence")
    if lic and lic.get("state") not in ("valid", "grace"):
        fail(20, "health", f"licence state {lic.get('state')}")
    steps.append({"step": "health", "ok": True, "detail": {k: h.get(k) for k in ("server_version", "engine_version", "backend", "install_id")}})

    # 21 auth
    st, _ = call("/health", auth=False)
    if st != 401:
        fail(21, "auth", f"anonymous /health returned {st}, expected 401")
    steps.append({"step": "auth", "ok": True})

    # 22 teach
    stamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    source = f"selfcheck/{stamp}"
    sentence = f"GrantAi self-check record {stamp}: this installation seals, recalls and verifies."
    st, r = tool("grantai_teach", {"content": sentence, "source": source, "speaker": "selfcheck"})
    created["source"] = source
    if not r or r.get("status") != "stored":
        fail(22, "teach", f"{st} {r}")
    steps.append({"step": "teach", "ok": True, "detail": {"seq": r.get("seq"), "sha256": r.get("sha256")}})

    # 23 infer
    st, r = tool("grantai_infer", {"input": f"self-check record {stamp} seals recalls verifies", "recall": 5})
    hits = (r or {}).get("results") or []
    if not hits or r.get("no_match") or not any(h.get("source") == source for h in hits):
        fail(23, "infer", f"hits {[h.get('source') for h in hits]}, no_match={r.get('no_match') if r else None}")
    steps.append({"step": "infer", "ok": True, "detail": {"latency_ms": (r.get("meta") or {}).get("latency_ms")}})

    # 24 verify
    st, r = tool("grantai_verify_chain", {})
    if not r or not r.get("intact") or int(r.get("count", 0)) < 1:
        fail(24, "verify", f"{r}")
    steps.append({"step": "verify", "ok": True, "detail": {"count": r.get("count"), "head": r.get("head_hash")}})

    # 25 cold tier
    if a.cold:
        st, c = call("/api/cold/status")
        if st != 200 or not c.get("enabled"):
            fail(25, "cold", f"status {st} {c}")
        st, c = call("/api/cold/archive", {"source_id": source})
        if st != 200 or c.get("status") != "archived":
            fail(25, "cold", f"archive {st} {c}")
        steps.append({"step": "cold", "ok": True, "detail": {"blob": c.get("blob")}})

    # 26 tombstone
    st, r = tool("grantai_delete_source", {"source": source})
    created["source"] = None
    st, v = tool("grantai_verify_chain", {})
    if not v or not v.get("intact") or not v.get("accounted", True):
        fail(26, "tombstone", f"{v}")
    steps.append({"step": "tombstone", "ok": True, "detail": {"deleted": v.get("deleted"), "delete_events": v.get("delete_events")}})

    finish(True)


if __name__ == "__main__":
    main()
