#!/usr/bin/env python3
"""GrantAi reviewer: a proactive agent that watches the record and raises findings.

It observes and flags; it never blocks. Every finding is sealed into the same chain under the
reviewer's own identity, citing the exact record (source, seq, sha256) it judged, so an auditor sees
what was flagged, when, on what evidence, and under which policy version. Rules are deterministic
(review-policies.json); two built-in checks run every cycle: chain verification and silent agents.

Environment (/opt/grantai/etc/reviewer.env):
  GRANTAI_REVIEW_BASE      https://127.0.0.1:<port>
  GRANTAI_REVIEW_TOKEN     static caller token for "reviewer"
  GRANTAI_REVIEW_CACERT    /opt/grantai/etc/tls.crt
  GRANTAI_REVIEW_POLICIES  /opt/grantai/etc/review-policies.json
  GRANTAI_REVIEW_STATE     /opt/grantai/var/reviewer.state.json
  GRANTAI_REVIEW_INTERVAL  seconds between cycles (default 60)
  GRANTAI_REVIEW_WEBHOOK   optional URL; each finding is POSTed as JSON
"""
import hashlib, json, os, re, ssl, sys, time, urllib.parse, urllib.request, urllib.error

BASE = os.environ.get("GRANTAI_REVIEW_BASE", "https://127.0.0.1:8443")
TOKEN = os.environ["GRANTAI_REVIEW_TOKEN"]
CACERT = os.environ.get("GRANTAI_REVIEW_CACERT", "")
POLICIES = os.environ.get("GRANTAI_REVIEW_POLICIES", "/opt/grantai/etc/review-policies.json")
STATE = os.environ.get("GRANTAI_REVIEW_STATE", "/opt/grantai/var/reviewer.state.json")
INTERVAL = int(os.environ.get("GRANTAI_REVIEW_INTERVAL", "60"))
WEBHOOK = os.environ.get("GRANTAI_REVIEW_WEBHOOK", "")
ctx = ssl.create_default_context(cafile=CACERT) if CACERT else ssl.create_default_context()   # empty: system trust store (CA-issued certificate)

def log(*a): print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), *a, flush=True)
def now(): return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def api(path, body=None, method=None):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode() if body is not None else None,
                                 method=method or ("POST" if body is not None else "GET"),
                                 headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
    with urllib.request.urlopen(req, context=ctx, timeout=60) as r: return json.loads(r.read().decode() or "{}")

def seal(content, source):
    j = api("/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "grantai_teach", "arguments": {"content": content, "source": source}}})
    if "result" not in j or j["result"].get("isError"): raise RuntimeError(f"seal refused: {j}")

def load_json(p, default):
    try: return json.load(open(p))
    except Exception: return default
def save_state(s):
    tmp = STATE + ".tmp"; json.dump(s, open(tmp, "w")); os.replace(tmp, STATE)

# ---------------------------------------------------------------- record access
def chain_rows(offset, limit=500):
    return api(f"/api/audit/chain?limit={limit}&offset={offset}").get("records", [])

def document(source):
    d = api("/api/audit/records/" + urllib.parse.quote(source, safe=""))
    body = d.get("content") or ""
    i = body.find("{")
    try: return json.loads(body[i:]) if i >= 0 else None
    except Exception: return None

# ---------------------------------------------------------------- rule evaluation
def output_text(rec): return "\n".join(o.get("text") or "" for o in rec.get("output", []) if o.get("type") == "message")
def tool_calls(rec): return [o for o in rec.get("output", []) if o.get("type") == "function_call"] + [o for o in rec.get("output", []) if o.get("type") == "mcp_call"]
def tool_results(rec):
    """Tool results this turn is answering. A conversation carries earlier turns' tool outputs in
    the input too; only the trailing run of function_call_output items belongs to this turn."""
    items = rec.get("input", []); tail = []
    for i in reversed(items):
        if i.get("type") == "function_call_output": tail.append(i)
        elif tail: break
        else: continue
    out = []
    for i in reversed(tail):
        try: out.append(json.loads(i.get("output") or "null"))
        except Exception: out.append(i.get("output"))
    return out
def path_get(obj, path):
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict): cur = cur.get(part)
        else: return None
    return cur

def evaluate(rule, rec, source):
    """Return evidence dict when every condition holds, else None."""
    ap = rule.get("applies_to", {})
    if ap.get("source_prefix") and not source.startswith(ap["source_prefix"]): return None
    if ap.get("agent") and rec.get("agent") != ap["agent"]: return None
    w = rule.get("when", {}); ev = {}
    if "output_text_matches" in w:
        m = re.search(w["output_text_matches"], output_text(rec), re.I)
        if not m: return None
        ev["output_match"] = m.group(0)[:160]
    if "tool_result" in w:
        c = w["tool_result"]; hit = None
        for tr in tool_results(rec):
            v = path_get(tr, c["path"]) if isinstance(tr, dict) else None
            if c.get("is_null") and isinstance(tr, dict) and c["path"].split(".")[0] in tr and v is None: hit = tr
            if "equals" in c and v == c["equals"]: hit = tr
        if hit is None: return None
        ev["tool_result"] = hit
    if "tool_result_number" in w:
        c = w["tool_result_number"]; hit = None
        for tr in tool_results(rec):
            v = path_get(tr, c["path"]) if isinstance(tr, dict) else None
            try: v = float(v)
            except Exception: continue
            if ("gt" in c and v > c["gt"]) or ("lt" in c and v < c["lt"]): hit = v
        if hit is None: return None
        ev[c["path"]] = hit
    if "tool_called_not_in" in w:
        allow = w["tool_called_not_in"]; agent = rec.get("agent") or "*"
        allowed = set(allow.get(agent, allow.get("*", [])))
        bad = [t.get("name") for t in tool_calls(rec) if t.get("name") and t.get("name") not in allowed]
        if not bad: return None
        ev["tools_not_allowed"] = bad
    if "field_not_in" in w:
        c = w["field_not_in"]
        if path_get(rec, c["path"]) in c["values"]: return None
        ev[c["path"]] = path_get(rec, c["path"])
    return ev

# ---------------------------------------------------------------- findings
def raise_finding(state, kind, severity, title, detail, rule_id=None, record=None, policy_sha=None):
    # keyed by the record's source, not its chain seq: a re-sealed (superseded) record is the same event
    fid = hashlib.sha256(f"{kind}|{rule_id}|{(record or {}).get('source')}|{detail.get('key','')}".encode()).hexdigest()[:16]
    if fid in state["raised"]: return False
    body = {"finding": fid, "kind": kind, "rule": rule_id, "severity": severity, "title": title,
            "record": record, "evidence": detail, "policy_sha256": policy_sha, "reviewed_at": now(),
            "reviewer": "grantai-reviewer", "action": "observe-and-flag"}
    seal(json.dumps(body, ensure_ascii=False), f"review/{rule_id or kind}/{fid}")
    state["raised"].append(fid)
    log(f"FINDING {severity} {rule_id or kind}: {title} :: {json.dumps(record or {})[:120]}")
    if WEBHOOK:
        try:
            req = urllib.request.Request(WEBHOOK, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=15).read()
        except Exception as e: log("webhook failed:", repr(e)[:120])
    return True

def cycle(state):
    pol = load_json(POLICIES, {"rules": []}); raw = open(POLICIES, "rb").read() if os.path.exists(POLICIES) else b""
    psha = hashlib.sha256(raw).hexdigest()
    if state.get("policy_sha256") != psha:   # seal the policy version before applying it
        seal(raw.decode("utf-8", "replace"), f"review/policy/{psha}")
        state["policy_sha256"] = psha; log("policy sealed", psha[:12])
    n = 0
    # 1. chain integrity
    v = api("/api/audit/verify_chain", {}, "POST")
    if not v.get("intact", False):
        n += raise_finding(state, "chain-broken", "critical", "Chain verification failed",
                           {"key": v.get("head_hash"), "first_broken_seq": v.get("first_broken_seq"), "broken": (v.get("broken") or [])[:5]})
    # 2. new records since the cursor
    offset = state.get("offset", 0); rows = chain_rows(offset)
    for row in rows:
        offset += 1
        if row.get("kind") != "teach" or row.get("deleted"): continue
        src = row.get("source", "")
        if src.startswith("review/") or src.startswith("selfcheck/"): continue
        rec = document(src)
        if not isinstance(rec, dict): continue
        if rec.get("agent"): state["last_seen"][rec["agent"]] = row.get("sealed_at") or now()
        for rule in pol.get("rules", []):
            ev = evaluate(rule, rec, src)
            if ev is not None:
                n += raise_finding(state, "rule", rule.get("severity", "medium"), rule.get("title", rule["id"]), ev, rule["id"],
                                   {"source": src, "seq": row.get("seq"), "sha256": row.get("content_sha256"), "agent": rec.get("agent"), "occurred_at": rec.get("occurred_at")}, psha)
    state["offset"] = offset
    # 3. silent agents
    hours = float(pol.get("silent_agent_hours", 24) or 0)
    if hours > 0:
        for agent, last in list(state["last_seen"].items()):
            try: t = time.mktime(time.strptime(last[:19], "%Y-%m-%dT%H:%M:%S"))
            except Exception: continue
            if time.time() - t > hours * 3600:
                n += raise_finding(state, "agent-silent", "low", f"No record from {agent} for over {int(hours)} h",
                                   {"key": last[:13], "agent": agent, "last_seen": last})
    return n, len(rows)

def withdraw(fid, reason):
    """Retract a finding on the record. The original stays sealed; the withdrawal cites it."""
    body = {"withdraws": fid, "reason": reason, "withdrawn_at": now(), "reviewer": "grantai-reviewer"}
    seal(json.dumps(body, ensure_ascii=False), f"review/withdrawn/{fid}")
    log(f"WITHDRAWN {fid}: {reason}")

def withdraw_rule(rule_id, reason):
    """Retract every finding raised by one rule, in a single sealed record listing them."""
    state = load_json(STATE, {"raised": []}); ids = []
    rows = []; offset = 0
    while True:
        page = chain_rows(offset); rows += page; offset += len(page)
        if len(page) < 500: break
    for row in rows:
        src = row.get("source", "")
        if src.startswith(f"review/{rule_id}/") and row.get("kind") == "teach" and not row.get("deleted"): ids.append(src.split("/")[-1])
    ids = sorted(set(ids))
    body = {"withdraws": ids, "rule": rule_id, "reason": reason, "withdrawn_at": now(), "reviewer": "grantai-reviewer"}
    seal(json.dumps(body, ensure_ascii=False), f"review/withdrawn/{rule_id}-{now().replace(':','').replace('-','')}")
    log(f"WITHDRAWN {len(ids)} finding(s) of rule {rule_id}: {reason}")

def main():
    if "--withdraw-rule" in sys.argv:
        i = sys.argv.index("--withdraw-rule"); withdraw_rule(sys.argv[i + 1], sys.argv[i + 2] if len(sys.argv) > i + 2 else "withdrawn by operator"); return
    if "--withdraw" in sys.argv:
        i = sys.argv.index("--withdraw"); withdraw(sys.argv[i + 1], sys.argv[i + 2] if len(sys.argv) > i + 2 else "withdrawn by operator"); return
    once = "--once" in sys.argv
    state = load_json(STATE, {"offset": 0, "raised": [], "last_seen": {}, "policy_sha256": None})
    log(f"reviewer started; policies {POLICIES}; interval {INTERVAL}s; webhook {'set' if WEBHOOK else 'none'}")
    while True:
        try:
            n, seen = cycle(state); save_state(state)
            if n or seen: log(f"reviewed {seen} new row(s), {n} new finding(s)")
        except Exception as e:
            log("cycle error:", repr(e)[:300])
        if once: return
        time.sleep(INTERVAL)

if __name__ == "__main__": main()
