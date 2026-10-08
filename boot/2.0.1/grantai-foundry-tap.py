#!/usr/bin/env python3
"""GrantAi Foundry tap: records what Azure AI Foundry agents did, with no agent configuration.

Runs on the collector VM as the service user. Reads the customer's Foundry project with the VM's
managed identity (role: Foundry User on the project) and seals every agent response (inputs,
outputs, function and MCP tool calls) from the Responses API into the system of record through the collector's own MCP endpoint, authenticated as the caller
"foundry-tap" (a static per-caller token minted at first boot). The tap is the witness: records
are attributed to the tap's credential, and the agent, thread and run identifiers are part of the
sealed content and the source id, so an auditor can see which agent did what and who observed it.

Environment (from /opt/grantai/etc/foundry-tap.env):
  GRANTAI_FOUNDRY_PROJECT_ENDPOINT  https://<account>.services.ai.azure.com/api/projects/<project>
  GRANTAI_TAP_BASE                  https://127.0.0.1:<port>
  GRANTAI_TAP_TOKEN                 static caller token for "foundry-tap"
  GRANTAI_TAP_CACERT                /opt/grantai/etc/tls.crt
  GRANTAI_TAP_INTERVAL              seconds between polls (default 20)
  GRANTAI_TAP_STATE                 /opt/grantai/var/foundry-tap.state.json
"""
import json, os, ssl, sys, time, urllib.request, urllib.error

EP = os.environ["GRANTAI_FOUNDRY_PROJECT_ENDPOINT"].rstrip("/")
BASE = os.environ.get("GRANTAI_TAP_BASE", "https://127.0.0.1:8443")
TOKEN = os.environ["GRANTAI_TAP_TOKEN"]
CACERT = os.environ.get("GRANTAI_TAP_CACERT", "")
INTERVAL = int(os.environ.get("GRANTAI_TAP_INTERVAL", "20"))
STATE = os.environ.get("GRANTAI_TAP_STATE", "/opt/grantai/var/foundry-tap.state.json")
API = "api-version=v1"
ctx = ssl.create_default_context(cafile=CACERT) if CACERT else ssl.create_default_context()   # empty: system trust store (CA-issued certificate)

def log(*a): print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), *a, flush=True)

_tok = {"v": "", "exp": 0}
def foundry_token():
    if time.time() < _tok["exp"] - 300: return _tok["v"]
    req = urllib.request.Request("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://ai.azure.com", headers={"Metadata": "true"})
    with urllib.request.urlopen(req, timeout=10) as r: j = json.loads(r.read().decode())
    _tok["v"], _tok["exp"] = j["access_token"], int(j.get("expires_on", time.time() + 3000)); return _tok["v"]

def foundry(path, versioned=True):
    url = f"{EP}{path}" + ((("&" if "?" in path else "?") + API) if versioned else "")
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + foundry_token()})
    with urllib.request.urlopen(req, timeout=60) as r: return json.loads(r.read().decode() or "{}")

def record(content, source):
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "grantai_teach", "arguments": {"content": content, "source": source}}}
    req = urllib.request.Request(BASE + "/mcp", data=json.dumps(body).encode(), method="POST",
                                 headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
    with urllib.request.urlopen(req, context=ctx, timeout=60) as r:
        j = json.loads(r.read().decode() or "{}")
    if "result" not in j or j["result"].get("isError"): raise RuntimeError(f"teach refused: {j}")
    return j["result"]

def load_state():
    try: st = json.load(open(STATE))
    except Exception: st = {}
    st.setdefault("cursor", None); st.setdefault("pending", []); st.setdefault("sealed", []); st.setdefault("agents_sealed", [])
    return st
def save_state(s):
    tmp = STATE + ".tmp"; json.dump(s, open(tmp, "w")); os.replace(tmp, STATE)

def iso(ts): return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)) if ts else ""

def items_text(items):
    out = []
    for it in items:
        t = it.get("type")
        if t == "message":
            txt = " ".join(c.get("text", "") for c in it.get("content", []) if c.get("type") in ("input_text", "output_text"))
            out.append({"type": "message", "role": it.get("role"), "text": txt})
        elif t == "function_call":
            out.append({"type": "function_call", "call_id": it.get("call_id"), "name": it.get("name"), "arguments": it.get("arguments")})
        elif t == "function_call_output":
            out.append({"type": "function_call_output", "call_id": it.get("call_id"), "output": it.get("output")})
        elif t in ("mcp_call", "mcp_approval_request", "mcp_list_tools"):
            out.append({"type": t, "server_label": it.get("server_label"), "name": it.get("name"), "arguments": it.get("arguments"), "output": it.get("output"), "error": it.get("error")})
        else:
            out.append({"type": t, "id": it.get("id")})
    return out

def seal_agent_definition(state, r):
    """Seal each agent version as it is first seen: what the agent was told, which model and tools it had."""
    ref = r.get("agent_reference") or {}
    name, ver = ref.get("name"), ref.get("version")
    if not name: return
    key = f"{name}@{ver or 'latest'}"
    if key in state.setdefault("agents_sealed", []): return
    try:
        d = foundry(f"/agents/{name}/versions/{ver}") if ver else foundry(f"/agents/{name}")
    except Exception as e:
        log("agent definition unavailable", key, repr(e)[:120]); return
    body = {"platform": "azure-ai-foundry", "project": EP, "agent": name, "version": ver,
            "definition": d.get("definition"), "description": d.get("description"), "created_at": d.get("created_at"),
            "sealed_by": "foundry-tap", "note": "agent definition as served by the platform when this version was first observed"}
    record(json.dumps(body, ensure_ascii=False), f"foundry/agents/{name}/v{ver or 'latest'}")
    state["agents_sealed"].append(key); log("sealed agent definition", key)

def seal_response(r, state=None):
    """One sealed record per agent turn: who (agent), where (conversation), inputs, outputs incl. tool calls.
    Idempotent: a response id already sealed is never sealed again, whatever the cursor says."""
    rid = r["id"]
    if state is not None and rid in state["sealed"]: return False
    agent = (r.get("agent_reference") or {}).get("name") or "model:" + str(r.get("model"))
    conv = (r.get("conversation") or {}).get("id") or ""
    try: inputs = items_text(foundry(f"/openai/v1/responses/{rid}/input_items", versioned=False).get("data", []))
    except Exception as e: inputs = [{"type": "unavailable", "error": repr(e)[:120]}]
    body = {"platform": "azure-ai-foundry", "project": EP, "agent": agent, "agent_version": (r.get("agent_reference") or {}).get("version"),
            "conversation": conv, "response": rid, "model": r.get("model"), "status": r.get("status"),
            "occurred_at": iso(r.get("created_at")), "sealed_by": "foundry-tap",
            "input": inputs, "output": items_text(r.get("output", [])), "usage": r.get("usage"), "error": r.get("error")}
    record(json.dumps(body, ensure_ascii=False), f"foundry/{agent}/{conv or 'no-conversation'}/{rid}")
    if state is not None:
        state["sealed"].append(rid); state["sealed"] = state["sealed"][-5000:]; save_state(state)
    return True

def sweep(state):
    """Responses are listed oldest first from the cursor; a response still in progress is retried next sweep."""
    n, after, pending = 0, state.get("cursor"), []
    for rid in state.get("pending", []):
        try:
            r = foundry(f"/openai/v1/responses/{rid}", versioned=False)
            if r.get("status") in ("in_progress", "queued"): pending.append(rid); continue
            seal_agent_definition(state, r); n += 1 if seal_response(r, state) else 0
        except Exception as e:
            log("pending", rid, repr(e)[:160]); pending.append(rid)
    while True:
        q = "/openai/v1/responses?limit=100&order=asc" + (f"&after={after}" if after else "")
        page = foundry(q, versioned=False)
        for r in page.get("data", []):
            seal_agent_definition(state, r)
            if r.get("status") in ("in_progress", "queued"): pending.append(r["id"])
            else: n += 1 if seal_response(r, state) else 0
            after = r["id"]; state["cursor"] = after; save_state(state)
        if not page.get("has_more"): break
    state["pending"] = pending
    return n

def main():
    once = "--once" in sys.argv
    state = load_state()
    log(f"foundry tap started; project {EP}; interval {INTERVAL}s")
    while True:
        try:
            n = sweep(state); save_state(state)
            if n: log(f"sealed {n} new record(s)")
        except Exception as e:
            save_state(state)   # keep what was sealed so far; never re-seal it
            log("sweep error:", repr(e)[:300])
        if once: return
        time.sleep(INTERVAL)

if __name__ == "__main__": main()
