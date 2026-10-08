#!/usr/bin/env python3
"""GrantAi AgentCore tap: records what Amazon Bedrock AgentCore agents did, with no agent configuration.

AgentCore writes each agent's telemetry (OpenTelemetry spans incl. prompts, tool calls, completions)
to one CloudWatch log group per agent: /aws/bedrock-agentcore/runtimes/<agent_id>-<endpoint>, with the
spans in a "spans" log stream. This tap, running on the collector with its instance role, reads those
spans from a cursor and seals one record per span that carries agent activity (model invocations and
tool executions) under the caller "agentcore-tap". The tap is the witness: attribution stays with the
credential that wrote; the agent, session and span ids are part of the content and the source id.

Environment (/opt/grantai/etc/agentcore-tap.env):
  GRANTAI_AGENTCORE_REGION   region of the AgentCore agents
  GRANTAI_TAP_BASE / GRANTAI_TAP_TOKEN / GRANTAI_TAP_CACERT / GRANTAI_TAP_INTERVAL / GRANTAI_TAP_STATE
Uses the AWS CLI (instance role). Log-group prefix can be overridden with GRANTAI_AGENTCORE_LOG_PREFIX.
"""
import json, os, ssl, subprocess, sys, time, urllib.request

REGION = os.environ["GRANTAI_AGENTCORE_REGION"]
PREFIX = os.environ.get("GRANTAI_AGENTCORE_LOG_PREFIX", "/aws/bedrock-agentcore/runtimes/")
BASE = os.environ.get("GRANTAI_TAP_BASE", "https://127.0.0.1:8443")
TOKEN = os.environ["GRANTAI_TAP_TOKEN"]
CACERT = os.environ.get("GRANTAI_TAP_CACERT", "")
INTERVAL = int(os.environ.get("GRANTAI_TAP_INTERVAL", "30"))
STATE = os.environ.get("GRANTAI_TAP_STATE", "/opt/grantai/var/agentcore-tap.state.json")
ctx = ssl.create_default_context(cafile=CACERT) if CACERT else ssl.create_default_context()

def log(*a): print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), *a, flush=True)

def aws(*args):
    out = subprocess.run(["aws", "--region", REGION, "--output", "json", *args], capture_output=True, text=True, timeout=120)
    if out.returncode != 0: raise RuntimeError(out.stderr.strip()[:300])
    return json.loads(out.stdout or "{}")

def record(content, source):
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "grantai_teach", "arguments": {"content": content, "source": source}}}
    req = urllib.request.Request(BASE + "/mcp", data=json.dumps(body).encode(), method="POST",
                                 headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
    with urllib.request.urlopen(req, context=ctx, timeout=60) as r: j = json.loads(r.read().decode() or "{}")
    if "result" not in j or j["result"].get("isError"): raise RuntimeError(f"teach refused: {j}")

def load_state():
    try: st = json.load(open(STATE))
    except Exception: st = {}
    st.setdefault("cursor", {}); st.setdefault("sealed", []); return st
def save_state(s):
    tmp = STATE + ".tmp"; json.dump(s, open(tmp, "w")); os.replace(tmp, STATE)

def iso(ms): return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ms / 1000.0)) if ms else ""

def interesting(span):
    """Spans that carry agent activity: model invocations (gen_ai.*) and tool executions."""
    attrs = span.get("attributes") or {}
    name = span.get("name", "")
    return any(k.startswith("gen_ai.") for k in attrs) or "tool" in name.lower() or attrs.get("gen_ai.operation.name")

def summarize(span, agent, group):
    a = span.get("attributes") or {}
    return {"platform": "bedrock-agentcore", "region": REGION, "log_group": group, "agent": agent,
            "session": a.get("session.id") or a.get("gen_ai.conversation.id") or span.get("session_id"),
            "trace": span.get("traceId") or span.get("trace_id"), "span": span.get("spanId") or span.get("span_id"),
            "name": span.get("name"), "kind": span.get("kind"), "operation": a.get("gen_ai.operation.name"),
            "model": a.get("gen_ai.request.model") or a.get("gen_ai.response.model"),
            "started_at": span.get("startTimeUnixNano") and iso(int(span["startTimeUnixNano"]) / 1e6),
            "ended_at": span.get("endTimeUnixNano") and iso(int(span["endTimeUnixNano"]) / 1e6),
            "status": (span.get("status") or {}).get("code"),
            "input": a.get("gen_ai.prompt") or a.get("gen_ai.input.messages") or a.get("input") or [e for e in (span.get("events") or []) if "prompt" in e.get("name", "")],
            "output": a.get("gen_ai.completion") or a.get("gen_ai.output.messages") or a.get("output") or [e for e in (span.get("events") or []) if "completion" in e.get("name", "")],
            "tool": {k.split("gen_ai.tool.")[1]: v for k, v in a.items() if k.startswith("gen_ai.tool.")} or None,
            "usage": {k.split("gen_ai.usage.")[1]: v for k, v in a.items() if k.startswith("gen_ai.usage.")} or None,
            "sealed_by": "agentcore-tap"}

def sweep(state):
    n = 0
    groups = [g["logGroupName"] for g in aws("logs", "describe-log-groups", "--log-group-name-prefix", PREFIX).get("logGroups", [])]
    for group in groups:
        agent = group[len(PREFIX):] if group.startswith(PREFIX) else group
        since = int(state["cursor"].get(group, (time.time() - 3600) * 1000))
        args = ["logs", "filter-log-events", "--log-group-name", group, "--log-stream-name-prefix", "spans", "--start-time", str(since + 1), "--limit", "500"]
        page = aws(*args); events = page.get("events", [])
        while page.get("nextToken") and len(events) < 5000:
            page = aws(*args, "--next-token", page["nextToken"]); events += page.get("events", [])
        for ev in events:
            try: span = json.loads(ev.get("message", ""))
            except Exception: continue
            if not isinstance(span, dict): continue
            spans = span.get("spans") if "spans" in span else [span]
            for sp in spans:
                sid = sp.get("spanId") or sp.get("span_id")
                if not sid or sid in state["sealed"] or not interesting(sp): continue
                body = summarize(sp, agent, group)
                record(json.dumps(body, ensure_ascii=False, default=str), f"agentcore/{agent}/{body.get('session') or 'no-session'}/{sid}")
                state["sealed"].append(sid); state["sealed"] = state["sealed"][-5000:]; n += 1
            state["cursor"][group] = max(since, ev.get("timestamp", since)); save_state(state)
    return n

def main():
    once = "--once" in sys.argv
    state = load_state()
    log(f"agentcore tap started; region {REGION}; prefix {PREFIX}; interval {INTERVAL}s")
    while True:
        try:
            n = sweep(state); save_state(state)
            if n: log(f"sealed {n} new record(s)")
        except Exception as e:
            save_state(state); log("sweep error:", repr(e)[:300])
        if once: return
        time.sleep(INTERVAL)

if __name__ == "__main__": main()
