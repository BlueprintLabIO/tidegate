#!/usr/bin/env python3
"""Full-cycle dogfood of the real tidegate binary against a mock MCP server.

Exercises the whole gate: connect -> install -> MCP over the shim -> ask ->
approve (via the key-gated dashboard channel) -> call flows -> receipt ->
chain verify -> revoke -> asks again. No GitHub token needed; the mock
upstream echoes its injected credential so we can also confirm the agent
never receives it in a pending/denied surface.
"""
import json, os, subprocess, sys, tempfile, time, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "target", "debug", "tidegate")

MOCK = r'''
import sys, json, os
def send(o): sys.stdout.write(json.dumps(o)+"\n"); sys.stdout.flush()
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    m=json.loads(line); i=m.get("id"); meth=m.get("method")
    if meth=="initialize": send({"jsonrpc":"2.0","id":i,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"mock","version":"0"}}})
    elif meth=="notifications/initialized": pass
    elif meth=="tools/list": send({"jsonrpc":"2.0","id":i,"result":{"tools":[{"name":"read_file","description":"r","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":True}}]}})
    elif meth=="tools/call": send({"jsonrpc":"2.0","id":i,"result":{"content":[{"type":"text","text":"UPSTREAM_SAW:"+os.environ.get("MOCK_TOKEN","?")}],"isError":False}})
    else: send({"jsonrpc":"2.0","id":i,"error":{"code":-32601,"message":"no"}})
'''

def main():
    home = tempfile.mkdtemp(prefix="tgd-home-")
    proj = tempfile.mkdtemp(prefix="tgd-proj-")
    mock_py = os.path.join(home, "mock.py")
    open(mock_py, "w").write(MOCK)
    open(os.path.join(home, "master.key"), "wb").write(bytes([7]) * 32)
    secret = "ghp_SECRET_that_must_never_reach_the_agent_0001"

    env = dict(os.environ,
               TIDEGATE_HOME=home,
               TIDEGATE_MASTER_KEY_FILE=os.path.join(home, "master.key"))

    def run(args, extra=None):
        e = dict(env, **(extra or {}))
        r = subprocess.run([BIN] + args, cwd=proj, env=e,
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("FAIL:", args, r.stdout, r.stderr); sys.exit(1)
        return r.stdout

    ok = lambda m: print("  ✓", m)

    # 1. connect + install
    run(["connect", "mock", "--secret-env", "SEC"],
        {"SEC": secret, "TIDEGATE_MCP_COMMAND": "python3",
         "TIDEGATE_MCP_ARGS": mock_py, "TIDEGATE_MCP_ENV": "MOCK_TOKEN"})
    run(["install", "claude"])
    cfg = json.load(open(os.path.join(proj, ".mcp.json")))
    token = cfg["mcpServers"]["tidegate"]["env"]["TIDEGATE_AGENT_TOKEN"]
    ok("connected mock, installed claude, minted per-project token")

    # 2. drive the shim
    shim = subprocess.Popen([BIN, "shim", "claude"], cwd=proj,
                            env=dict(env, TIDEGATE_AGENT_TOKEN=token, TIDEGATE_ELICIT="1"),
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
    def rpc(obj):
        shim.stdin.write(json.dumps(obj) + "\n"); shim.stdin.flush()
        return json.loads(shim.stdout.readline())

    assert rpc({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}})["result"]["serverInfo"]["name"] == "tidegate"
    tools = rpc({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})["result"]["tools"]
    assert any(t["name"] == "mock.read_file" for t in tools), tools
    ok("shim: initialize + tools/list (mock.read_file advertised)")

    # 3. first call ASKS
    call = {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"mock.read_file","arguments":{"repo":"acme"}}}
    r = rpc(call)
    txt = r["result"]["content"][0]["text"]
    assert r["result"]["isError"] and "approval_pending" in txt, txt
    assert secret not in txt, "SECRET LEAKED into pending message!"
    ok("first read -> ask (pending, model-legible, no secret in message)")

    # 4. approve via the key-gated dashboard channel
    port = int(open(os.path.join(home, "control.port")).read().strip())
    key = open(os.path.join(home, "dashboard.key")).read().strip()
    pend = api(port, key, "GET", "/api/pending")["pending"]
    assert pend and secret not in json.dumps(pend), "secret in pending list!"
    pid = pend[0]["id"]
    api(port, key, "POST", "/api/approve", {"id": pid, "answer": "allow_always"})
    ok("approved via dashboard key channel (allow always)")

    # 5. same call now FLOWS, upstream got the secret, agent got only the result
    r = rpc(call)
    txt = r["result"]["content"][0]["text"]
    assert not r["result"].get("isError"), r
    assert "UPSTREAM_SAW:" + secret in txt, "upstream should have received the injected secret"
    ok("read now flows; upstream received the key, agent received only the result")

    # 6. receipts + chain
    out = run(["audit", "--verify"])
    assert "intact" in out, out
    ok("receipt chain verifies intact")

    # 7. revoke -> asks again
    grants = run(["audit", "--grants"])
    gid = grants.split()[0]
    run(["revoke", gid])
    r = rpc(call)
    assert r["result"]["isError"] and "approval_pending" in r["result"]["content"][0]["text"]
    ok("revoke is immediate: the next call asks again")

    shim.terminate()
    subprocess.run([BIN, "daemon"], env=env, timeout=1, capture_output=True) if False else None
    # stop the daemon
    subprocess.run(["pkill", "-f", "tidegate daemon"], capture_output=True)
    print("\nDOGFOOD PASSED — full gate cycle verified end to end.")

def api(port, key, method, path, body=None):
    url = f"http://127.0.0.1:{port}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"X-Tidegate-Key": key, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.load(r)

if __name__ == "__main__":
    main()
