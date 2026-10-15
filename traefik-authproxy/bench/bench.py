"""AuthProxy /auth benchmark: the real app under real uvicorn, a fake identity provider and PDP, closed-loop
load, and the server process's CPU per request read from /proc (Linux).

CPU per request is the number to watch: throughput on a shared machine is noisy, CPU time is not. Compare
variants by running this before and after a change; try the knobs the deployment sets:

    python3 bench/bench.py --label baseline
    python3 bench/bench.py --label cached --env AUTHZ_DECISION_CACHE_TTL=5 --env TOKEN_CACHE_TTL=5
    python3 bench/bench.py --label quiet  --env LOG_LEVEL=WARNING --uvicorn=--no-access-log

Needs the service's own requirements (PyJWT[crypto], uvicorn, ...). Absolute numbers are this machine's;
the deployed arm64 pods are slower, so read ratios, not milliseconds."""
import asyncio, json, os, pathlib, subprocess, sys, tempfile, time, signal, argparse
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

ap = argparse.ArgumentParser()
ap.add_argument("--app-dir", default=str(pathlib.Path(__file__).resolve().parent.parent))
ap.add_argument("--conc", type=int, default=8)
ap.add_argument("--secs", type=float, default=8)
ap.add_argument("--env", action="append", default=[], help="KEY=VALUE for the server")
ap.add_argument("--uvicorn", default="", help="extra uvicorn args")
ap.add_argument("--label", default="run")
ap.add_argument("--runs", type=int, default=2)
a = ap.parse_args()

HERE = pathlib.Path(__file__).parent
WORK = pathlib.Path(tempfile.mkdtemp(prefix="authproxy-bench-"))
ISSUER = "http://127.0.0.1:18090/realms/labs64io"; AUD = "labs64io-api"
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())); jwk.update({"kid": "k1", "use": "sig", "alg": "RS256"})
enc = dict(jwk); enc.update({"kid": "k2", "use": "enc", "alg": "RSA-OAEP"})      # Keycloak publishes an enc key too
(WORK/"jwks.json").write_text(json.dumps({"keys": [enc, jwk]}))
routes = WORK/"routes"; routes.mkdir()
(routes/"auditflow.routes.yaml").write_text("""version: 1
module: auditflow
basePath: /auditflow/api/v1
routes:
  - {operationId: publish, method: POST, path: /audit/publish, public: false, tenantRequired: false, scopes: []}
  - {operationId: getEvent, method: GET, path: "/audit/events/{id}", public: false, tenantRequired: false, scopes: []}
  - {operationId: listEvents, method: GET, path: /audit/events, public: false, tenantRequired: false, scopes: []}
  - {operationId: health, method: GET, path: /actuator/health, public: true, tenantRequired: false, scopes: []}
""")
token = jwt.encode({"exp": int(time.time()) + 3600, "iss": ISSUER, "aud": AUD, "sub": "svc-loadtest", "azp": "loadtest",
                    "scope": "audit:publish", "tenant": "loadtest"}, key, algorithm="RS256", headers={"kid": "k1"})
REQ = (b"GET /auth HTTP/1.1\r\nHost: authproxy\r\nX-Forwarded-Method: POST\r\nX-Forwarded-Uri: /auditflow/api/v1/audit/publish\r\n"
       b"Authorization: Bearer " + token.encode() + b"\r\nAccept: */*\r\n\r\n")

def cpu_ticks(pid):
    f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    return int(f[11]) + int(f[12])            # utime + stime

async def worker(stop_at, counts, lats):
    r, w = await asyncio.open_connection("127.0.0.1", 18081)
    while time.perf_counter() < stop_at:
        t0 = time.perf_counter()
        w.write(REQ)
        head = await r.readuntil(b"\r\n\r\n")
        n = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"): n = int(line.split(b":")[1])
        if n: await r.readexactly(n)
        counts[head[9:12]] += 1
        lats.append(time.perf_counter() - t0)
    w.close()

async def drive():
    counts, lats = {b"200": 0}, []
    from collections import defaultdict
    counts = defaultdict(int)
    await asyncio.gather(*[worker(time.perf_counter() + 1.5, defaultdict(int), []) for _ in range(a.conc)])   # warm-up
    t0 = cpu_ticks(srv.pid); w0 = time.perf_counter()
    await asyncio.gather(*[worker(w0 + a.secs, counts, lats) for _ in range(a.conc)])
    wall = time.perf_counter() - w0; cpu = (cpu_ticks(srv.pid) - t0) / os.sysconf("SC_CLK_TCK")
    return counts, lats, wall, cpu

env = {**os.environ, "OIDC_DISCOVERY_URL": "http://127.0.0.1:18090/.well-known/openid-configuration", "OIDC_ISSUER": ISSUER,
       "OIDC_AUDIENCE": AUD, "CERBOS_URL": "http://127.0.0.1:18090", "ROUTES_DIR": str(routes),
       "STATIC_ROUTES_FILE": str(WORK/"none.yaml"), "TOKEN_SCOPES_CLAIM_PATHS": "scope", "LOG_LEVEL": "INFO"}
for kv in a.env: k, v = kv.split("=", 1); env[k] = v
be = subprocess.Popen([sys.executable, str(HERE/"fake_backend.py"), "18090", str(WORK/"jwks.json"), ISSUER], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(0.5)
cmd = [sys.executable, "-m", "uvicorn", "traefik_authproxy:app", "--host", "127.0.0.1", "--port", "18081", "--no-server-header"] + a.uvicorn.split()
srv = subprocess.Popen(cmd, cwd=a.app_dir, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    import urllib.request
    for _ in range(60):
        try: urllib.request.urlopen("http://127.0.0.1:18081/health/ready", timeout=1); break
        except Exception: time.sleep(0.25)
    for i in range(a.runs):
        counts, lats, wall, cpu = asyncio.run(drive())
        n = sum(counts.values()); ok = counts.get(b"200", 0)
        lats.sort()
        print(f"{a.label:34} run{i+1}: {ok/wall:7.0f} req/s  server CPU {1000*cpu/n:5.2f} ms/req  "
              f"p50 {1000*lats[len(lats)//2]:5.1f} ms  p99 {1000*lats[int(len(lats)*0.99)]:6.1f} ms  non-200: {n-ok}")
finally:
    import shutil
    shutil.rmtree(WORK, ignore_errors=True)
    for p in (srv, be): p.send_signal(signal.SIGTERM)
    for p in (srv, be):
        try: p.wait(5)
        except Exception: p.kill()
