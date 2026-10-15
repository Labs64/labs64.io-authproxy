"""Fake OIDC provider (discovery + JWKS) and fake Cerbos PDP on one port, for bench.py. Not part of what is measured."""
import asyncio, json, sys
port, jwks_file, issuer = int(sys.argv[1]), sys.argv[2], sys.argv[3]
jwks = json.load(open(jwks_file))
async def handle(reader, writer):
    try:
        while True:
            head = await reader.readuntil(b"\r\n\r\n")
            lines = head.decode("latin1").split("\r\n")
            method, path, _ = lines[0].split(" ")
            h = {l.split(":", 1)[0].lower(): l.split(":", 1)[1].strip() for l in lines[1:] if ":" in l}
            n = int(h.get("content-length", 0))
            body = await reader.readexactly(n) if n else b""
            if path.startswith("/.well-known"):
                payload = {"issuer": issuer, "jwks_uri": f"http://127.0.0.1:{port}/jwks"}
            elif path == "/jwks":
                payload = jwks
            elif path.startswith("/api/check/resources"):
                req = json.loads(body); r = req["resources"][0]
                payload = {"requestId": req.get("requestId", ""), "results": [{
                    "resource": {"id": r["resource"]["id"], "kind": r["resource"]["kind"], "policyVersion": "default"},
                    "actions": {a: "EFFECT_ALLOW" for a in r["actions"]}}]}
            else:
                payload = {}
            data = json.dumps(payload).encode()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n" % len(data) + data)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        writer.close()
async def main():
    srv = await asyncio.start_server(handle, "127.0.0.1", port)
    async with srv: await srv.serve_forever()
asyncio.run(main())
