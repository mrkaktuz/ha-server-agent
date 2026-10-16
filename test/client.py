"""Перевірка API агента ззовні (свій сертифікат агента не перевіряємо — справжність дає підпис відповіді): підписані запити, дії, відмови, повтор nonce, підробка підпису.
python3 test/client.py URL AGENT_PUBKEY CLIENT_PRIVKEY"""
import json, ssl, sys, time, urllib.request, urllib.error
sys.path.insert(0, __file__.rsplit('/', 2)[0] + '/agent')
import protocol as P

url, agent_pub, cpriv = sys.argv[1], P.load_public(sys.argv[2]), sys.argv[3]
priv, kid = P.load_private(cpriv), P.key_id(P.public_of(cpriv))

def call(method, path, payload=None, tamper=None, nonce=None, ts=None):
    body = json.dumps(payload).encode() if payload is not None else b""
    ts = ts or str(int(time.time())); nonce = nonce or P.new_nonce()
    sig = P.sign(priv, P.req_message(method, path, ts, nonce, body))
    if tamper == "sig": sig = P.sign(P.load_private(P.generate_keypair()[0]), P.req_message(method, path, ts, nonce, body))
    if tamper == "body": body = body.replace(b"restart", b"stop")
    req = urllib.request.Request(url + path, data=body or None, method=method, headers={
        P.H_KEY: kid, P.H_TIME: ts, P.H_NONCE: nonce, P.H_SIG: sig, "Content-Type": "application/json"})
    try:
        r = urllib.request.urlopen(req, timeout=60, context=ssl._create_unverified_context()); status, raw, hd = r.status, r.read(), r.headers
    except urllib.error.HTTPError as e:
        status, raw, hd = e.code, e.read(), e.headers
    ok = bool(hd.get(P.H_SIG)) and P.verify(agent_pub, P.resp_message(status, nonce, hd.get(P.H_TIME, ""), raw), hd.get(P.H_SIG, ""))
    return status, ok, json.loads(raw or b"{}"), nonce

def show(title, res):
    st, ok, data, _ = res
    print(f"{title:42} HTTP {st} підпис {'✓' if ok else '—'} {json.dumps(data, ensure_ascii=False)[:150]}")

show("ping", call("GET", "/v1/ping"))
show("pm2 restart deploy/api", call("POST", "/v1/action", {"module": "pm2", "target": "deploy/api", "action": "restart"}))
show("pm2 restart неіснуючого", call("POST", "/v1/action", {"module": "pm2", "target": "deploy/nope", "action": "restart"}))
show("nginx test", call("POST", "/v1/action", {"module": "nginx", "target": "", "action": "test"}))
show("tmux kill (заборонено політикою)", call("POST", "/v1/action", {"module": "tmux", "target": "deploy/build", "action": "kill"}))
show("модуль, якого немає", call("POST", "/v1/action", {"module": "shell", "target": "rm -rf /", "action": "run"}))
show("чужий підпис", call("GET", "/v1/state", tamper="sig"))
show("підмінене тіло", call("POST", "/v1/action", {"module": "pm2", "target": "deploy/api", "action": "restart"}, tamper="body"))
show("старий час (−120 с)", call("GET", "/v1/ping", ts=str(int(time.time()) - 120)))
n = P.new_nonce(); call("GET", "/v1/ping", nonce=n)
show("повтор nonce", call("GET", "/v1/ping", nonce=n))
