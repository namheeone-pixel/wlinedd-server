# -*- coding: utf-8 -*-
"""
WLineDD 라이선스 서버 (단일 파일, 표준 라이브러리만)

무료 클라우드(Render 등)에 올려 두면:
  - 길드원 exe 가 자동으로 '승인 신청'을 보냄 → 관리자 화면 '대기'에 뜸
  - 관리자가 브라우저에서 [승인]/[차단] 버튼만 누르면 됨
  - exe 들은 /allowlist.json 을 받아 서명 검증 후 실행 여부 결정

환경변수(배포 때 설정):
  ADMIN_PASSWORD      관리자 화면 비밀번호 (필수)
  LICENSE_PRIVATE_KEY 서명용 개인키 16진수 (admin_tool '키 만들기'로 생성, 필수)
                      → 같은 키의 공개키를 클라이언트 license_config.py 에 넣어야 함
  PORT                (호스트가 자동 지정)
  DB_PATH             데이터 파일 경로 (기본 ./data/license.db)
  SEED_MEMBERS        (선택) 디스크가 비면 복원할 백업 JSON (base64) — 무료호스트 초기화 대비

로컬 실행:  ADMIN_PASSWORD=1234 python server.py
"""
import os, sys, json, time, sqlite3, base64, hmac, hashlib, threading, html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path: sys.path.insert(0, HERE)
import ed25519_pure as ED

DB_PATH   = os.environ.get("DB_PATH", os.path.join(HERE, "data", "license.db"))
ADMIN_PW  = os.environ.get("ADMIN_PASSWORD", "")
PRIV_HEX  = os.environ.get("LICENSE_PRIVATE_KEY", "").strip()
PORT      = int(os.environ.get("PORT", "8000"))
PRODUCT   = os.environ.get("PRODUCT_NAME", "WLineDD")

_lock = threading.Lock()
_blob_cache = {"v": None, "data": None}     # 서명된 명단 캐시 (변경 시 무효화)

# GitHub 영구 저장 (무료 호스트가 꺼졌다 켜져도 명단 유지). 안 쓰면 로컬 SQLite 만.
GH_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GH_REPO  = os.environ.get("GITHUB_REPO", "")      # "아이디/저장소"
GH_FILE  = os.environ.get("GITHUB_FILE", "members.json")
_dirty = threading.Event()


def _gh_on():
    return bool(GH_TOKEN and "/" in GH_REPO)


def _gh_req(method, data=None):
    import urllib.request
    url = "https://api.github.com/repos/%s/contents/%s" % (GH_REPO, GH_FILE)
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": "Bearer " + GH_TOKEN, "Accept": "application/vnd.github+json",
        "User-Agent": "WLineDD", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode("utf-8"))


def _gh_load():
    j = _gh_req("GET")
    rows = json.loads(base64.b64decode(j["content"]).decode("utf-8"))
    return rows, j["sha"]


def _gh_save(rows):
    try: _, sha = _gh_load()
    except Exception: sha = None
    body = {"message": "update members %s" % time.strftime("%Y-%m-%d %H:%M"),
            "content": base64.b64encode(json.dumps(rows, ensure_ascii=False, indent=2).encode()).decode()}
    if sha: body["sha"] = sha
    _gh_req("PUT", json.dumps(body).encode("utf-8"))


def mark_dirty():
    if _gh_on(): _dirty.set()


def _persist_loop():
    while True:
        _dirty.wait(); time.sleep(2); _dirty.clear()       # 연속 변경을 2초로 묶음
        try: _gh_save(list_members())
        except Exception as e: print("[gh] 저장 실패:", e)


def load_boot():
    """서버 시작 시 GitHub 에 저장된 명단을 불러옴 (있으면 그게 기준)."""
    if not _gh_on(): return
    try:
        rows, _ = _gh_load()
        c = db(); c.execute("DELETE FROM members"); c.commit(); c.close()
        restore_members(rows)
        print("[gh] %d명 불러옴" % len(rows))
    except Exception as e:
        print("[gh] 불러오기 실패(빈 상태로 시작):", e)


# ---------------------------------------------------------------- 저장소
def db():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.execute("""CREATE TABLE IF NOT EXISTS members(
        code TEXT PRIMARY KEY, name TEXT, status TEXT, note TEXT,
        created REAL, updated REAL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)""")
    return c


def norm_code(code):
    s = "".join(ch for ch in str(code).strip().lower() if ch in "0123456789abcdef")
    return s[:20]


def _seed_if_empty():
    c = db()
    n = c.execute("SELECT COUNT(*) FROM members").fetchone()[0]
    seed = os.environ.get("SEED_MEMBERS", "")
    if n == 0 and seed:
        try:
            rows = json.loads(base64.b64decode(seed).decode("utf-8"))
            restore_members(rows)
            print("[seed] restored %d members from SEED_MEMBERS" % len(rows))
        except Exception as e:
            print("[seed] failed:", e)
    c.close()


def list_members(status=None):
    c = db()
    if status:
        rows = c.execute("SELECT code,name,status,note,created,updated FROM members WHERE status=? ORDER BY updated DESC", (status,)).fetchall()
    else:
        rows = c.execute("SELECT code,name,status,note,created,updated FROM members ORDER BY status,updated DESC").fetchall()
    c.close()
    return [dict(code=r[0], name=r[1], status=r[2], note=r[3], created=r[4], updated=r[5]) for r in rows]


def upsert_request(code, name):
    code = norm_code(code)
    if len(code) != 20: return False, "invalid code"
    now = time.time()
    c = db()
    row = c.execute("SELECT status FROM members WHERE code=?", (code,)).fetchone()
    if row is None:
        c.execute("INSERT INTO members(code,name,status,note,created,updated) VALUES(?,?,?,?,?,?)",
                  (code, name[:40], "pending", "", now, now))
        st = "pending"
    else:
        st = row[0]
        if name:        # 이름만 갱신 (상태는 유지)
            c.execute("UPDATE members SET name=?, updated=? WHERE code=?", (name[:40], now, code))
    c.commit(); c.close()
    _invalidate(); mark_dirty()
    return True, st


def set_status(code, status):
    code = norm_code(code); now = time.time()
    c = db(); c.execute("UPDATE members SET status=?, updated=? WHERE code=?", (status, now, code))
    c.commit(); c.close(); _invalidate(); mark_dirty()


def delete_member(code):
    c = db(); c.execute("DELETE FROM members WHERE code=?", (norm_code(code),))
    c.commit(); c.close(); _invalidate(); mark_dirty()


def add_member(code, name, status="allowed"):
    code = norm_code(code)
    if len(code) != 20: return False
    now = time.time(); c = db()
    c.execute("INSERT OR REPLACE INTO members(code,name,status,note,created,updated) VALUES(?,?,?,?,?,?)",
              (code, name[:40], status, "", now, now))
    c.commit(); c.close(); _invalidate(); mark_dirty(); return True


def restore_members(rows):
    c = db(); now = time.time()
    for m in rows:
        code = norm_code(m.get("code", ""))
        if len(code) != 20: continue
        c.execute("INSERT OR REPLACE INTO members(code,name,status,note,created,updated) VALUES(?,?,?,?,?,?)",
                  (code, (m.get("name") or "")[:40], m.get("status", "allowed"), m.get("note", ""),
                   m.get("created", now), m.get("updated", now)))
    c.commit(); c.close(); _invalidate()


# ---------------------------------------------------------------- 서명된 명단
def _invalidate():
    with _lock: _blob_cache["v"] = None


def signed_allowlist():
    with _lock:
        if _blob_cache["v"] is not None:
            return _blob_cache["data"]
    members = list_members()
    allow = sorted(m["code"] for m in members if m["status"] == "allowed")
    revoke = sorted(m["code"] for m in members if m["status"] == "blocked")
    note = {m["code"]: (m["name"] or "") for m in members if m["name"]}
    payload = {"v": 1, "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "allow": allow, "revoke": revoke, "note": note}
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    try:
        sk = bytes.fromhex(PRIV_HEX); pk = ED.publickey(sk)
        sig = ED.sign(data.encode("utf-8"), sk, pk).hex()
    except Exception as e:
        return json.dumps({"error": "server key not set: %s" % e}).encode("utf-8")
    blob = json.dumps({"data": data, "sig": sig}, ensure_ascii=False).encode("utf-8")
    with _lock:
        _blob_cache["v"] = payload["updated"]; _blob_cache["data"] = blob
    return blob


def server_pubkey():
    try: return ED.publickey(bytes.fromhex(PRIV_HEX)).hex()
    except Exception: return "(개인키 미설정)"


# ---------------------------------------------------------------- 관리자 화면
def _esc(s): return html.escape(str(s or ""))


def admin_html(msg=""):
    ms = list_members()
    groups = {"pending": [], "allowed": [], "blocked": []}
    for m in ms: groups.get(m["status"], groups["allowed"]).append(m)
    def section(title, items, actions):
        rows = ""
        for m in items:
            btns = ""
            for label, act in actions:
                btns += ('<form method="post" action="/admin/action" style="display:inline">'
                         '<input type="hidden" name="code" value="%s">'
                         '<input type="hidden" name="act" value="%s">'
                         '<button>%s</button></form> ' % (_esc(m["code"]), act, label))
            rows += ("<tr><td class=c>%s</td><td>%s</td><td>%s</td></tr>"
                     % (_esc(m["code"]), _esc(m["name"]), btns))
        return ("<h3>%s <span class=n>(%d)</span></h3><table>"
                "<tr><th>PC 코드</th><th>이름</th><th>동작</th></tr>%s</table>"
                % (title, len(items), rows or "<tr><td colspan=3 class=n>없음</td></tr>"))
    body = (section("승인 대기", groups["pending"], [("승인", "allow"), ("차단", "block"), ("삭제", "delete")])
            + section("사용 허용", groups["allowed"], [("차단", "block"), ("삭제", "delete")])
            + section("차단됨", groups["blocked"], [("허용", "allow"), ("삭제", "delete")]))
    return """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s 관리자</title><style>
body{background:#15171c;color:#e8eaed;font-family:'Segoe UI','맑은 고딕',sans-serif;max-width:760px;margin:0 auto;padding:16px}
h2{color:#ff6a1a} h3{margin:18px 0 6px} .n{color:#8a919b;font-weight:normal}
table{width:100%%;border-collapse:collapse;margin-bottom:8px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #262a32;font-size:13px}
th{color:#aeb4bd} td.c{font-family:monospace;color:#ff8038}
button{background:#262a32;color:#e8eaed;border:1px solid #333845;border-radius:6px;padding:4px 10px;cursor:pointer}
form.add input{background:#0f1115;color:#e8eaed;border:1px solid #333845;border-radius:6px;padding:7px;margin-right:6px}
.box{background:#1b1e24;border:1px solid #262a32;border-radius:10px;padding:14px;margin:12px 0}
.msg{color:#39d353} a{color:#ff8038} code{color:#ff8038;word-break:break-all}
</style></head><body>
<h2>%s 라이선스 관리자</h2>
<div class=msg>%s</div>
<div class=box><b>내 명단 주소</b> (exe 가 읽는 곳):<br><code>/allowlist.json</code><br>
<b>서버 공개키</b> (클라이언트에 넣는 값):<br><code>%s</code></div>
%s
<div class=box><b>직접 추가</b>
<form class=add method="post" action="/admin/add">
<input name="code" placeholder="PC 코드" size="26">
<input name="name" placeholder="이름(선택)">
<button>허용으로 추가</button></form></div>
<div class=box><b>백업 / 복원</b> (무료 호스트가 초기화돼도 복구용)<br><br>
<a href="/admin/backup">⬇ 백업 내려받기 (members.json)</a><br><br>
<form method="post" action="/admin/restore" enctype="multipart/form-data">
<input type="file" name="f" accept=".json"><button>복원 업로드</button></form></div>
<p class=n>%s</p>
</body></html>""" % (_esc(PRODUCT), _esc(PRODUCT), _esc(msg), _esc(server_pubkey()), body,
                     time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()))


# ---------------------------------------------------------------- HTTP
def _parse_body(h):
    n = int(h.headers.get("Content-Length", 0) or 0)
    return h.rfile.read(n) if n else b""


def _form(raw):
    from urllib.parse import parse_qs
    d = parse_qs(raw.decode("utf-8", "replace"))
    return {k: v[0] for k, v in d.items()}


def _multipart_file(raw, ctype):
    """아주 단순한 multipart 파서: 첫 파일 바이트만 반환."""
    try:
        b = b"boundary="; i = ctype.find("boundary="); bnd = ("--" + ctype[i+len(b):]).encode()
        parts = raw.split(bnd)
        for p in parts:
            if b"filename=" in p.split(b"\r\n\r\n")[0]:
                return p.split(b"\r\n\r\n", 1)[1].rsplit(b"\r\n", 1)[0]
    except Exception:
        pass
    return b""


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a): pass        # 조용히

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        if isinstance(body, str): body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD": self.wfile.write(body)

    def _auth_ok(self):
        if not ADMIN_PW: return False
        h = self.headers.get("Authorization", "")
        if not h.startswith("Basic "): return False
        try:
            u, p = base64.b64decode(h[6:]).decode("utf-8").split(":", 1)
        except Exception:
            return False
        return hmac.compare_digest(p, ADMIN_PW)

    def _need_auth(self):
        self._send(401, "<h3>관리자 로그인</h3>", extra={"WWW-Authenticate": 'Basic realm="WLineDD"'})

    # ---- GET ----
    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/health":
            return self._send(200, "ok", "text/plain; charset=utf-8")
        if p == "/allowlist.json":
            return self._send(200, signed_allowlist(), "application/json; charset=utf-8")
        if p in ("/", "/admin"):
            if not self._auth_ok(): return self._need_auth()
            return self._send(200, admin_html())
        if p == "/admin/backup":
            if not self._auth_ok(): return self._need_auth()
            data = json.dumps(list_members(), ensure_ascii=False, indent=2)
            return self._send(200, data, "application/json; charset=utf-8",
                              extra={"Content-Disposition": "attachment; filename=members.json"})
        return self._send(404, "not found", "text/plain; charset=utf-8")

    do_HEAD = do_GET

    # ---- POST ----
    def do_POST(self):
        p = self.path.split("?")[0]
        raw = _parse_body(self)
        if p == "/request":
            try:
                j = json.loads(raw.decode("utf-8")); code = j.get("code", ""); name = j.get("name", "")
            except Exception:
                f = _form(raw); code = f.get("code", ""); name = f.get("name", "")
            ok, st = upsert_request(code, name)
            return self._send(200 if ok else 400,
                              json.dumps({"ok": ok, "status": st if ok else st}),
                              "application/json; charset=utf-8")
        # 아래는 관리자 전용
        if not self._auth_ok(): return self._need_auth()
        if p == "/admin/action":
            f = _form(raw); code = f.get("code", ""); act = f.get("act", "")
            if act == "allow": set_status(code, "allowed"); msg = "허용함"
            elif act == "block": set_status(code, "blocked"); msg = "차단함"
            elif act == "delete": delete_member(code); msg = "삭제함"
            else: msg = "?"
            return self._send(200, admin_html(msg + ": " + code[:12]))
        if p == "/admin/add":
            f = _form(raw)
            ok = add_member(f.get("code", ""), f.get("name", ""), "allowed")
            return self._send(200, admin_html("추가함" if ok else "코드 형식 오류"))
        if p == "/admin/restore":
            ctype = self.headers.get("Content-Type", "")
            fb = _multipart_file(raw, ctype) if "multipart" in ctype else raw
            try:
                rows = json.loads(fb.decode("utf-8")); restore_members(rows); mark_dirty(); msg = "복원함 (%d명)" % len(rows)
            except Exception as e:
                msg = "복원 실패: %s" % e
            return self._send(200, admin_html(msg))
        return self._send(404, "not found", "text/plain; charset=utf-8")


def main():
    if not ADMIN_PW:
        print("!! ADMIN_PASSWORD 환경변수를 설정하세요 (관리자 화면 비밀번호)")
    if not PRIV_HEX:
        print("!! LICENSE_PRIVATE_KEY 환경변수를 설정하세요 (서명용 개인키). 없으면 명단 서명이 안 됩니다.")
    else:
        print("[key] 서버 공개키:", server_pubkey())
    if _gh_on():
        print("[gh] 영구저장 사용:", GH_REPO, "/", GH_FILE)
        threading.Thread(target=_persist_loop, daemon=True).start()
    load_boot()
    _seed_if_empty()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), H)
    print("[run] http://0.0.0.0:%d  (admin: /admin, list: /allowlist.json)" % PORT)
    srv.serve_forever()


if __name__ == "__main__":
    main()
