"""HTTP API + dashboard for the audit archive aggregator.

Endpoints:
  GET  /               dashboard (auto-refreshing)
  GET  /api/status     per-source gaps/conflicts/positions, round, published root
  GET  /api/export     full audit bundle for the offline verifier
  POST /api/segments   upload one segment, a list, or {"segments": [...]}
  POST /api/resolve    {"source","seq","accepted_digest","reason","decided_by"}
  POST /api/publish    {"publisher": "..."} -> published | already_published | refused
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

DASHBOARD = """<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<title>离线审计档案汇聚器</title>
<style>
 body{font-family:system-ui,sans-serif;margin:2rem;background:#f6f7f9;color:#222}
 h1{font-size:1.4rem} h2{font-size:1.05rem;margin-top:1.6rem}
 table{border-collapse:collapse;background:#fff;width:100%}
 th,td{border:1px solid #ddd;padding:4px 8px;font-size:.85rem;text-align:left;vertical-align:top}
 code{font-family:ui-monospace,monospace;font-size:.8rem}
 .ok{color:#087f23}.bad{color:#b00020}.warn{color:#9a6a00}
 .card{background:#fff;border:1px solid #ddd;padding:1rem;margin:.6rem 0}
 button{padding:.3rem .8rem} textarea{width:100%;font-family:monospace}
 input{padding:.25rem}
</style>
</head>
<body>
<h1>离线审计档案汇聚器 · Audit Archive Aggregator</h1>
<div class="card" id="summary">加载中…</div>

<h2>来源状态（确认位置 / 缺口 / 候选 / 隔离）</h2>
<div id="sources"></div>

<h2>上传分段（JSON：单个对象或数组）</h2>
<div class="card">
<textarea id="seg" rows="6" placeholder='[{"source":"region-a","seq":1,"prev_digest":"...","payload_digest":"...","signature":"..."}]'></textarea><br>
<button onclick="upload()">上传</button>
<pre id="upresult"></pre>
</div>

<h2>冲突处置（需填写理由与决策人）</h2>
<div id="conflicts"></div>

<h2>发布见证（单次提交，并发最多一个成功）</h2>
<div class="card">
<input id="publisher" placeholder="发布人">
<button onclick="doPublish()">发布</button>
<pre id="pubresult"></pre>
</div>

<h2>发布记录</h2>
<div id="pubs"></div>

<p><a href="/api/export">导出离线校验包</a> · <a href="/api/status">状态 JSON</a></p>

<script>
const short = h => h ? String(h).slice(0,12) + '…' : '';
const esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
async function api(u, opts){ const r = await fetch(u, opts); return await r.json(); }

async function refresh(){
  const s = await api('/api/status');
  document.getElementById('summary').innerHTML =
    '门限: <b>' + s.threshold + '</b> · 当前轮次: <b>' + s.current_round + '</b> · ' +
    '已发布根: <code>' + (short(s.published_root) || '（无）') + '</code> · ' +
    '当前汇聚根: <code>' + short(s.aggregate_root) + '</code> · ' +
    '活跃来源: <b>' + s.active_sources + '</b> · ' +
    '未决冲突: <b class="' + (s.pending_conflicts ? 'bad' : 'ok') + '">' + s.pending_conflicts + '</b> · ' +
    '可发布: <b class="' + (s.publishable ? 'ok' : 'warn') + '">' + (s.publishable ? '是' : '否') + '</b>';
  let rows = '';
  for (const [name, st] of Object.entries(s.sources)){
    rows += '<tr><td><b>' + esc(name) + '</b></td><td>' + st.last_confirmed_seq + '</td>' +
      '<td><code>' + short(st.head_digest) + '</code></td>' +
      '<td>' + (st.gaps.join(', ') || '—') + '</td>' +
      '<td>' + (st.queued.map(q => q.seq).join(', ') || '—') + '</td>' +
      '<td class="' + (st.quarantined ? 'bad' : 'ok') + '">' +
        (st.quarantined ? '隔离: ' + esc(st.quarantine_reason || '') : '正常') + '</td>' +
      '<td>' + st.conflicts.length + '</td></tr>';
  }
  document.getElementById('sources').innerHTML =
    '<table><tr><th>来源</th><th>已确认</th><th>链头</th><th>缺口</th><th>候选序号</th><th>状态</th><th>未决冲突</th></tr>' +
    (rows || '<tr><td colspan="7">尚无分段</td></tr>') + '</table>';
  let chtml = '';
  for (const [name, st] of Object.entries(s.sources)){
    for (const c of st.conflicts){
      chtml += '<div class="card"><b>' + esc(name) + '</b> 序号 ' + c.seq + ' · 冲突 #' + c.id +
        ' · ' + esc(c.detected_at) + '<br>竞争版本:<br>';
      for (const d of c.digests){ chtml += '<code>' + d + '</code><br>'; }
      chtml += '接受版本摘要: <input id="acc-' + c.id + '" size="70"> ' +
        '理由: <input id="rsn-' + c.id + '"> 决策人: <input id="by-' + c.id + '" size="8"> ' +
        '<button onclick="resolveConflict(' + c.id + ', &quot;' + esc(name) + '&quot;, ' + c.seq + ')">提交处置</button></div>';
    }
  }
  document.getElementById('conflicts').innerHTML = chtml || '<p>无未决冲突。</p>';
  let prows = '';
  for (const p of s.publications){
    prows += '<tr><td>' + p.round + '</td><td><code>' + short(p.root) + '</code></td><td>' +
      p.source_count + '</td><td>' + esc(p.publisher || '') + '</td><td>' + esc(p.published_at) + '</td></tr>';
  }
  document.getElementById('pubs').innerHTML =
    '<table><tr><th>轮次</th><th>发布根</th><th>来源数</th><th>发布人</th><th>时间</th></tr>' +
    (prows || '<tr><td colspan="5">尚无发布</td></tr>') + '</table>';
}
async function upload(){
  let data;
  try { data = JSON.parse(document.getElementById('seg').value); }
  catch(e){ alert('JSON 解析失败: ' + e); return; }
  const r = await api('/api/segments', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)});
  document.getElementById('upresult').textContent = JSON.stringify(r, null, 2);
  refresh();
}
async function resolveConflict(id, source, seq){
  const body = {source: source, seq: seq,
    accepted_digest: document.getElementById('acc-' + id).value.trim(),
    reason: document.getElementById('rsn-' + id).value,
    decided_by: document.getElementById('by-' + id).value};
  const r = await api('/api/resolve', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
  alert(JSON.stringify(r));
  refresh();
}
async function doPublish(){
  const r = await api('/api/publish', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({publisher: document.getElementById('publisher').value})});
  document.getElementById('pubresult').textContent = JSON.stringify(r, null, 2);
  refresh();
}
refresh(); setInterval(refresh, 3000);
</script>
</body>
</html>
"""


class _Handler(BaseHTTPRequestHandler):
    server_version = "AuditArchive/0.1"

    @property
    def aggregator(self):
        return self.server.aggregator  # type: ignore[attr-defined]

    def _send_json(self, obj, code: int = 200, headers: dict | None = None):
        body = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        return json.loads(raw.decode("utf-8") or "null")

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self._send_html(DASHBOARD)
        elif path == "/api/status":
            self._send_json(self.aggregator.status())
        elif path == "/api/export":
            self._send_json(
                self.aggregator.export_bundle(),
                headers={"Content-Disposition": "attachment; filename=audit-bundle.json"},
            )
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            body = self._read_json()
        except Exception as exc:
            self._send_json({"error": f"invalid JSON body: {exc}"}, 400)
            return
        try:
            if path == "/api/segments":
                if isinstance(body, dict) and "segments" in body:
                    segments = body["segments"]
                elif isinstance(body, list):
                    segments = body
                else:
                    segments = [body]
                results = self.aggregator.ingest_many(segments)
                self._send_json({"results": results})
            elif path == "/api/resolve":
                result = self.aggregator.resolve_conflict(
                    source=body.get("source", ""),
                    seq=int(body.get("seq", 0)),
                    accepted_digest=body.get("accepted_digest", ""),
                    reason=body.get("reason", ""),
                    decided_by=body.get("decided_by", ""),
                )
                self._send_json(result, 200 if result.get("status") == "resolved" else 400)
            elif path == "/api/publish":
                publisher = (body or {}).get("publisher", "") if isinstance(body, dict) else ""
                result = self.aggregator.publish(publisher=publisher)
                self._send_json(result, 200 if result.get("status") != "refused" else 409)
            else:
                self._send_json({"error": "not found"}, 404)
        except Exception as exc:  # keep the service alive on bad input
            self._send_json({"error": str(exc)}, 500)

    def log_message(self, *args):  # quiet by default
        pass


def make_server(aggregator, host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), _Handler)
    server.daemon_threads = True
    server.aggregator = aggregator  # type: ignore[attr-defined]
    return server
