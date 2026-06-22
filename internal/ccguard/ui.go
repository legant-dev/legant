package ccguard

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"time"
)

// RunUI starts a LOCAL control panel for inspecting the role rules and editing the
// deny overlay, and blocks until ctx is cancelled. It is hardened for a security
// tool: it binds 127.0.0.1 ONLY (never a routable address), gates every request
// with a random per-run token printed in the URL, and rejects non-loopback Host
// headers (anti DNS-rebinding) — so no other process or web page can read or
// change your rules. Overlay edits are deny-only and take effect on the next tool
// call, exactly like `legant guard deny`.
func RunUI(ctx context.Context, dir string, port int) error {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return err
	}
	s := &uiServer{dir: dir, token: hex.EncodeToString(buf)}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handlePage)
	mux.HandleFunc("/api/state", s.handleState)
	mux.HandleFunc("/api/deny", s.handleEdit(true))
	mux.HandleFunc("/api/allow", s.handleEdit(false))

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	url := fmt.Sprintf("http://%s/?t=%s", ln.Addr().String(), s.token)
	fmt.Printf("Legant guard UI:  %s\n  (loopback only · per-run token · edits the deny overlay · Ctrl-C to stop)\n", url)

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

type uiServer struct {
	dir   string
	token string
}

// authed enforces loopback-only + the per-run token on every request.
func (s *uiServer) authed(r *http.Request) bool {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	switch host {
	case "127.0.0.1", "localhost", "::1", "[::1]":
	default:
		return false // anti DNS-rebinding: only loopback Host is accepted
	}
	t := r.URL.Query().Get("t")
	if t == "" {
		t = r.Header.Get("X-Legant-UI")
	}
	return subtle.ConstantTimeCompare([]byte(t), []byte(s.token)) == 1
}

func (s *uiServer) handlePage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(uiPage))
}

func (s *uiServer) handleState(w http.ResponseWriter, r *http.Request) {
	if !s.authed(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	role := r.URL.Query().Get("role")
	if role == "" {
		role = "open"
	}
	ruleText, err := ShowFromDir(s.dir, filepath.Join(s.dir, role+".jwt"), time.Now())
	if err != nil {
		ruleText = "(" + err.Error() + ")"
	}
	ov, _ := LoadOverlay(OverlayPath(s.dir))
	if ov == nil {
		ov = &Overlay{}
	}
	writeUIJSON(w, map[string]any{
		"roles":   []string{"reviewer", "builder", "open", "operator"},
		"role":    role,
		"rule":    ruleText,
		"overlay": ov,
	})
}

func (s *uiServer) handleEdit(add bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) || r.Method != http.MethodPost {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		var req struct{ Type, Value string }
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil || req.Value == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		ov, _ := LoadOverlay(OverlayPath(s.dir))
		if ov == nil {
			ov = &Overlay{}
		}
		p, c, h, t := bucketRule(req.Type, req.Value)
		if add {
			ov.Add(p, c, h, t)
		} else {
			ov.Remove(p, c, h, t)
		}
		if err := SaveOverlay(OverlayPath(s.dir), ov); err != nil {
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
		writeUIJSON(w, ov)
	}
}

func bucketRule(typ, val string) (paths, cmds, hosts, tools []string) {
	switch typ {
	case "path":
		paths = []string{val}
	case "cmd":
		cmds = []string{val}
	case "host":
		hosts = []string{val}
	case "tool":
		tools = []string{val}
	}
	return
}

func writeUIJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

const uiPage = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Legant guard — rules</title>
<style>
:root{--bg:#0d0f14;--panel:#161922;--panel2:#1d212c;--line:#2a2f3c;--ink:#e7e9ee;--ink2:#a6adbb;--ink3:#6b7280;--gold:#e2b457;--mono:ui-monospace,SFMono-Regular,Menlo,monospace}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;padding:28px}
.wrap{max-width:840px;margin:0 auto}h1{font-size:20px;display:flex;align-items:center;gap:8px}.crown{color:var(--gold)}
.sub{color:var(--ink3);font-size:13px;margin:2px 0 22px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;margin-bottom:20px;overflow:hidden}
.hd{display:flex;justify-content:space-between;align-items:center;padding:13px 18px;border-bottom:1px solid var(--line)}
.hd h2{font-size:13px;letter-spacing:.4px;text-transform:uppercase;color:var(--ink2);margin:0}
.bd{padding:16px 18px}
select,input{background:var(--panel2);border:1px solid var(--line);border-radius:8px;color:var(--ink);padding:9px 11px;font-size:13px}
input{min-width:280px;font-family:var(--mono)}
button{cursor:pointer;border-radius:8px;padding:9px 14px;font-size:13px;border:1px solid var(--line);background:transparent;color:var(--ink2)}
button.go{background:var(--gold);color:#1a1407;border:none;font-weight:700}
pre{background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:12px 14px;font-size:12px;overflow:auto;white-space:pre-wrap;color:var(--ink)}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.chip{display:inline-flex;gap:6px;align-items:center;font-family:var(--mono);font-size:12px;padding:4px 9px;border-radius:7px;margin:3px 6px 3px 0;border:1px solid #7f3a3a;color:#f5a3a3;background:rgba(127,58,58,.14);cursor:pointer}
.chip:hover{filter:brightness(1.25)}.muted{color:var(--ink3);font-size:12.5px}.tag{font-family:var(--mono);font-size:11px;color:var(--ink3)}
</style></head><body><div class="wrap">
<h1><span class="crown">♛</span> Legant guard — rules</h1>
<div class="sub">Loopback-only. Overlay edits are deny-only (tighten the token, never widen) and take effect on the next tool call.</div>

<div class="card"><div class="hd"><h2>Role rule</h2>
  <select id="role" onchange="load()"></select></div>
  <div class="bd"><pre id="rule">…</pre>
  <div class="muted">This is the signed token's rule. To change roles in your agents: <span class="tag">legant guard install --role &lt;role&gt;</span></div></div></div>

<div class="card"><div class="hd"><h2>Deny overlay</h2><span class="tag">overlay.json</span></div>
  <div class="bd">
    <div id="chips"></div>
    <div class="row" style="margin-top:12px">
      <select id="rtype"><option value="cmd">command</option><option value="path">path</option><option value="host">host</option><option value="tool">tool</option></select>
      <input id="rval" placeholder="terraform · ./prod · *.internal · WebFetch" onkeydown="if(event.key==='Enter')addRule()">
      <button class="go" onclick="addRule()">Add deny</button>
    </div>
  </div></div>
</div>
<script>
const T = new URLSearchParams(location.search).get('t') || '';
const H = {'X-Legant-UI': T, 'Content-Type':'application/json'};
function esc(s){return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
let STATE = {overlay:{}, roles:[], role:'open'};
async function load(){
  const role = document.getElementById('role').value || STATE.role || 'open';
  const r = await fetch('/api/state?role='+encodeURIComponent(role), {headers:H});
  STATE = await r.json();
  const sel = document.getElementById('role');
  if(!sel.options.length){ STATE.roles.forEach(x=>{const o=document.createElement('option');o.value=o.textContent=x;sel.appendChild(o)}); sel.value=STATE.role; }
  document.getElementById('rule').textContent = STATE.rule;
  renderChips();
}
function renderChips(){
  const o = STATE.overlay||{}, items=[];
  (o.deny_cmds||[]).forEach(v=>items.push(['cmd',v]));
  (o.deny_paths||[]).forEach(v=>items.push(['path',v]));
  (o.deny_hosts||[]).forEach(v=>items.push(['host',v]));
  (o.deny_tools||[]).forEach(v=>items.push(['tool',v]));
  document.getElementById('chips').innerHTML = items.length
    ? items.map(([t,v])=>'<span class="chip" onclick="rm(\''+t+'\','+JSON.stringify(v)+')">− '+t+' '+esc(v)+' ✕</span>').join('')
    : '<span class="muted">no overlay rules — add one below</span>';
}
async function addRule(){
  const type=document.getElementById('rtype').value, el=document.getElementById('rval'), value=el.value.trim();
  if(!value) return;
  STATE.overlay = await (await fetch('/api/deny?t='+T,{method:'POST',headers:H,body:JSON.stringify({type,value})})).json();
  el.value=''; renderChips();
}
async function rm(type,value){
  STATE.overlay = await (await fetch('/api/allow?t='+T,{method:'POST',headers:H,body:JSON.stringify({type,value})})).json();
  renderChips();
}
load();
</script></body></html>`
