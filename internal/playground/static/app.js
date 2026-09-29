/* Patch Log playground. Vanilla JS, no dependencies, works offline. */
(() => {
'use strict';

const PJ = 'application/json-patch+json';
const ID_RE = /^1[a-z2-7]{32}$/;
const $ = (id) => document.getElementById(id);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ------------------------------------------------------------------ *
 * small helpers
 * ------------------------------------------------------------------ */
const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch (_) { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (_) { /* private mode etc. */ } },
};

function h(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else if (k.startsWith('on')) n[k] = v;
    else n.setAttribute(k, v === true ? '' : v);
  }
  const add = (c) => {
    if (c == null || c === false) return;
    if (Array.isArray(c)) c.forEach(add);
    else n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  };
  kids.forEach(add);
  return n;
}
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const short = (id) => (id && id.length > 14 ? id.slice(0, 7) + '\u2026' + id.slice(-5) : id || '');
const sq = (s) => "'" + String(s).replace(/'/g, "'\\''") + "'";
const tsFmt = (s) => (s ? String(s).replace('T', ' ').replace(/\.\d+Z$/, 'Z') : '');
const quoteId = (s) => (s && !s.startsWith('"') ? '"' + s + '"' : s);

function pretty(text) {
  try { return JSON.stringify(JSON.parse(text), null, 2); } catch (_) { return text; }
}
function hlJSON(text) {
  const re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(?:true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
  let out = '', last = 0, m;
  while ((m = re.exec(text))) {
    out += esc(text.slice(last, m.index));
    let cls = 'j-n';
    if (m[1]) cls = m[2] ? 'j-k' : 'j-s';
    else if (/^(true|false|null)$/.test(m[0])) cls = 'j-b';
    out += m[1] && m[2]
      ? `<span class="${cls}">${esc(m[1])}</span>${esc(m[2])}`
      : `<span class="${cls}">${esc(m[0])}</span>`;
    last = re.lastIndex;
  }
  return out + esc(text.slice(last));
}
function jsonPre(value, cls) {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  const p = h('pre', { class: 'json ' + (cls || '') });
  p.innerHTML = hlJSON(text);
  return p;
}
function setJSON(pre, value) {
  if (value === undefined || value === null) { pre.textContent = '\u2014'; pre.className = 'json empty'; return; }
  pre.className = 'json';
  pre.innerHTML = hlJSON(typeof value === 'string' ? value : JSON.stringify(value, null, 2));
}
function idEl(id) {
  return h('span', { class: 'id', title: id + '  (click to copy)', onclick: (e) => { e.stopPropagation(); copy(id); } }, short(id));
}
function fmtPatch(ops) {
  return '[\n' + ops.map((o) => '  ' + JSON.stringify(o)).join(',\n') + '\n]';
}
function tryParse(text) { try { return { ok: true, v: JSON.parse(text) }; } catch (e) { return { ok: false, err: e.message }; } }

let toastTimer;
function toast(msg) {
  document.querySelectorAll('.toast').forEach((t) => t.remove());
  const t = h('div', { class: 'toast', role: 'status' }, msg);
  document.body.append(t);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.remove(), 2200);
}
async function copy(text, what) {
  try {
    if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(text);
    else {
      const ta = h('textarea', { style: 'position:fixed;opacity:0' }); ta.value = text;
      document.body.append(ta); ta.select(); document.execCommand('copy'); ta.remove();
    }
    toast('Copied ' + (what || short(text)));
  } catch (_) { toast('Copy failed'); }
}

/* ------------------------------------------------------------------ *
 * state
 * ------------------------------------------------------------------ */
const S = {
  ns: '', res: '',
  nsHead: '', config: '', nsDoc: null, nsErr: null, nsLog: [], heads: [], headsNext: '', branches: [],
  resState: null, hist: [], selRev: '',
  ifDirty: false, cfgDirty: false,
};

/* ------------------------------------------------------------------ *
 * request inspector
 * ------------------------------------------------------------------ */
const INTERESTING = ['ETag', 'Location', 'X-Revision', 'X-Namespace-Revision', 'X-Config-Revision', 'Cache-Control',
  'Cache-Tag', 'Retry-After', 'CDN-Cache-Control', 'X-Cursor', 'Content-Type'];
const insp = { entries: [], seq: 0, filter: 'all', q: '', label: '', manual: 0, showAuto: false };
const MAX_ENTRIES = 300;

function maskAuth(v) {
  const m = /^(Bearer\s+)(.+)$/i.exec(v);
  if (!m) return '\u2026';
  return m[1] + (m[2].length > 14 ? m[2].slice(0, 6) + '\u2026' + m[2].slice(-4) : '\u2026');
}

function toCurl(e) {
  const parts = ['curl -i'];
  if (e.sse) parts[0] = 'curl -i -N';
  if (e.method !== 'GET' && !e.sse) parts.push('-X ' + e.method);
  if (e.redirected) parts.push('-L');
  parts.push(sq(location.origin + e.path));
  for (const [k, v] of Object.entries(e.reqHeaders)) parts.push('-H ' + sq(k + ': ' + v));
  if (e.reqBody !== undefined) parts.push('--data-raw ' + sq(e.reqBody));
  return parts.join(' \\\n  ');
}

function errSummary(e) {
  const j = e.json;
  if (!j || typeof j !== 'object' || Array.isArray(j)) return e.status >= 400 ? `HTTP ${e.status}` : '';
  const bits = [j.code || `HTTP ${e.status}`];
  if (j.message) bits.push(j.message);
  for (const k of ['head', 'config', 'rule', 'path', 'pointer', 'successor', 'horizon', 'tombstone', 'last']) {
    if (j[k] !== undefined) bits.push(`${k}=${typeof j[k] === 'string' ? short(j[k]) : JSON.stringify(j[k])}`);
  }
  if (Array.isArray(j.errors) && j.errors[0]) bits.push(`${j.errors.length} validation error(s)`);
  if (Array.isArray(j.items)) bits.push(`${j.items.length} item(s)`);
  return bits.join('  \u00b7  ');
}

function statusClass(e) {
  if (e.neterr) return 'neterr';
  if (e.sse) return 'sse';
  if (e.status == null) return 'pend';
  return 's' + Math.floor(e.status / 100);
}

function renderEntry(e) {
  if (!e.node) {
    e.node = h('details', { class: 'req' });
    $('inspList').prepend(e.node);
  }
  const n = e.node;
  const sc = statusClass(e);
  n.className = 'req ' + sc + (e.auto ? ' auto' : '');
  const isErr = e.neterr || (e.status != null && e.status >= 400);
  n.dataset.write = (e.method !== 'GET' && !e.sse) ? '1' : '';
  n.dataset.err = isErr ? '1' : '';
  n.dataset.text = (e.method + ' ' + e.path + ' ' + (e.label || '') + ' ' + (e.status || '')).toLowerCase();

  const sum = h('summary', {},
    h('span', { class: 'pill ' + sc }, e.neterr ? 'ERR' : e.sse ? 'live' : e.status == null ? '\u2026' : e.status),
    h('span', { class: 'meth' }, e.method),
    h('span', { class: 'path' }, e.path, e.redirected ? h('span', { class: 'redir' }, ' \u21aa ' + e.finalPath) : null),
    h('span', { class: 'rmeta' }, e.time.toLocaleTimeString([], { hour12: false }) + (e.ms != null ? ' \u00b7 ' + Math.round(e.ms) + ' ms' : '')),
    e.label ? h('span', { class: 'tag' }, e.label) : null,
    e.neterr ? h('div', { class: 'errline' }, 'network error: ' + e.neterr)
      : isErr ? h('div', { class: 'errline' }, errSummary(e)) : null);

  const body = h('div', { class: 'req-body' });
  if (e.redirected) body.append(h('div', { class: 'redir' }, `Followed redirect \u2192 ${e.finalPath}. Status, headers and body below are from the final response.`));

  // request
  const reqHdrs = h('div', { class: 'hdrs' });
  for (const [k, v] of Object.entries(e.reqHeaders)) {
    reqHdrs.append(h('b', {}, k), h('span', {}, /^authorization$/i.test(k) ? maskAuth(v) : v));
  }
  body.append(h('div', {},
    h('h3', {}, 'Request'),
    h('div', { class: 'mono' }, e.method + ' ' + location.origin + e.path),
    Object.keys(e.reqHeaders).length ? reqHdrs : h('div', { class: 'muted small' }, '(no custom headers)'),
    e.reqBody !== undefined ? h('div', { style: 'margin-top:4px' }, jsonPre(pretty(e.reqBody))) : null));

  // response
  if (e.neterr) {
    body.append(h('div', { class: 'errbox' }, h('span', { class: 'code' }, 'network error'), ' ' + e.neterr));
  } else if (e.status != null || e.sse) {
    const res = h('div', {}, h('h3', {}, 'Response'));
    if (e.status != null) res.append(h('div', { class: 'mono' }, `HTTP ${e.status} ${e.statusText || ''}`.trim()));
    if (e.resHeaders) {
      const hd = h('div', { class: 'hdrs' });
      const seen = new Set();
      for (const k of INTERESTING) {
        const v = e.resHeaders.get(k);
        if (v != null) { seen.add(k.toLowerCase()); hd.append(h('b', {}, k), h('span', {}, v)); }
      }
      res.append(hd.children.length ? hd : h('div', { class: 'muted small' }, '(none of the headers of interest)'));
      const rest = [...e.resHeaders.entries()].filter(([k]) => !seen.has(k));
      if (rest.length) {
        const all = h('div', { class: 'hdrs' });
        rest.forEach(([k, v]) => all.append(h('b', {}, k), h('span', {}, v)));
        res.append(h('details', {}, h('summary', { class: 'muted small' }, `${rest.length} more header(s)`), all));
      }
    }
    if (isErr && e.json && typeof e.json === 'object') res.append(errBox(e));
    if (e.resBody) {
      const shown = e.resBody.length > 60000 ? e.resBody.slice(0, 60000) + '\n\u2026 (truncated)' : e.resBody;
      res.append(h('div', { style: 'margin-top:4px' }, jsonPre(pretty(shown))));
    } else if (!e.sse) res.append(h('div', { class: 'muted small' }, '(empty body)'));
    body.append(res);
  }

  const actions = h('div', { class: 'actions' },
    h('button', { class: 'tiny', onclick: () => copy(toCurl(e), 'curl command') }, 'Copy as curl'),
    h('button', { class: 'tiny', onclick: () => copy(location.origin + e.path, 'URL') }, 'Copy URL'),
    e.resBody ? h('button', { class: 'tiny', onclick: () => copy(e.resBody, 'response body') }, 'Copy response') : null);
  body.append(actions);

  n.replaceChildren(sum, body);
  applyFilter(e);
}

function errBox(e) {
  const j = e.json;
  const box = h('div', { class: 'errbox' },
    h('span', { class: 'code' }, j.code || 'HTTP ' + e.status),
    j.message ? '  ' + j.message : null);
  if (Array.isArray(j.errors) && j.errors.length) {
    const t = h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'pointer'), h('th', {}, 'message'))));
    const tb = h('tbody');
    j.errors.forEach((x) => tb.append(h('tr', {}, h('td', { class: 'mono' }, x.pointer || ''), h('td', { style: 'white-space:normal' }, x.message || ''))));
    t.append(tb); box.append(t);
  }
  if (Array.isArray(j.items) && j.items.length) {
    const t = h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'item'), h('th', {}, 'status'), h('th', {}, 'code'), h('th', {}, 'detail'))));
    const tb = h('tbody');
    j.items.forEach((x) => {
      const { index, status, code, ...rest } = x;
      tb.append(h('tr', {}, h('td', {}, index), h('td', {}, status), h('td', { class: 'mono' }, code || ''), h('td', { class: 'mono', style: 'white-space:normal' }, Object.keys(rest).length ? JSON.stringify(rest) : '')));
    });
    t.append(tb); box.append(t);
  }
  const acts = h('div', { class: 'actions', style: 'margin-top:5px' });
  if (typeof j.head === 'string') acts.append(h('button', { class: 'tiny', onclick: () => { setIfMatch(j.head); toast('If-Match set to head'); } }, 'Use head as If-Match'));
  if (typeof j.config === 'string') acts.append(h('button', { class: 'tiny', onclick: () => { $('nsIfMatch').value = j.config; S.cfgDirty = true; toast('Config If-Match set'); } }, 'Use config as If-Match'));
  if (acts.children.length) box.append(acts);
  return box;
}

function applyFilter(e) {
  const n = e.node; if (!n) return;
  let show = true;
  if (insp.filter === 'writes') show = n.dataset.write === '1';
  if (insp.filter === 'errors') show = n.dataset.err === '1';
  if (show && insp.q) show = n.dataset.text.includes(insp.q);
  if (show && e.auto && !insp.showAuto) show = false;
  n.hidden = !show;
}
function updateHidden() {
  const n = insp.entries.filter((e) => e.auto).length;
  $('inspHidden').textContent = insp.showAuto || !n ? '' : `(${n} hidden)`;
}
/* run a user-initiated action: the reads it triggers are shown, not treated as background */
async function asUser(fn) {
  insp.manual++;
  try { return await fn(); } finally { insp.manual--; }
}

function newEntry(o) {
  const e = Object.assign({ id: ++insp.seq, time: new Date(), reqHeaders: {}, auto: false, label: insp.label }, o);
  insp.entries.push(e);
  if (insp.entries.length > MAX_ENTRIES) { const old = insp.entries.shift(); old.node && old.node.remove(); }
  const empty = document.querySelector('.insp-empty'); if (empty) empty.remove();
  renderEntry(e);
  $('inspCount').textContent = insp.entries.length;
  updateHidden();
  return e;
}

function authHeaders() {
  const hd = {};
  const a = $('author').value.trim();
  if (a) hd['X-Author'] = a;
  const b = $('bearer').value.trim();
  if (b) hd['Authorization'] = /^bearer\s/i.test(b) ? b : 'Bearer ' + b;
  return hd;
}

/* api(method, path, {headers, body, ct, auto, label, stream}) -> Response wrapper */
async function api(method, path, o = {}) {
  const headers = authHeaders();
  for (const [k, v] of Object.entries(o.headers || {})) if (v != null && v !== '') headers[k] = v;
  let body = o.body;
  if (body !== undefined && typeof body !== 'string') body = JSON.stringify(body);
  if (body !== undefined && !headers['Content-Type']) headers['Content-Type'] = o.ct || 'application/json';
  const e = newEntry({ method, path, reqHeaders: headers, reqBody: body, auto: !!o.auto && !insp.manual, label: o.label !== undefined ? o.label : insp.label });
  const t0 = performance.now();
  const ctl = new AbortController();
  try {
    const res = await fetch(path, { method, headers, body, cache: 'no-store', redirect: 'follow', credentials: 'same-origin', signal: ctl.signal });
    e.status = res.status; e.statusText = res.statusText; e.resHeaders = res.headers;
    e.redirected = res.redirected;
    if (res.redirected) { const u = new URL(res.url); e.finalPath = u.pathname + u.search; }
    else e.finalPath = path;
    if (o.stream && res.ok) { ctl.abort(); e.resBody = '(event stream opened, then closed by the probe)'; }
    else e.resBody = await res.text();
    try { e.json = e.resBody ? JSON.parse(e.resBody) : null; } catch (_) { e.json = null; }
  } catch (err) {
    e.neterr = err && err.message ? err.message : String(err);
  }
  e.ms = performance.now() - t0;
  renderEntry(e);
  return wrap(e);
}
function wrap(e) {
  return {
    entry: e, status: e.status, ok: e.status >= 200 && e.status < 300, json: e.json, text: e.resBody,
    finalPath: e.finalPath, redirected: e.redirected, neterr: e.neterr,
    hdr: (k) => (e.resHeaders ? e.resHeaders.get(k) : null),
    etag() { const v = this.hdr('ETag'); return v ? v.replace(/^"|"$/g, '') : ''; },
  };
}

/* ------------------------------------------------------------------ *
 * connection bar
 * ------------------------------------------------------------------ */
function initConn() {
  $('author').value = store.get('pl.author', '');
  $('bearer').value = store.get('pl.bearer', '');
  $('author').addEventListener('input', () => store.set('pl.author', $('author').value));
  $('bearer').addEventListener('input', () => { store.set('pl.bearer', $('bearer').value); updateLiveWarn(); });
  api('GET', '/', { label: 'connect' }).then((r) => {
    $('origin').textContent = r.ok && r.json && r.json.origin ? 'origin ' + r.json.origin : (r.neterr ? 'server unreachable' : 'HTTP ' + r.status);
  });
}

/* ------------------------------------------------------------------ *
 * namespaces
 * ------------------------------------------------------------------ */
let known = [];
function loadKnown() { known = store.get('pl.known', []); if (!Array.isArray(known)) known = []; }
function addKnown(n) { if (n && !known.includes(n)) { known.push(n); known.sort(); store.set('pl.known', known); } renderNsSelect(); }
function renderNsSelect() {
  const sel = $('nsSel');
  sel.replaceChildren(h('option', { value: '' }, known.length ? '\u2014 select \u2014' : '\u2014 none yet \u2014'),
    ...known.map((n) => h('option', { value: n, selected: n === S.ns }, n)));
  sel.value = S.ns;
}

function resetNsState() {
  Object.assign(S, { nsHead: '', config: '', nsDoc: null, nsErr: null, nsLog: [], heads: [], headsNext: '', branches: [],
    resState: null, hist: [], selRev: '', cfgDirty: false, ifDirty: false });
}

async function selectNS(name, o = {}) {
  name = (name || '').trim();
  S.ns = name; if (!o.keepRes) S.res = '';
  resetNsState();
  store.set('pl.ns', name); store.set('pl.res', S.res);
  if (name) addKnown(name); else renderNsSelect();
  $('resName').value = S.res;
  renderNsAll(); renderResAll(); renderHistory();
  if (!name) { updateLiveUrls(); restartStreams(); return; }
  await refreshNS();
  if (S.res) await refreshRes();
  restartStreams();
}

async function refreshNS() {
  const ns = S.ns; if (!ns) return;
  let r = await api('GET', `/ns/${ns}`, { auto: true });
  if (ns !== S.ns) return;
  S.nsErr = null;
  if (r.status === 200) {
    S.nsHead = r.etag() || ((/\/rev\/([^/]+)$/.exec(r.finalPath) || [])[1] || '');
    S.config = r.hdr('X-Config-Revision') || '';
    S.nsDoc = r.json;
  } else {
    S.nsErr = r; S.nsDoc = null; S.nsHead = ''; S.config = '';
    // Fall back to the log, which 302s to the range and reveals the head in its final URL.
    const l = await api('GET', `/ns/${ns}/log`, { auto: true });
    if (ns !== S.ns) return;
    if (l.status === 200) {
      S.nsHead = (/\/rev\/([^/]+)\/log/.exec(l.finalPath) || [])[1] || '';
      S.nsLog = Array.isArray(l.json) ? l.json : [];
      const cfg = [...S.nsLog].reverse().find((x) => x.kind === 'config');
      S.config = cfg ? cfg.target : '';
      S.nsErr = null;
    }
  }
  if (!S.nsHead) { S.nsLog = []; S.heads = []; S.branches = []; renderNsAll(); updateLiveUrls(); return; }
  renderNsAll();
  const head = S.nsHead;
  const [lg, hd, br] = await Promise.all([
    api('GET', `/ns/${ns}/rev/${head}/log`, { auto: true }),
    api('GET', `/ns/${ns}/rev/${head}/heads`, { auto: true }),
    api('GET', `/ns/${ns}/branches`, { auto: true }),
  ]);
  if (ns !== S.ns) return;
  if (lg.status === 200 && Array.isArray(lg.json)) S.nsLog = lg.json;
  if (hd.status === 200 && hd.json) { S.heads = hd.json.items || []; S.headsNext = hd.json.next || ''; }
  if (br.status === 200 && Array.isArray(br.json)) S.branches = br.json; else S.branches = [];
  renderNsAll();
  updateLiveUrls();
}

function renderNsAll() {
  renderNsStatus(); renderNsDoc(); renderNsLog(); renderHeads(); renderBranches();
  if (!S.cfgDirty) $('nsIfMatch').value = S.config || '';
  if (!$('nsPurgeIm').dataset.dirty) $('nsPurgeIm').value = S.nsHead || '';
}

function renderNsStatus() {
  const box = $('nsStatus');
  if (!S.ns) { box.className = 'muted'; box.textContent = 'Select or add a namespace above.'; return; }
  if (!S.nsHead) {
    box.className = '';
    const r = S.nsErr;
    box.replaceChildren(h('div', { class: 'state-line' }, h('b', {}, S.ns), h('span', { class: 'badge warn' }, r ? 'not readable / unknown' : 'loading\u2026')),
      r ? h('div', { class: 'muted' }, `GET /ns/${S.ns} answered ${r.status}${r.json && r.json.code ? ' ' + r.json.code : ''}. Create it with the form, or check Author / Bearer grant (a namespace you cannot read looks the same as one that does not exist).`) : null);
    return;
  }
  const d = S.nsDoc || {};
  const kv = h('dl', { class: 'kv' },
    h('dt', {}, 'ns_id (head)'), h('dd', {}, idEl(S.nsHead)),
    h('dt', {}, 'config id'), h('dd', {}, S.config ? idEl(S.config) : h('span', { class: 'muted' }, 'unknown')),
    h('dt', {}, 'readable'), h('dd', {}, S.nsDoc ? 'document, log, heads' : 'log only (document not readable)'));
  if (d.base) kv.append(h('dt', {}, 'base'), h('dd', {}, `${d.base.ns} @ `, idEl(d.base.at)));
  if (d.successor) kv.append(h('dt', {}, 'successor'), h('dd', {}, d.successor));
  box.className = '';
  box.replaceChildren(
    h('div', { class: 'state-line' }, h('b', {}, S.ns),
      d.read ? h('span', { class: 'badge ' + (d.read === 'public' ? 'info' : '') }, 'read: ' + d.read) : null,
      d.frozen ? h('span', { class: 'badge warn' }, 'frozen') : null,
      d.base ? h('span', { class: 'badge' }, 'branch') : null),
    kv);
}

function renderNsDoc() {
  setJSON($('nsDoc'), S.nsDoc);
  $('nsDocMeta').textContent = S.nsHead ? `as of ${short(S.nsHead)}` : '';
}

function kindBadge(kind) {
  const cls = { tombstone: 'tomb', purge: 'err', 'purge-ns': 'err', config: 'info', batch: 'ok', branch: 'info', prune: 'warn', head: 'live', rev: 'live' }[kind] || '';
  return h('span', { class: 'badge ' + cls }, kind);
}

function renderNsLog() {
  const tb = $('nsLog').tBodies[0];
  const rows = [...S.nsLog].reverse().slice(0, 200);
  $('nsLogMeta').textContent = S.nsLog.length ? `${S.nsLog.length} entr${S.nsLog.length === 1 ? 'y' : 'ies'}${S.nsLog.length > 200 ? ' (latest 200 shown)' : ''}` : '';
  if (!rows.length) { tb.replaceChildren(h('tr', {}, h('td', { class: 'empty', colspan: 6 }, S.ns ? 'No entries.' : 'No namespace selected.'))); return; }
  tb.replaceChildren(...rows.map((e) => {
    const target = e.target || e.name || '';
    const tr = h('tr', { class: 'click' + (e.kind === 'tombstone' ? ' tomb' : '') },
      h('td', {}, kindBadge(e.kind)),
      h('td', { class: 'mono' }, e.resource || (e.kind === 'branch' ? e.name : '') || ''),
      h('td', {}, ID_RE.test(target) ? idEl(target) : h('span', { class: 'mono' }, target)),
      h('td', {}, e.author || ''),
      h('td', { class: 'mono', title: e.created }, tsFmt(e.created)),
      h('td', {}, idEl(e.id)));
    tr.title = 'entry ' + JSON.stringify(e);
    tr.onclick = () => { if (e.resource) openResource(e.resource); else if (e.kind === 'branch' && e.name) asUser(() => selectNS(e.name)); };
    return tr;
  }));
}

function renderHeads() {
  const tb = $('headsTbl').tBodies[0];
  $('headsMeta').textContent = S.heads.length ? `${S.heads.length} resource(s)` : '';
  $('headsMore').hidden = !S.headsNext;
  const dl = $('headsList');
  dl.replaceChildren(...S.heads.map((x) => h('option', { value: x.resource })));
  if (!S.heads.length) { tb.replaceChildren(h('tr', {}, h('td', { class: 'empty', colspan: 3 }, S.nsHead ? 'No resources yet.' : '\u2014'))); return; }
  tb.replaceChildren(...S.heads.map((x) => {
    const tr = h('tr', { class: 'click' + (x.kind === 'tombstone' ? ' tomb' : '') + (x.resource === S.res ? ' sel' : '') },
      h('td', { class: 'mono' }, x.resource), h('td', {}, kindBadge(x.kind)), h('td', {}, x.target ? idEl(x.target) : ''));
    tr.onclick = () => openResource(x.resource);
    return tr;
  }));
}

function renderBranches() {
  const tb = $('brTbl').tBodies[0];
  if (!S.branches.length) { tb.replaceChildren(h('tr', {}, h('td', { class: 'empty', colspan: 6 }, 'No branches.'))); return; }
  tb.replaceChildren(...S.branches.map((b) => h('tr', {},
    h('td', { class: 'mono' }, b.name || (b.remote ? 'remote ' + b.remote : '')),
    h('td', {}, b.at ? idEl(b.at) : ''),
    h('td', {}, b.frozen ? h('span', { class: 'badge warn' }, 'frozen') : 'no'),
    h('td', {}, b.purged ? h('span', { class: 'badge err' }, 'purged') : 'no'),
    h('td', { class: 'mono' }, b.successor || ''),
    h('td', {}, b.name ? h('button', { class: 'tiny', onclick: () => asUser(() => selectNS(b.name)) }, 'open') : ''))));
}

async function headsMore() {
  if (!S.headsNext || !S.nsHead) return;
  const r = await api('GET', `/ns/${S.ns}/rev/${S.nsHead}/heads?after=${encodeURIComponent(S.headsNext)}`, { auto: true });
  if (r.status === 200 && r.json) { S.heads = S.heads.concat(r.json.items || []); S.headsNext = r.json.next || ''; renderHeads(); }
}

/* namespace actions */
async function createNamespace() {
  const name = $('nsNewName').value.trim();
  if (!name) return toast('Enter a namespace name');
  const doc = tryParse($('nsNewDoc').value);
  if (!doc.ok) return toast('Document is not valid JSON');
  const r = await api('PATCH', `/ns/${name}`, { ct: PJ, headers: { 'If-None-Match': '*' }, body: [{ op: 'add', path: '', value: doc.v }] });
  if (r.ok) { toast(`Created ${name}`); await selectNS(name); }
}

async function applyConfig(patchText) {
  if (!S.ns) return toast('Select a namespace first');
  const im = $('nsIfMatch').value.trim();
  const r = await api('PATCH', `/ns/${S.ns}`, { ct: PJ, headers: { 'If-Match': im ? quoteId(im) : '' }, body: patchText });
  if (r.ok) { S.cfgDirty = false; await refreshNS(); if (S.res) await refreshRes(); }
  return r;
}
function freeze(v) { return applyConfig(fmtPatch([{ op: 'add', path: '/frozen', value: v }])); }

async function purgeNamespace() {
  if (!S.ns) return toast('Select a namespace first');
  const im = $('nsPurgeIm').value.trim();
  if (!confirm(`Purge namespace "${S.ns}"?\n\nThis removes all resource content and cannot be undone. The namespace must be frozen and have no live branches.`)) return;
  const r = await api('POST', `/ns/${S.ns}/purge`, { headers: { 'If-Match': im ? quoteId(im) : '' } });
  if (r.ok) { toast('Namespace purged'); await refreshNS(); if (S.res) await refreshRes(); }
}

async function createBranch() {
  if (!S.ns) return toast('Select a namespace first');
  const name = $('brName').value.trim();
  if (!name) return toast('Enter a branch name');
  const body = { name };
  const at = $('brAt').value.trim(); if (at) body.at = at;
  const pt = $('brPatches').value.trim();
  if (pt) { const p = tryParse(pt); if (!p.ok) return toast('Patches are not valid JSON'); body.patches = p.v; }
  const r = await api('POST', `/ns/${S.ns}/branches`, { headers: { 'If-None-Match': '*' }, body });
  if (r.ok || r.status === 200) { addKnown(name); toast(`Branch ${name} created`); await refreshNS(); }
}

/* ------------------------------------------------------------------ *
 * resources
 * ------------------------------------------------------------------ */
function rpath(suffix = '') { return `/r/${S.ns}/${S.res}${suffix}`; }
function setIfMatch(v) { $('ifMatch').value = v; S.ifDirty = true; }

function openResource(name, tab = 'res') {
  asUser(() => selectRes(name)); showTab(tab);
}

async function selectRes(name) {
  name = (name || '').trim();
  S.res = name; S.resState = null; S.hist = []; S.selRev = ''; S.ifDirty = false;
  store.set('pl.res', name);
  $('resName').value = name;
  renderResAll(); renderHistory(); renderHeads();
  if (S.ns && name) await refreshRes();
  updateLiveUrls();
  restartStreams('res');
}

async function refreshRes() {
  const { ns, res } = S;
  if (!ns || !res) return;
  const r = await api('GET', rpath(), { auto: true });
  if (ns !== S.ns || res !== S.res) return;
  let st;
  if (r.status === 200) st = { kind: 'live', head: r.hdr('X-Revision') || r.etag(), doc: r.json, via: r.finalPath };
  else if (r.status === 410 && r.json && r.json.tombstone) st = { kind: 'tomb', head: r.json.tombstone, last: r.json.last };
  else if (r.status === 410) st = { kind: 'purged' };
  else if (r.status === 404) st = { kind: 'missing' };
  else st = { kind: 'error', status: r.status, code: r.json && r.json.code };
  S.resState = st;
  if (st.kind === 'tomb' && st.last) {
    const lr = await api('GET', rpath(`/rev/${st.last}`), { auto: true });
    if (ns !== S.ns || res !== S.res) return;
    if (lr.status === 200) st.lastDoc = lr.json;
  }
  renderResAll();
  if (!S.ifDirty) $('ifMatch').value = st.head || '';
  await loadHistory();
  renderHeads();
}

function renderResAll() {
  const box = $('resState'), st = S.resState;
  const pre = $('resDoc');
  if (!S.ns || !S.res) { box.className = 'muted'; box.textContent = 'Pick a resource from the heads table, or type a name above.'; setJSON(pre, null); return; }
  if (!st) { box.className = 'muted'; box.textContent = `${S.res} \u2014 loading\u2026`; setJSON(pre, null); return; }
  box.className = '';
  const line = h('div', { class: 'state-line' }, h('b', { class: 'mono' }, `${S.ns}/${S.res}`));
  switch (st.kind) {
    case 'live':
      line.append(h('span', { class: 'badge live' }, 'live'), h('span', { class: 'muted' }, 'head'), idEl(st.head));
      setJSON(pre, st.doc); break;
    case 'tomb':
      line.append(h('span', { class: 'badge tomb' }, 'tombstoned'), h('span', { class: 'muted' }, 'tombstone'), idEl(st.head));
      if (st.last) line.append(h('span', { class: 'muted' }, 'last'), idEl(st.last));
      box.replaceChildren(line, h('div', { class: 'note' }, 'GET answered 410. Restore with If-Match set to the tombstone; the document below is the last live one.'));
      setJSON(pre, st.lastDoc); return;
    case 'purged':
      line.append(h('span', { class: 'badge err' }, 'purged'));
      box.replaceChildren(line, h('div', { class: 'note' }, '410 gone: the content was removed for good. Creating this name again is refused.'));
      setJSON(pre, null); return;
    case 'missing':
      line.append(h('span', { class: 'badge' }, 'not found'));
      box.replaceChildren(line, h('div', { class: 'note' }, '404: never existed (or not readable by this caller). Use Create with If-None-Match: *.'));
      setJSON(pre, null); return;
    default:
      line.append(h('span', { class: 'badge err' }, `HTTP ${st.status}${st.code ? ' ' + st.code : ''}`));
      setJSON(pre, null);
  }
  box.replaceChildren(line);
}

function normIf(v) { v = (v || '').trim(); return v ? quoteId(v) : ''; }

async function writeRes(kind) {
  if (!S.ns || !S.res) return toast('Select a namespace and a resource name');
  const patch = $('patch').value;
  let r;
  if (kind === 'create') r = await api('PATCH', rpath(), { ct: PJ, headers: { 'If-None-Match': '*' }, body: patch });
  else if (kind === 'append') r = await api('PATCH', rpath(), { ct: PJ, headers: { 'If-Match': normIf($('ifMatch').value) }, body: patch });
  else if (kind === 'restore') r = await api('PATCH', rpath(), { ct: PJ, headers: { 'If-Match': normIf($('ifMatch').value) }, body: $('restoreEditor').checked ? patch : '[]' });
  else if (kind === 'delete') r = await api('DELETE', rpath(), { headers: { 'If-Match': normIf($('ifMatch').value) } });
  if (r && (r.status === 201 || (kind === 'delete' && r.ok))) { S.ifDirty = false; await afterWrite(); }
  else if (r && r.status === 200) toast('200: idempotent retry, entry already in the log');
}
async function afterWrite() { await refreshNS(); await refreshRes(); }

async function purgeRes() {
  if (!S.ns || !S.res) return toast('Select a namespace and a resource name');
  if (!confirm(`Purge ${S.ns}/${S.res}?\n\nIts content is removed for good.`)) return;
  const force = $('purgeForce').checked ? '?force=1' : '';
  const r = await api('POST', rpath('/purge' + force), { headers: { 'If-Match': normIf($('ifMatch').value) } });
  if (r.ok) { toast('Purged'); await afterWrite(); }
}

async function pruneRes() {
  if (!S.ns || !S.res) return toast('Select a namespace and a resource name');
  const horizon = $('pruneH').value.trim();
  const body = { horizon };
  const keep = $('pruneKeep').value.split(',').map((s) => s.trim()).filter(Boolean);
  if (keep.length) body.keep = keep;
  const r = await api('POST', rpath('/prune'), { body });
  if (r.ok) { toast('Pruned; effective horizon ' + short((r.json || {}).horizon || '')); await afterWrite(); }
}

/* templates */
const TEMPLATES = [
  ['add', () => ({ op: 'add', path: '/title', value: 'hello' })],
  ['replace', () => ({ op: 'replace', path: '/title', value: 'hello again' })],
  ['remove', () => ({ op: 'remove', path: '/title' })],
  ['test', () => ({ op: 'test', path: '/title', value: 'hello' })],
  ['array append', () => ({ op: 'add', path: '/tags/-', value: 'new' })],
  ['move', () => ({ op: 'move', from: '/a', path: '/b' })],
  ['copy', () => ({ op: 'copy', from: '/a', path: '/b' })],
  ['root add', () => ({ op: 'add', path: '', value: { title: 'Hello' } })],
  ['root replace', () => ({ op: 'replace', path: '', value: {} })],
  ['$schema (revision)', () => ({ op: 'add', path: '/$schema', value: `/r/${S.ns || 'ns'}/schema-name/rev/1\u2026` })],
  ['$schema (dialect: makes a schema)', () => ({ op: 'add', path: '/$schema', value: 'https://json-schema.org/draft/2020-12/schema' })],
];
function insertOp(textarea, op) {
  const p = tryParse(textarea.value);
  const arr = p.ok && Array.isArray(p.v) ? p.v : [];
  arr.push(op);
  textarea.value = fmtPatch(arr);
  textarea.dispatchEvent(new Event('input'));
}
function buildChips(box, label, items, textareaId) {
  box.replaceChildren(h('span', {}, label), ...items.map(([name, fn]) => h('button', { type: 'button', onclick: () => insertOp($(textareaId), fn()) }, name)));
}

/* ------------------------------------------------------------------ *
 * history
 * ------------------------------------------------------------------ */
async function loadHistory() {
  const st = S.resState;
  if (!st || !st.head) { S.hist = []; renderHistory(); return; }
  const { ns, res } = S;
  const r = await api('GET', rpath(`/rev/${st.head}/log`), { auto: true });
  if (ns !== S.ns || res !== S.res) return;
  S.hist = r.status === 200 && Array.isArray(r.json) ? r.json : [];
  if (r.status !== 200) S.histErr = r; else S.histErr = null;
  renderHistory();
}

function opsSummary(e) {
  if (e.kind === 'tombstone') return 'tombstone (deleted)';
  return (e.patches || []).map((p) => `${p.op} ${p.path === '' ? '(root)' : p.path}`).join(', ') || '(no ops)';
}

function renderHistory() {
  const ul = $('timeline');
  $('histMeta').textContent = S.res ? `${S.ns}/${S.res}` : '';
  if (!S.hist.length) {
    ul.replaceChildren(h('li', { class: 'muted', style: 'cursor:default' }, S.res ? (S.histErr ? `Log answered ${S.histErr.status} ${(S.histErr.json || {}).code || ''}` : 'No history loaded.') : 'Select a resource.'));
    return;
  }
  ul.replaceChildren(...[...S.hist].reverse().map((e) => {
    const tomb = e.kind === 'tombstone';
    const li = h('li', { class: (tomb ? 'tomb ' : '') + (e.id === S.selRev ? 'sel' : ''), tabindex: 0, role: 'button' },
      h('div', { class: 'top1' }, kindBadge(e.kind), idEl(e.id), h('span', { class: 'muted' }, e.author || ''), h('span', { class: 'muted mono', title: e.created }, tsFmt(e.created))),
      h('div', { class: 'ops' }, opsSummary(e)));
    li.onclick = () => selectRev(e.id);
    li.onkeydown = (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); selectRev(e.id); } };
    return li;
  }));
}

async function selectRev(id) {
  S.selRev = id; renderHistory();
  const entry = S.hist.find((x) => x.id === id) || {};
  const box = $('revView');
  box.replaceChildren(h('p', { class: 'muted' }, 'Loading ' + short(id) + '\u2026'));
  const r = await api('GET', rpath(`/rev/${id}`));
  if (S.selRev !== id) return;
  const head = h('div', { class: 'state-line' }, kindBadge(entry.kind || '?'), h('span', { class: 'id', onclick: () => copy(id) }, id),
    entry.parent ? h('span', { class: 'muted' }, 'parent') : null, entry.parent ? idEl(entry.parent) : null);
  const meta = h('div', { class: 'muted small' }, `${entry.author || ''}  ${tsFmt(entry.created)}`);
  const acts = h('div', { class: 'row' },
    h('button', { class: 'tiny', onclick: () => { setIfMatch(id); toast('If-Match set'); showTab('res'); } }, 'Use as If-Match'),
    h('button', { class: 'tiny', onclick: () => { $('pruneH').value = id; toast('Prune horizon set'); showTab('res'); } }, 'Use as prune horizon'),
    h('button', { class: 'tiny', onclick: () => copy(id) }, 'Copy id'));
  const parts = [head, meta, acts];
  if (entry.patches) parts.push(h('h3', {}, 'Patches'), jsonPre(entry.patches));
  if (r.status === 200) parts.push(h('h3', { style: 'margin-top:8px' }, 'Document at this revision'), jsonPre(r.text ? pretty(r.text) : ''));
  else if (r.status === 410 && entry.kind === 'tombstone') parts.push(h('p', { class: 'note' }, '410: a tombstone id has no document; earlier revisions stay readable.'));
  else parts.push(h('div', { class: 'errbox' }, h('span', { class: 'code' }, (r.json && r.json.code) || 'HTTP ' + r.status), '  ' + (r.status === 410 && r.json && r.json.code === 'pruned' ? 'below the horizon ' + short(r.json.horizon || '') : '')));
  box.replaceChildren(...parts);
}

/* ------------------------------------------------------------------ *
 * batch
 * ------------------------------------------------------------------ */
function batchExample() {
  return `{
  "items": [
    { "resource": "post-1", "ifNoneMatch": "*",
      "steps": [ [ { "op": "add", "path": "", "value": { "title": "First" } } ] ] },
    { "resource": "post-2", "ifNoneMatch": "*",
      "steps": [ [ { "op": "add", "path": "", "value": { "title": "Second" } } ] ] }
  ]
}`;
}
function batchInsert(kind) {
  let p = tryParse($('batchBody').value);
  if (!p.ok || !p.v || typeof p.v !== 'object' || Array.isArray(p.v)) p = { ok: true, v: { items: [] } };
  const b = p.v;
  b.items = Array.isArray(b.items) ? b.items : [];
  const target = S.heads.find((x) => x.kind === 'head') || S.heads[0];
  if (kind === 'append') b.items.push({ resource: target ? target.resource : 'post-1', ifMatch: target ? target.target : '1\u2026', steps: [[{ op: 'add', path: '/edited', value: true }]] });
  if (kind === 'delrestore') b.items.push({ resource: target ? target.resource : 'post-1', ifMatch: target ? target.target : '1\u2026', steps: ['delete', []] });
  if (kind === 'delete') b.items.push({ resource: target ? target.resource : 'post-1', ifMatch: target ? target.target : '1\u2026', steps: ['delete'] });
  if (kind === 'config') b.config = { ifMatch: S.config || '1\u2026', patches: [{ op: 'add', path: '/rules', value: [] }] };
  if (kind === 'source') b.source = { ns: S.ns || 'ns', at: S.nsHead || '1\u2026' };
  $('batchBody').value = JSON.stringify(b, null, 2);
  $('batchBody').dispatchEvent(new Event('input'));
}
async function runBatch(dry) {
  if (!S.ns) return toast('Select a namespace first');
  const r = await api('POST', `/ns/${S.ns}/batch${dry ? '?dry-run=1' : ''}`, { body: $('batchBody').value });
  const out = $('batchOut'); out.hidden = false;
  out.replaceChildren(h('div', { class: 'state-line' }, h('span', { class: 'badge ' + (r.ok ? 'ok' : 'err') }, r.neterr ? 'network error' : `HTTP ${r.status}`), h('span', { class: 'muted' }, dry ? 'dry run: nothing written' : (r.ok ? 'committed' : 'nothing written'))),
    jsonPre(r.text ? pretty(r.text) : (r.neterr || '')));
  if (r.ok && !dry) await afterWrite();
}

/* ------------------------------------------------------------------ *
 * live (SSE)
 * ------------------------------------------------------------------ */
const streams = { ns: null, res: null };
const NS_EVENTS = ['head', 'tombstone', 'purge', 'config', 'batch', 'branch', 'purge-ns', 'prune'];
const RES_EVENTS = ['revision', 'tombstone', 'purge', 'prune'];
let refreshTimer;

function liveUrl(kind) {
  if (!S.ns) return '';
  if (kind === 'ns') return `/ns/${S.ns}/events` + (S.nsHead ? `?since=${S.nsHead}` : '');
  if (!S.res) return '';
  const head = S.resState && S.resState.head;
  return `/r/${S.ns}/${S.res}/events` + (head ? `?since=${head}` : '');
}
function updateLiveUrls() {
  if (!streams.ns) $('liveNsUrl').textContent = liveUrl('ns') || '(select a namespace)';
  if (!streams.res) $('liveResUrl').textContent = liveUrl('res') || '(select a resource)';
}
function updateLiveWarn() { $('liveWarn').hidden = !$('bearer').value.trim(); }
function setStreamState(kind, text, cls) {
  const b = $(kind === 'ns' ? 'liveNsSt' : 'liveResSt');
  b.textContent = text; b.className = 'badge ' + (cls || '');
  $('liveDot').hidden = !(streams.ns || streams.res);
}
function stopStream(kind) {
  const s = streams[kind];
  if (s) { s.es.close(); s.entry.status = null; s.entry.statusText = 'closed'; s.entry.resBody = (s.entry.resBody || '') + '\n(closed)'; renderEntry(s.entry); }
  streams[kind] = null;
  setStreamState(kind, 'off', '');
  updateLiveUrls();
}
function startStream(kind) {
  stopStream(kind);
  const url = liveUrl(kind);
  if (!url) { $(kind === 'ns' ? 'liveNs' : 'liveRes').checked = false; return toast(kind === 'ns' ? 'Select a namespace first' : 'Select a resource first'); }
  const entry = newEntry({ method: 'SSE', path: url, sse: true, reqHeaders: { Accept: 'text/event-stream' }, label: 'live ' + kind, resBody: '' });
  const es = new EventSource(url);
  const s = streams[kind] = { es, url, entry, seen: new Set() };
  $(kind === 'ns' ? 'liveNsUrl' : 'liveResUrl').textContent = url;
  setStreamState(kind, 'connecting\u2026', 'warn');
  es.onopen = () => { setStreamState(kind, 'live', 'ok'); entry.statusText = 'open'; renderEntry(entry); };
  es.onerror = () => {
    if (es.readyState === EventSource.CLOSED) {
      setStreamState(kind, 'closed (error)', 'err');
      entry.resBody += '\n(connection failed; probing for the error response)';
      renderEntry(entry);
      es.close(); streams[kind] = null;
      $(kind === 'ns' ? 'liveNs' : 'liveRes').checked = false;
      api('GET', url, { stream: true, label: 'live ' + kind + ' probe' });
    } else setStreamState(kind, 'reconnecting\u2026', 'warn');
  };
  (kind === 'ns' ? NS_EVENTS : RES_EVENTS).forEach((t) => es.addEventListener(t, (ev) => onStreamEvent(kind, s, t, ev)));
}
function onStreamEvent(kind, s, type, ev) {
  const key = type + ':' + ev.lastEventId;
  if (s.seen.has(key)) return;
  s.seen.add(key);
  let data = ev.data; try { data = JSON.parse(ev.data); } catch (_) { /* leave as text */ }
  s.entry.resBody += `event: ${type}\nid: ${ev.lastEventId}\ndata: ${ev.data}\n\n`;
  renderEntry(s.entry);
  const feed = $('feed');
  if (feed.firstChild && feed.firstChild.classList && feed.firstChild.classList.contains('muted')) feed.replaceChildren();
  const d = typeof data === 'object' && data ? data : {};
  feed.prepend(h('li', {}, h('time', {}, new Date().toLocaleTimeString([], { hour12: false })), h('span', { class: 'badge info' }, kind),
    kindBadge(type), d.resource ? h('span', { class: 'mono' }, d.resource) : null, idEl(ev.lastEventId || d.id || ''),
    d.author ? h('span', { class: 'muted' }, d.author) : null,
    h('button', { class: 'link small', onclick: (e) => { e.target.replaceWith(jsonPre(data)); } }, 'json')));
  while (feed.children.length > 200) feed.lastChild.remove();
  $('feedCount').textContent = feed.children.length + ' shown';
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(async () => { await refreshNS(); if (S.res) await refreshRes(); }, 250);
}
function restartStreams(only) {
  for (const kind of ['ns', 'res']) {
    if (only && only !== kind) continue;
    if ($(kind === 'ns' ? 'liveNs' : 'liveRes').checked) startStream(kind); else stopStream(kind);
  }
}

/* ------------------------------------------------------------------ *
 * examples
 * ------------------------------------------------------------------ */
const q = (id) => `"${id}"`;
const rnd = () => Math.random().toString(36).slice(2, 7).replace(/[^a-z0-9]/g, 'x');
const add = (path, value) => ({ op: 'add', path, value });
const NEW = { 'If-None-Match': '*' };

const EXAMPLES = [
  {
    id: 'a', title: 'Create, append, stale 412, rebase',
    desc: 'Optimistic concurrency: a write names the revision it was based on. A stale parent is refused with the current head; retrying on that head works, and repeating a write that already landed is idempotent.',
    steps: [
      { t: 'Create the namespace', why: 'PATCH /ns/{ns} with If-None-Match: *. The body is the genesis patch set; the document is {"read":"public"}.', expect: 201,
        run: (c) => c.req('PATCH', `/ns/${c.ns}`, { ct: PJ, headers: NEW, body: [add('', { read: 'public' })] }) },
      { t: 'Create resource "note"', why: 'Create needs If-None-Match: *. The new revision id is in ETag and Location.', expect: 201,
        run: async (c) => { c.show(c.ns, 'note'); const r = await c.req('PATCH', `/r/${c.ns}/note`, { ct: PJ, headers: NEW, body: [add('', { title: 'Hello', count: 0 })] }); c.v.r1 = r.etag(); return r; } },
      { t: 'Append on the head (If-Match r1)', why: 'Append names its parent in If-Match. It succeeds because r1 is the head.', expect: 201,
        run: async (c) => { const r = await c.req('PATCH', `/r/${c.ns}/note`, { ct: PJ, headers: { 'If-Match': q(c.v.r1) }, body: [{ op: 'replace', path: '/count', value: 1 }] }); c.v.r2 = r.etag(); return r; } },
      { t: 'Stale append (If-Match r1 again)', why: 'r1 is no longer the head, so the server answers 412 stale and puts the current head in the body.', expect: 412,
        run: async (c) => { const r = await c.req('PATCH', `/r/${c.ns}/note`, { ct: PJ, headers: { 'If-Match': q(c.v.r1) }, body: [{ op: 'replace', path: '/title', value: 'Hello, world' }] }); c.v.head = r.json && r.json.head; return r; } },
      { t: 'Rebase: retry on the head from the 412', why: 'Same patch, parent taken from the 412 body. The patch is a path-level change, so it still applies.', expect: 201,
        run: async (c) => { const r = await c.req('PATCH', `/r/${c.ns}/note`, { ct: PJ, headers: { 'If-Match': q(c.v.head) }, body: [{ op: 'replace', path: '/title', value: 'Hello, world' }] }); c.v.r3 = r.etag(); return r; } },
      { t: 'Repeat the same request (lost-response retry)', why: 'The entry this request would produce is already in the log, by the same author with that parent: 200 with the entry, not 412.', expect: 200,
        run: (c) => c.req('PATCH', `/r/${c.ns}/note`, { ct: PJ, headers: { 'If-Match': q(c.v.head) }, body: [{ op: 'replace', path: '/title', value: 'Hello, world' }] }) },
      { t: 'Append without any precondition', why: 'Writes are never unconditional: no If-Match is 428.', expect: 428,
        run: (c) => c.req('PATCH', `/r/${c.ns}/note`, { ct: PJ, body: [{ op: 'replace', path: '/count', value: 99 }] }) },
    ],
  },
  {
    id: 'b', title: 'Typed document, failing validation (422)',
    desc: 'A document that carries $schema is validated on every write against that immutable schema revision. Invalid results are refused with a list of { pointer, message } errors.',
    steps: [
      { t: 'Create the namespace', why: 'Public, no rules.', expect: 201,
        run: (c) => c.req('PATCH', `/ns/${c.ns}`, { ct: PJ, headers: NEW, body: [add('', { read: 'public' })] }) },
      { t: 'Create a schema resource "person"', why: 'A document whose $schema is the bundled 2020-12 dialect URL is itself a schema and is validated against the meta-schema.', expect: 201,
        run: async (c) => {
          c.show(c.ns, 'person');
          const schema = { $schema: 'https://json-schema.org/draft/2020-12/schema', type: 'object', required: ['name', 'age'],
            properties: { name: { type: 'string', minLength: 1 }, age: { type: 'integer', minimum: 0 } } };
          const r = await c.req('PATCH', `/r/${c.ns}/person`, { ct: PJ, headers: NEW, body: [add('', schema)] });
          c.v.schema = r.etag(); return r;
        } },
      { t: 'Create "alice" typed with that revision', why: '$schema must be the revision path /r/{ns}/{name}/rev/{id}: never a head URL, so a validator can be cached forever.', expect: 201,
        run: async (c) => { c.show(c.ns, 'alice'); const r = await c.req('PATCH', `/r/${c.ns}/alice`, { ct: PJ, headers: NEW, body: [add('', { $schema: `/r/${c.ns}/person/rev/${c.v.schema}`, name: 'Alice', age: 30 })] }); c.v.a1 = r.etag(); return r; } },
      { t: 'Append age: "thirty" (wrong type)', why: 'The resulting document fails validation: 422 with errors[] naming the JSON pointer.', expect: 422,
        run: (c) => c.req('PATCH', `/r/${c.ns}/alice`, { ct: PJ, headers: { 'If-Match': q(c.v.a1) }, body: [{ op: 'replace', path: '/age', value: 'thirty' }] }) },
      { t: 'Append: remove the required name', why: 'Also 422: required properties are checked on the whole resulting document.', expect: 422,
        run: (c) => c.req('PATCH', `/r/${c.ns}/alice`, { ct: PJ, headers: { 'If-Match': q(c.v.a1) }, body: [{ op: 'remove', path: '/name' }] }) },
      { t: 'Append age: 31 (valid)', why: 'The failed writes changed nothing, so the parent is still the head.', expect: 201,
        run: async (c) => { const r = await c.req('PATCH', `/r/${c.ns}/alice`, { ct: PJ, headers: { 'If-Match': q(c.v.a1) }, body: [{ op: 'replace', path: '/age', value: 31 }] }); c.v.a2 = r.etag(); return r; } },
      { t: 'Point $schema at a made-up revision', why: 'An unknown or purged revision is 422 schema_unavailable; a malformed path would be schema_ref.', expect: 422,
        run: (c) => c.req('PATCH', `/r/${c.ns}/alice`, { ct: PJ, headers: { 'If-Match': q(c.v.a2) }, body: [{ op: 'replace', path: '/$schema', value: `/r/${c.ns}/person/rev/1${'a'.repeat(32)}` }] }) },
    ],
  },
  {
    id: 'c', title: 'Namespace rules reject a write (422 rule)',
    desc: 'Rules live in the namespace document (§6.4) and judge every write. Here: appends may not replace the whole document, and documents need a string title.',
    steps: [
      { t: 'Create the namespace', why: 'Public, no rules yet.', expect: 201,
        run: async (c) => { const r = await c.req('PATCH', `/ns/${c.ns}`, { ct: PJ, headers: NEW, body: [add('', { read: 'public' })] }); c.v.cfg = r.hdr('X-Config-Revision'); return r; } },
      { t: 'Add two rules with a config patch', why: 'PATCH /ns/{ns} with If-Match set to the config id (X-Config-Revision), not the namespace head.', expect: 201,
        run: async (c) => {
          const rules = [
            { if: [{ op: 'test', path: '/action', value: 'append' }], then: [{ not: { op: 'writes', covers: '' } }] },
            { if: [{ op: 'test', path: '/action', schema: { enum: ['create', 'append', 'restore'] } }], then: [{ op: 'test', path: '/doc/title', schema: { type: 'string' } }] },
          ];
          const r = await c.req('PATCH', `/ns/${c.ns}`, { ct: PJ, headers: { 'If-Match': q(c.v.cfg) }, body: [add('/rules', rules)] });
          return r;
        } },
      { t: 'Create "page" with a title', why: 'Rule 1 is satisfied: /doc/title is a string.', expect: 201,
        run: async (c) => { c.show(c.ns, 'page'); const r = await c.req('PATCH', `/r/${c.ns}/page`, { ct: PJ, headers: NEW, body: [add('', { title: 'Home', body: 'Welcome' })] }); c.v.p1 = r.etag(); return r; } },
      { t: 'Append: replace the whole document', why: 'Rule 0 (index 0) says appends must not cover the root. writes for a root op is "", so it is refused: 422 code rule, rule 0.', expect: 422,
        run: (c) => c.req('PATCH', `/r/${c.ns}/page`, { ct: PJ, headers: { 'If-Match': q(c.v.p1) }, body: [{ op: 'replace', path: '', value: { title: 'New' } }] }) },
      { t: 'Append: remove /title', why: 'The resulting document has no title, so rule 1 fails.', expect: 422,
        run: (c) => c.req('PATCH', `/r/${c.ns}/page`, { ct: PJ, headers: { 'If-Match': q(c.v.p1) }, body: [{ op: 'remove', path: '/title' }] }) },
      { t: 'Append: replace /title', why: 'A path-level change that keeps a string title passes both rules.', expect: 201,
        run: (c) => c.req('PATCH', `/r/${c.ns}/page`, { ct: PJ, headers: { 'If-Match': q(c.v.p1) }, body: [{ op: 'replace', path: '/title', value: 'Home (edited)' }] }) },
    ],
  },
  {
    id: 'd', title: 'Batch with delete + restore',
    desc: 'A batch applies several items atomically. An item may have several steps: here "delete" then a patch set that restores. A dry run reports the ids without writing.',
    steps: [
      { t: 'Create the namespace', why: 'Public.', expect: 201,
        run: (c) => c.req('PATCH', `/ns/${c.ns}`, { ct: PJ, headers: NEW, body: [add('', { read: 'public' })] }) },
      { t: 'Batch: create a, b and c', why: 'POST /ns/{ns}/batch. Each item has exactly one precondition; ifNoneMatch "*" is a create. One batch entry is logged.', expect: 201,
        run: async (c) => {
          const item = (n) => ({ resource: n, ifNoneMatch: '*', steps: [[add('', { name: n, n: 1 })]] });
          const r = await c.req('POST', `/ns/${c.ns}/batch`, { body: { items: [item('a'), item('b'), item('c')] } });
          c.v.ids = {}; ((r.json || {}).items || []).forEach((i) => { c.v.ids[i.resource] = i.ids[i.ids.length - 1]; });
          return r;
        } },
      { t: 'Dry run: delete a, delete+restore b, edit c', why: '?dry-run=1 runs the gate for every item and writes nothing. 200 with the ids a submit would produce.', expect: 200,
        run: (c) => c.req('POST', `/ns/${c.ns}/batch?dry-run=1`, { body: batch2(c) }) },
      { t: 'Submit the same batch', why: 'All items land in one atomic step: a is tombstoned, b gets a tombstone then a restoring revision (steps chain), c gets a new revision.', expect: 201,
        run: (c) => c.req('POST', `/ns/${c.ns}/batch`, { body: batch2(c) }) },
      { t: 'Read a (tombstoned)', why: 'GET on a tombstoned resource is 410 with { tombstone, last }.', expect: 410,
        run: (c) => { c.show(c.ns, 'a'); return c.req('GET', `/r/${c.ns}/a`); } },
      { t: 'Read b (deleted and restored)', why: 'Restore with [] brings back the last live document, so b reads as live again.', expect: 200,
        run: (c) => { c.show(c.ns, 'b'); return c.req('GET', `/r/${c.ns}/b`); } },
      { t: 'Batch with a stale precondition', why: 'The batch is all or nothing. Item 0 is fine, item 1 uses the id c had before the batch. The failure lists only the failing items: { code: "batch", items: [{ index, status, code }] }.', expect: 412,
        run: async (c) => {
          const b = (await c.req('GET', `/r/${c.ns}/b`, { auto: true })).etag();
          return c.req('POST', `/ns/${c.ns}/batch`, { body: { items: [
            { resource: 'b', ifMatch: b, steps: [[{ op: 'replace', path: '/n', value: 5 }]] },
            { resource: 'c', ifMatch: c.v.ids.c, steps: [[{ op: 'replace', path: '/n', value: 3 }]] }] } });
        } },
    ],
  },
  {
    id: 'e', title: 'Branch read-through, then first write',
    desc: 'A branch reads its base through as of the moment it was cut. Its first write to a resource takes the base revision as foreign parent; later base changes are never seen.',
    steps: [
      { t: 'Create the base namespace', why: 'Public.', expect: 201,
        run: (c) => c.req('PATCH', `/ns/${c.ns}`, { ct: PJ, headers: NEW, body: [add('', { read: 'public' })] }) },
      { t: 'Create "page" in the base', why: 'This is what the branch will read through.', expect: 201,
        run: async (c) => { c.show(c.ns, 'page'); const r = await c.req('PATCH', `/r/${c.ns}/page`, { ct: PJ, headers: NEW, body: [add('', { title: 'Base v1' })] }); c.v.p1 = r.etag(); return r; } },
      { t: 'Create the branch', why: 'POST /ns/{base}/branches with If-None-Match: *. "at" defaults to the base head. The branch entry is logged in the base.', expect: 201,
        run: (c) => { c.v.br = `${c.ns}-br`; return c.req('POST', `/ns/${c.ns}/branches`, { headers: NEW, body: { name: c.v.br } }); } },
      { t: 'Read "page" through the branch', why: 'The branch has no entries of its own for page, so it answers as the base did at "at": same revision id, served under the branch URL.', expect: 200,
        run: (c) => { c.show(c.v.br, 'page'); return c.req('GET', `/r/${c.v.br}/page`); } },
      { t: 'Change "page" in the base', why: 'The base moves on to a new revision.', expect: 201,
        run: async (c) => { const r = await c.req('PATCH', `/r/${c.ns}/page`, { ct: PJ, headers: { 'If-Match': q(c.v.p1) }, body: [{ op: 'replace', path: '/title', value: 'Base v2' }] }); c.v.p2 = r.etag(); return r; } },
      { t: 'Read "page" through the branch again', why: 'Still "Base v1": changes in the base after "at" are not seen through a branch.', expect: 200,
        run: (c) => c.req('GET', `/r/${c.v.br}/page`) },
      { t: 'First write in the branch', why: 'The precondition is checked against the base head as of "at" (p1, not the base head p2). That revision becomes the foreign parent.', expect: 201,
        run: async (c) => { const r = await c.req('PATCH', `/r/${c.v.br}/page`, { ct: PJ, headers: { 'If-Match': q(c.v.p1) }, body: [{ op: 'replace', path: '/title', value: 'Branch edit' }] }); c.v.b1 = r.etag(); return r; } },
      { t: 'History of the branch resource', why: 'The log crosses the foreign parent: the base revision and the branch revision both appear.', expect: 200,
        run: (c) => c.req('GET', `/r/${c.v.br}/page/rev/${c.v.b1}/log`) },
      { t: 'Base is untouched by the branch write', why: 'The base still reads "Base v2" on its own chain.', expect: 200,
        run: (c) => c.req('GET', `/r/${c.ns}/page`) },
    ],
  },
];

function batch2(c) {
  return { items: [
    { resource: 'a', ifMatch: c.v.ids.a, steps: ['delete'] },
    { resource: 'b', ifMatch: c.v.ids.b, steps: ['delete', []] },
    { resource: 'c', ifMatch: c.v.ids.c, steps: [[{ op: 'replace', path: '/n', value: 2 }]] },
  ] };
}

const X = { ex: null, ctx: null, i: 0, results: [], busy: false, stop: false };

function initExamples() {
  const menu = $('exMenu');
  menu.replaceChildren(...EXAMPLES.map((ex) => h('button', { role: 'menuitem', onclick: () => { closeMenu(); startExample(ex); } },
    h('b', {}, `(${ex.id}) ${ex.title}`), h('span', {}, ex.desc))));
  $('exBtn').onclick = (e) => { e.stopPropagation(); const open = menu.hidden; menu.hidden = !open; $('exBtn').setAttribute('aria-expanded', String(open)); };
  document.addEventListener('click', (e) => { if (!menu.contains(e.target)) closeMenu(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeMenu(); });
  function closeMenu() { menu.hidden = true; $('exBtn').setAttribute('aria-expanded', 'false'); }
}

function startExample(ex) {
  const ns = 'demo-' + rnd();
  X.ex = ex; X.i = 0; X.results = []; X.busy = false; X.stop = true;
  X.ctx = {
    ns, v: {}, label: '', showNs: null, showRes: null,
    show(n, r) { this.showNs = n; this.showRes = r; },
    req(method, path, o = {}) { return api(method, path, Object.assign({ label: this.label }, o)); },
  };
  renderExample();
  $('exPanel').scrollIntoView({ block: 'nearest' });
}

function renderExample() {
  const p = $('exPanel');
  if (!X.ex) { p.hidden = true; return; }
  p.hidden = false;
  const done = X.i >= X.ex.steps.length;
  const list = h('ol', {}, ...X.ex.steps.map((s, i) => {
    const r = X.results[i];
    return h('li', { class: i === X.i && !done ? 'cur' : '' },
      h('span', { class: 'n' }, i + 1),
      h('div', {}, h('b', {}, s.t), h('span', { class: 'why' }, s.why)),
      h('div', { class: 'res' }, r
        ? h('span', { class: 'pill ' + (r.ok ? 's2' : 's5') }, (r.ok ? '\u2713 ' : '\u2717 ') + (r.status == null ? 'ERR' : r.status))
        : (i === X.i && X.busy ? h('span', { class: 'muted' }, 'running\u2026') : h('span', { class: 'muted small' }, s.expect ? 'expect ' + s.expect : ''))));
  }));
  p.replaceChildren(
    h('header', {}, h('h2', {}, `Example (${X.ex.id}): ${X.ex.title}`), h('span', { class: 'grow' }),
      h('span', { class: 'muted small' }, 'namespace '), h('code', { class: 'mono' }, X.ctx.ns),
      h('button', { class: 'primary', disabled: X.busy || done, onclick: () => runExampleStep() }, done ? 'Done' : 'Next step'),
      h('button', { disabled: X.busy || done, onclick: () => runExampleAll() }, 'Run all'),
      h('button', { disabled: X.busy, onclick: () => startExample(X.ex) }, 'Restart (new namespace)'),
      h('button', { onclick: () => { X.stop = true; X.ex = null; renderExample(); } }, 'Close')),
    h('p', { class: 'note', style: 'margin:0' }, X.ex.desc + ' Every request appears in the inspector, tagged ' + `ex ${X.ex.id}\u00b7step.`),
    list);
}

async function runExampleStep() {
  if (X.busy || !X.ex || X.i >= X.ex.steps.length) return null;
  const step = X.ex.steps[X.i], c = X.ctx, idx = X.i;
  X.busy = true; renderExample();
  c.label = `ex ${X.ex.id}\u00b7${idx + 1}`;
  insp.label = c.label;
  let r = null;
  try { r = await step.run(c); }
  catch (err) { toast('Step failed: ' + err.message); }
  insp.label = '';
  const exp = [].concat(step.expect);
  X.results[idx] = { status: r ? r.status : null, ok: !!r && exp.includes(r.status) };
  X.i++; X.busy = false;
  // reflect the new state in the views
  try {
    if (c.showNs && S.ns !== c.showNs) { await selectNS(c.showNs); }
    else if (!c.showNs && S.ns !== c.ns) await selectNS(c.ns);
    else await refreshNS();
    if (c.showRes && S.res !== c.showRes) await selectRes(c.showRes);
    else if (S.res) await refreshRes();
  } catch (_) { /* views are best effort */ }
  renderExample();
  return X.results[idx];
}
async function runExampleAll() {
  X.stop = false;
  const ex = X.ex;
  while (X.ex === ex && !X.stop && X.i < ex.steps.length) {
    const res = await runExampleStep();
    if (!res || !res.ok) break;
    await sleep(350);
  }
}

/* ------------------------------------------------------------------ *
 * tabs and wiring
 * ------------------------------------------------------------------ */
function showTab(name) {
  document.querySelectorAll('.tab').forEach((t) => t.setAttribute('aria-selected', String(t.dataset.tab === name)));
  document.querySelectorAll('[role=tabpanel]').forEach((p) => { p.hidden = p.id !== 'tab-' + name; });
  store.set('pl.tab', name);
}

function bindJSONHints() {
  document.querySelectorAll('textarea[data-json]').forEach((ta) => {
    const hint = h('div', { class: 'hint' });
    ta.after(hint);
    const check = () => {
      const t = ta.value.trim();
      if (!t) { hint.textContent = ''; hint.className = 'hint'; return; }
      const p = tryParse(t);
      hint.textContent = p.ok ? 'valid JSON' : 'invalid JSON: ' + p.err;
      hint.className = 'hint ' + (p.ok ? 'good' : 'bad');
    };
    ta.addEventListener('input', check); check();
  });
}

function bindInspector() {
  $('inspToggle').onclick = () => { document.body.classList.toggle('insp-off'); store.set('pl.inspOff', document.body.classList.contains('insp-off')); };
  $('inspFloat').onclick = () => { document.body.classList.remove('insp-off'); store.set('pl.inspOff', false); };
  $('inspClear').onclick = () => { insp.entries.splice(0).forEach((e) => e.node && e.node.remove()); $('inspCount').textContent = '0'; updateHidden(); };
  let expanded = false;
  $('inspExpand').onclick = () => { expanded = !expanded; insp.entries.forEach((e) => { if (e.node) e.node.open = expanded; }); $('inspExpand').textContent = expanded ? 'Collapse' : 'Expand'; };
  document.querySelectorAll('.seg button').forEach((b) => {
    b.onclick = () => {
      insp.filter = b.dataset.f;
      document.querySelectorAll('.seg button').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
      insp.entries.forEach(applyFilter);
    };
  });
  $('inspAuto').onchange = (e) => { insp.showAuto = e.target.checked; store.set('pl.showAuto', insp.showAuto); insp.entries.forEach(applyFilter); updateHidden(); };
  insp.showAuto = !!store.get('pl.showAuto', false); $('inspAuto').checked = insp.showAuto;
  $('inspQ').oninput = (e) => { insp.q = e.target.value.trim().toLowerCase(); insp.entries.forEach(applyFilter); };
  $('inspList').append(h('div', { class: 'insp-empty' }, 'Requests the playground makes will show up here.'));
  if (store.get('pl.inspOff', false)) document.body.classList.add('insp-off');
}

function init() {
  loadKnown();
  bindInspector();
  bindJSONHints();
  initConn();
  initExamples();

  document.querySelectorAll('.tab').forEach((t) => { t.onclick = () => showTab(t.dataset.tab); });

  // namespace selection
  $('nsSel').onchange = (e) => asUser(() => selectNS(e.target.value));
  const addNs = () => { const n = $('nsAdd').value.trim(); if (!n) return; $('nsAdd').value = ''; asUser(() => selectNS(n)); };
  $('nsAddBtn').onclick = addNs;
  $('nsAdd').onkeydown = (e) => { if (e.key === 'Enter') addNs(); };
  $('nsForget').onclick = () => {
    if (!S.ns) return;
    known = known.filter((n) => n !== S.ns); store.set('pl.known', known);
    asUser(() => selectNS(''));
  };
  $('resLoad').onclick = () => asUser(() => selectRes($('resName').value));
  $('resName').onkeydown = (e) => { if (e.key === 'Enter') asUser(() => selectRes($('resName').value)); };
  $('resName').onchange = () => { if ($('resName').value.trim() !== S.res) asUser(() => selectRes($('resName').value)); };

  // namespace tab
  $('nsRefresh').onclick = () => asUser(refreshNS);
  $('nsCreate').onclick = createNamespace;
  $('nsApply').onclick = () => applyConfig($('nsPatch').value);
  $('nsFreeze').onclick = () => freeze(true);
  $('nsUnfreeze').onclick = () => freeze(false);
  $('nsIfMatch').oninput = () => { S.cfgDirty = true; };
  $('nsUseCfg').onclick = () => { S.cfgDirty = false; $('nsIfMatch').value = S.config || ''; };
  $('headsMore').onclick = headsMore;
  $('brCreate').onclick = createBranch;
  $('brUseHead').onclick = () => { $('brAt').value = S.nsHead || ''; };
  $('nsPurge').onclick = purgeNamespace;
  $('nsPurgeUse').onclick = () => { delete $('nsPurgeIm').dataset.dirty; $('nsPurgeIm').value = S.nsHead || ''; };
  $('nsPurgeIm').oninput = () => { $('nsPurgeIm').dataset.dirty = '1'; };
  buildChips($('nsTpl'), 'insert:', [
    ['read: grant', () => ({ op: 'replace', path: '/read', value: 'grant' })],
    ['read: public', () => ({ op: 'replace', path: '/read', value: 'public' })],
    ['rules = [\u2026]', () => add('/rules', [{ if: [{ op: 'test', path: '/action', value: 'append' }], then: [{ not: { op: 'writes', covers: '' } }] }])],
    ['add rule', () => add('/rules/-', { if: [{ op: 'test', path: '/action', schema: { enum: ['create', 'append', 'restore'] } }], then: [{ op: 'test', path: '/doc/title', schema: { type: 'string' } }] })],
    ['limits', () => add('/limits', { itemsPerBatch: 10 })],
    ['successor', () => add('/successor', 'other-namespace')],
    ['frozen: true', () => add('/frozen', true)],
    ['frozen: false', () => add('/frozen', false)],
  ], 'nsPatch');

  // resource tab
  $('resRefresh').onclick = () => asUser(refreshRes);
  $('btnCreate').onclick = () => writeRes('create');
  $('btnAppend').onclick = () => writeRes('append');
  $('btnDelete').onclick = () => writeRes('delete');
  $('btnRestore').onclick = () => writeRes('restore');
  $('btnPurge').onclick = purgeRes;
  $('btnPrune').onclick = pruneRes;
  $('ifMatch').oninput = () => { S.ifDirty = true; };
  $('ifUseHead').onclick = () => { S.ifDirty = false; $('ifMatch').value = (S.resState && S.resState.head) || ''; };
  buildChips($('patchTpl'), 'insert:', TEMPLATES, 'patch');

  // history
  $('histRefresh').onclick = () => asUser(loadHistory);

  // batch
  $('batchBody').value = batchExample();
  $('batchBody').dispatchEvent(new Event('input'));
  $('batchDry').onclick = () => runBatch(true);
  $('batchGo').onclick = () => runBatch(false);
  $('batchExample').onclick = () => { $('batchBody').value = batchExample(); $('batchBody').dispatchEvent(new Event('input')); };
  $('batchTpl').replaceChildren(h('span', {}, 'add:'), ...[
    ['append item', 'append'], ['delete item', 'delete'], ['delete + restore item', 'delrestore'],
    ['config change', 'config'], ['source', 'source'],
  ].map(([label, kind]) => h('button', { type: 'button', onclick: () => batchInsert(kind) }, label)));

  // live
  $('liveNs').onchange = () => ($('liveNs').checked ? startStream('ns') : stopStream('ns'));
  $('liveRes').onchange = () => ($('liveRes').checked ? startStream('res') : stopStream('res'));
  $('feedClear').onclick = () => { $('feed').replaceChildren(h('li', { class: 'muted' }, 'No events yet.')); $('feedCount').textContent = ''; };
  updateLiveWarn();

  // restore session
  showTab(store.get('pl.tab', 'ns'));
  renderNsSelect(); renderNsAll(); renderResAll(); renderHistory(); updateLiveUrls();
  const ns = store.get('pl.ns', ''), res = store.get('pl.res', '');
  if (ns) { S.res = res; asUser(() => selectNS(ns, { keepRes: true })); $('resName').value = res; }
}

document.addEventListener('DOMContentLoaded', init);
})();
