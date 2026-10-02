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
  nsLevel: '', nsRaw: '', nsSeal: null, nsLogSeal: null,
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
  else if (e.reqNote) parts.push('--data-binary @FILE');
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
    e.reqBody !== undefined ? h('div', { style: 'margin-top:4px' }, jsonPre(pretty(e.reqBody))) : null,
    e.reqNote ? h('div', { class: 'muted small' }, e.reqNote) : null));

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
    } else if (e.binNote) res.append(h('div', { class: 'muted small' }, e.binNote));
    else if (!e.sse) res.append(h('div', { class: 'muted small' }, '(empty body)'));
    if (e.dec) res.append(decView(e.dec));
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

/* api(method, path, {headers, body, ct, auto, label, stream, raw, binary, cache}) -> Response wrapper.
 * raw sends body (bytes) as is, binary keeps a 2xx body as bytes (wrapper .bin) instead of text. cache is the
 * fetch cache mode, 'no-store' unless given (tree listings use the HTTP cache, see treeGet). */
async function api(method, path, o = {}) {
  const headers = authHeaders();
  for (const [k, v] of Object.entries(o.headers || {})) if (v != null && v !== '') headers[k] = v;
  let body = o.body;
  if (body !== undefined && typeof body !== 'string' && !o.raw) body = JSON.stringify(body);
  if (body !== undefined && !headers['Content-Type']) headers['Content-Type'] = o.ct || 'application/json';
  const e = newEntry({ method, path, reqHeaders: headers, reqBody: o.raw ? undefined : body, reqNote: o.raw ? `(${body.length} bytes of binary data, not shown)` : '', auto: !!o.auto && !insp.manual, label: o.label !== undefined ? o.label : insp.label });
  const t0 = performance.now();
  const ctl = new AbortController();
  try {
    const res = await fetch(path, { method, headers, body, cache: o.cache || 'no-store', redirect: 'follow', credentials: 'same-origin', signal: ctl.signal });
    e.status = res.status; e.statusText = res.statusText; e.resHeaders = res.headers;
    e.redirected = res.redirected;
    if (res.redirected) { const u = new URL(res.url); e.finalPath = u.pathname + u.search; }
    else e.finalPath = path;
    if (o.stream && res.ok) { ctl.abort(); e.resBody = '(event stream opened, then closed by the probe)'; }
    else if (o.binary && res.ok) {
      e.bin = new Uint8Array(await res.arrayBuffer()); e.resBody = '';
      e.binNote = `(${e.bin.length} bytes of ${(res.headers.get('Content-Type') || 'unknown type').split(';')[0]}, not shown)`;
    } else e.resBody = await res.text();
    try { e.json = e.resBody ? JSON.parse(e.resBody) : null; } catch (_) { e.json = null; }
  } catch (err) {
    e.neterr = err && err.message ? err.message : String(err);
  }
  e.ms = performance.now() - t0;
  noteWrite(method, path, e);
  renderEntry(e);
  return wrap(e);
}

/* WRITES: the last write this page made to each namespace, by X-Namespace-Revision. The Search tab passes it as
 * ?min= (§A.5) so the index has applied it before it answers, and the Catalog tab for the catalog and the
 * namespaces it trusts (§B.5 fresh listings after a write). */
const WRITES = new Map(); // ns -> { id, at: Date }
function noteWrite(method, path, e) {
  if (method === 'GET' || method === 'HEAD' || !(e.status >= 200 && e.status < 300) || !e.resHeaders || /[?&]dry-run=/.test(path)) return;
  const id = e.resHeaders.get('X-Namespace-Revision');
  const m = /^\/(?:r|ns)\/([^/?]+)/.exec(path);
  if (id && m && ID_RE.test(id)) { WRITES.set(m[1], { id, at: new Date() }); if (document.getElementById('srRywInfo')) renderSrRyw(); }
}
function wrap(e) {
  return {
    entry: e, status: e.status, ok: e.status >= 200 && e.status < 300, json: e.json, text: e.resBody,
    finalPath: e.finalPath, redirected: e.redirected, neterr: e.neterr, bin: e.bin,
    jose: !!(e.resHeaders && /^application\/jose\b/i.test(e.resHeaders.get('Content-Type') || '')),
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
    resState: null, hist: [], selRev: '', cfgDirty: false, ifDirty: false, nsLevel: '', nsRaw: '', nsSeal: null, nsLogSeal: null });
}

async function selectNS(name, o = {}) {
  name = (name || '').trim();
  S.ns = name; if (!o.keepRes) S.res = '';
  resetNsState(); syncSealBoxes();
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
    S.nsRaw = r.jose ? r.text : '';
    if (r.jose) {
      // A sealed namespace (E2) serves its document as a JWE bound to { ns, id: ns_id, kind: "config" }.
      const d = await decrypted(r, ns, '', { ns, id: S.nsHead, kind: 'config' });
      if (ns !== S.ns) return;
      S.nsDoc = d.value; S.nsSeal = d;
    } else { S.nsDoc = r.json; S.nsSeal = null; }
    S.nsLevel = r.jose ? 'sealed' : ((S.nsDoc && S.nsDoc.encryption && S.nsDoc.encryption.level) || '');
    nsInfoCache.set(ns, { level: S.nsLevel, doc: S.nsDoc });
    syncSealBoxes();
    if (S.nsLevel === 'e2e') loadKeyring(); else if (KR.ns !== ns) { KR.ns = ns; KR.doc = null; renderKeyring(); }
  } else {
    S.nsErr = r; S.nsDoc = null; S.nsHead = ''; S.config = '';
    // Fall back to the log, which 302s to the range and reveals the head in its final URL.
    const l = await api('GET', `/ns/${ns}/log`, { auto: true });
    if (ns !== S.ns) return;
    if (l.status === 200) {
      S.nsHead = (/\/rev\/([^/]+)\/log/.exec(l.finalPath) || [])[1] || '';
      S.nsLog = Array.isArray(l.json) ? l.json : (l.jose ? (await nsLogOpen(ns, l, S.nsHead)) || [] : []);
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
  else if (lg.status === 200 && lg.jose) { const v = await nsLogOpen(ns, lg, head); if (ns !== S.ns) return; S.nsLog = v || []; }
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
  if (S.nsLevel) {
    const enc = d.encryption || {};
    kv.append(h('dt', {}, 'encryption'), h('dd', {}, `${S.nsLevel}` + (enc.epoch ? `, epoch ${enc.epoch}` : '') + (enc.pad ? ', padded' : ''),
      S.nsSeal ? (S.nsSeal.error ? h('span', { class: 'badge err', title: S.nsSeal.error }, 'document not decrypted') : h('span', { class: 'badge ok', title: 'kid ' + S.nsSeal.kid }, 'decrypted in this browser')) : null,
      S.nsLevel === 'e2e' ? h('button', { class: 'link small', onclick: () => showTab('keys') }, 'keyring →') : null));
  }
  box.className = '';
  box.replaceChildren(
    h('div', { class: 'state-line' }, h('b', {}, S.ns),
      d.read ? h('span', { class: 'badge ' + (d.read === 'public' ? 'info' : '') }, 'read: ' + d.read) : null,
      d.frozen ? h('span', { class: 'badge warn' }, 'frozen') : null,
      d.base ? h('span', { class: 'badge' }, 'branch') : null,
      S.nsLevel === 'sealed' || S.nsLevel === 'e2e' ? h('span', { class: 'badge tomb' }, S.nsLevel === 'e2e' ? 'E3 end-to-end' : 'E2 sealed') : null),
    kv,
    S.nsSeal && S.nsSeal.error ? h('div', { class: 'note' }, 'The namespace document is sealed (application/jose). ' + S.nsSeal.error + ' — see the Keys tab.') : '');
}

function renderNsDoc() {
  setJSON($('nsDoc'), S.nsDoc != null ? S.nsDoc : (S.nsRaw || null));
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
  if (r.status === 200) {
    st = { kind: 'live', head: r.hdr('X-Revision') || r.etag() || foldTarget(r.finalPath), via: r.finalPath };
    Object.assign(st, await readDoc(ns, res, st.head, r));
  } else if (r.status === 410 && r.json && r.json.tombstone) st = { kind: 'tomb', head: r.json.tombstone, last: r.json.last };
  else if (r.status === 410) st = { kind: 'purged' };
  else if (r.status === 404) st = { kind: 'missing' };
  else st = { kind: 'error', status: r.status, code: r.json && r.json.code };
  if (ns !== S.ns || res !== S.res) return;
  S.resState = st;
  if (st.kind === 'tomb' && st.last) {
    const lr = await api('GET', rpath(`/rev/${st.last}`), { auto: true });
    if (ns !== S.ns || res !== S.res) return;
    if (lr.status === 200) { const d = await readDoc(ns, res, st.last, lr); st.lastDoc = d.doc; st.seal = d.seal; st.fold = d.fold; st.foldErr = d.foldErr; }
  }
  renderResAll();
  if (!S.ifDirty) $('ifMatch').value = st.head || '';
  await loadHistory();
  renderHeads();
}

function renderResAll() {
  const box = $('resState'), st = S.resState;
  const pre = $('resDoc');
  renderResSeal(st); renderBlobs(null);
  if (!S.ns || !S.res) { box.className = 'muted'; box.textContent = 'Pick a resource from the heads table, or type a name above.'; setJSON(pre, null); return; }
  if (!st) { box.className = 'muted'; box.textContent = `${S.res} \u2014 loading\u2026`; setJSON(pre, null); return; }
  box.className = '';
  const line = h('div', { class: 'state-line' }, h('b', { class: 'mono' }, `${S.ns}/${S.res}`));
  switch (st.kind) {
    case 'live':
      line.append(h('span', { class: 'badge live' }, 'live'), h('span', { class: 'muted' }, 'head'), idEl(st.head));
      setJSON(pre, st.doc != null ? st.doc : st.raw); renderBlobs(st.doc); break;
    case 'tomb':
      line.append(h('span', { class: 'badge tomb' }, 'tombstoned'), h('span', { class: 'muted' }, 'tombstone'), idEl(st.head));
      if (st.last) line.append(h('span', { class: 'muted' }, 'last'), idEl(st.last));
      box.replaceChildren(line, h('div', { class: 'note' }, 'GET answered 410. Restore with If-Match set to the tombstone; the document below is the last live one.'));
      setJSON(pre, st.lastDoc != null ? st.lastDoc : st.raw); renderBlobs(st.lastDoc); return;
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
  let patch = $('patch').value;
  const usesPatch = kind === 'create' || kind === 'append' || (kind === 'restore' && $('restoreEditor').checked);
  if (usesPatch && $('sealE2E').checked && S.res !== 'keyring') return writeSealed(kind, patch);
  if (usesPatch && $('addNonce').checked) {
    const p = tryParse(patch);
    if (!p.ok || !Array.isArray(p.v)) return toast('The patch set is not a JSON array');
    patch = fmtPatch(withNonce(p.v));
  }
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
  let hist = r.status === 200 && Array.isArray(r.json) ? r.json : [];
  S.histNote = '';
  if (hist.length && typeof hist[0] === 'string') {
    // E2: an array of per-entry JWEs under the resource's key K_r (§E.2.2).
    hist = await openEntries(ns, res, hist, st.head, r);
    S.histNote = 'Entries were sealed (application/jose); decrypted in this browser.';
  } else if (S.nsLevel === 'e2e' && res !== 'keyring' && hist.length) {
    // E3: plain entries whose patch sets are sealed; fold them here to flag bad revisions (§E.3.2).
    const since = new URLSearchParams((r.finalPath || '').split('?')[1] || '').get('since') || '';
    try { hist = (await foldLog(ns, res, st.head, since, hist)).entries; S.histNote = 'Sealed patch sets opened and folded in this browser.'; }
    catch (err) { S.histNote = 'Could not fold: ' + err.message; }
  }
  if (ns !== S.ns || res !== S.res) return;
  S.hist = hist;
  if (r.status !== 200) S.histErr = r; else S.histErr = null;
  renderHistory();
}

function opsSummary(e) {
  if (e.kind === 'tombstone') return 'tombstone (deleted)';
  if (e.kind === 'snapshot') return 'prune snapshot (sealed document)';
  if (e._err) return 'sealed entry: ' + e._err;
  const ops = (p) => p.map((x) => `${x.op} ${x.path === '' ? '(root)' : x.path}`).join(', ') || '(no ops)';
  if (PLSeal.sealedJWE(e.patches)) return e._plain ? 'sealed: ' + ops(e._plain) : 'sealed patch set' + (e._flag ? '' : ' (not opened)');
  return ops(e.patches || []);
}

function renderHistory() {
  const ul = $('timeline');
  $('histMeta').textContent = S.res ? `${S.ns}/${S.res}` + (S.histNote ? ' · ' + S.histNote : '') : '';
  if (!S.hist.length) {
    ul.replaceChildren(h('li', { class: 'muted', style: 'cursor:default' }, S.res ? (S.histErr ? `Log answered ${S.histErr.status} ${(S.histErr.json || {}).code || ''}` : 'No history loaded.') : 'Select a resource.'));
    return;
  }
  ul.replaceChildren(...[...S.hist].reverse().map((e) => {
    const tomb = e.kind === 'tombstone';
    const li = h('li', { class: (tomb ? 'tomb ' : '') + (e.id === S.selRev ? 'sel' : ''), tabindex: 0, role: 'button' },
      h('div', { class: 'top1' }, kindBadge(e.kind), idEl(e.id), h('span', { class: 'muted' }, e.author || ''), h('span', { class: 'muted mono', title: e.created }, tsFmt(e.created)),
        e._sealed ? h('span', { class: 'badge tomb', title: 'kid ' + e._sealed }, 'sealed') : null,
        e._flag ? h('span', { class: 'badge err', title: e._flag }, 'flagged') : null),
      h('div', { class: 'ops' }, opsSummary(e)),
      e._flag ? h('div', { class: 'ops', style: 'color:var(--err)' }, e._flag + (e.author ? ` (author ${e.author} is accountable)` : '')) : null,
      e._note ? h('div', { class: 'ops muted' }, e._note) : null);
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
  if (entry._flag) parts.push(h('div', { class: 'errbox' }, h('span', { class: 'code' }, 'flagged'), '  ' + entry._flag + '. The revision is left out of the fold; its author is accountable (§E.3.2).'));
  if (entry._plain) parts.push(h('h3', {}, 'Patches (decrypted in this browser)'), jsonPre(entry._plain), h('details', {}, h('summary', { class: 'muted small' }, 'sealed patch set as stored (ids are over this ciphertext)'), jsonPre(entry.patches)));
  else if (entry.patches) parts.push(h('h3', {}, 'Patches'), jsonPre(entry.patches));
  if (entry._raw) parts.push(h('details', {}, h('summary', { class: 'muted small' }, 'log entry as served (JWE)'), jsonPre(entry._raw)));
  if (r.status === 200) {
    const d = await readDoc(S.ns, S.res, id, r);
    if (S.selRev !== id) return;
    if (d.fold) parts.push(h('h3', { style: 'margin-top:8px' }, 'Document at this revision (folded in this browser)'), foldSummary(d.fold), jsonPre(d.doc), blobsPanel(d.doc));
    else if (d.foldErr) parts.push(h('div', { class: 'errbox' }, h('span', { class: 'code' }, 'fold failed'), '  ' + d.foldErr));
    else if (d.seal) parts.push(h('h3', { style: 'margin-top:8px' }, 'Document at this revision'), sealSummary(d.seal), d.doc != null ? jsonPre(d.doc) : jsonPre(r.text), blobsPanel(d.doc));
    else parts.push(h('h3', { style: 'margin-top:8px' }, 'Document at this revision'), jsonPre(r.text ? pretty(r.text) : ''), blobsPanel(d.doc));
  } else if (r.status === 410 && entry.kind === 'tombstone') parts.push(h('p', { class: 'note' }, '410: a tombstone id has no document; earlier revisions stay readable.'));
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
 * encryption (Addendum E): keys, sealed responses, e2e folding
 * ------------------------------------------------------------------ */
const Z = PLSeal;
const KEYS = { epoch: new Map(), res: new Map(), from: new Map(), pending: new Map() };
const nsInfoCache = new Map(); // ns -> { level, doc }
let ID = null; // identity { d, x } (base64url X25519 private scalar and public key)

function loadIdentity() {
  const v = store.get('pl.identity', null);
  ID = v && typeof v.d === 'string' && typeof v.x === 'string' ? v : null;
}
function saveIdentity(v) {
  ID = v;
  try { if (v) localStorage.setItem('pl.identity', JSON.stringify(v)); else localStorage.removeItem('pl.identity'); } catch (_) { toast('localStorage is unavailable: the identity lasts until reload'); }
  renderIdentity(); renderKeyring();
}

function keyFrom(kid, resource, from) { KEYS.from.set(kid + '\n' + (resource || ''), from); renderKeysHeld(); }
function holdEpoch(kid, key, from) { KEYS.epoch.set(kid, key); keyFrom(kid, '', from); }
function holdRes(kid, resource, key, from) { KEYS.res.set(kid + '\n' + resource, key); keyFrom(kid, resource, from); }

/* nsInfo returns a namespace's encryption level and (plaintext or decrypted) document. */
async function nsInfo(ns) {
  if (nsInfoCache.has(ns)) return nsInfoCache.get(ns);
  const r = await api('GET', `/ns/${ns}`, { auto: true });
  let info = { level: '', doc: null };
  if (r.status === 200 && r.jose) info = { level: 'sealed', doc: null };
  else if (r.status === 200) info = { level: (r.json && r.json.encryption && r.json.encryption.level) || '', doc: r.json };
  nsInfoCache.set(ns, info);
  return info;
}

/* takeKeys stores the entries of a POST /ns/{ns}/keys answer: raw keys, or keys wrapped to the grant's enc. */
async function takeKeys(arr) {
  let n = 0;
  for (const e of arr || []) {
    if (!e || typeof e.kid !== 'string') continue;
    let key, from = 'POST /keys (raw)';
    if (typeof e.key === 'string') key = Z.unb64u(e.key);
    else if (typeof e.wrapped === 'string') {
      if (e.suite && e.suite !== Z.SUITE) continue;
      if (!ID) throw new Error('the keys are wrapped to the grant\'s enc: import that identity in the Keys tab');
      key = await Z.unwrapKey(ID, e.kid, e.resource || '', Z.unb64u(e.wrapped));
      from = 'POST /keys (HPKE-wrapped)';
    } else continue;
    if (key.length !== 32) continue;
    if (e.resource) holdRes(e.kid, e.resource, key, from); else holdEpoch(e.kid, key, from);
    n++;
  }
  return n;
}

/* keyringKey unwraps an e2e epoch key from the namespace's keyring with this identity (§E.3.2). */
async function keyringKey(ns, epoch) {
  if (!ID) throw new Error('no identity: generate or import one in the Keys tab');
  const r = await api('GET', `/r/${ns}/keyring`, { auto: true, label: 'keyring' });
  if (r.status !== 200 || !r.json) throw new Error(`no keyring in ${ns} (GET answered ${r.status})`);
  const kr = Z.parseKeyring(r.json);
  const key = await Z.keyringEpochKey(kr, ID, epoch);
  holdEpoch(Z.kid(ns, epoch), key, 'keyring (HPKE-wrapped)');
  return key;
}

async function fetchKeyFor(kid, resource) {
  const { ns, epoch } = Z.parseKid(kid);
  const info = await nsInfo(ns);
  const bearer = !!$('bearer').value.trim();
  if (info.level !== 'e2e' || bearer) {
    const body = { epochs: [epoch] };
    if (resource && info.level !== 'e2e') body.resources = [resource];
    const r = await api('POST', `/ns/${ns}/keys`, { body, auto: true, label: 'keys' });
    if (r.ok && r.json) await takeKeys(r.json.keys);
    if (KEYS.epoch.has(kid) || (resource && KEYS.res.has(kid + '\n' + resource))) return;
    if (info.level !== 'e2e') throw new Error(`POST /ns/${ns}/keys gave no key for ${kid}${resource ? ' / ' + resource : ''} (HTTP ${r.status}${r.json && r.json.code ? ' ' + r.json.code : ''})`);
  }
  await keyringKey(ns, epoch);
}

/* contentKey returns K_e (resource "") or K_r for kid, fetching it once if needed. */
async function contentKey(kid, resource) {
  const rk = kid + '\n' + (resource || '');
  if (resource && KEYS.res.has(rk)) return KEYS.res.get(rk);
  if (!KEYS.epoch.has(kid)) {
    if (!KEYS.pending.has(rk)) KEYS.pending.set(rk, fetchKeyFor(kid, resource).finally(() => KEYS.pending.delete(rk)));
    await KEYS.pending.get(rk);
    if (resource && KEYS.res.has(rk)) return KEYS.res.get(rk);
  }
  const ke = KEYS.epoch.get(kid);
  if (!ke) throw new Error('no key for ' + kid);
  if (!resource) return ke;
  const kr = await Z.resourceKey(ke, Z.parseKid(kid).ns, resource);
  holdRes(kid, resource, kr, 'derived from ' + kid);
  return kr;
}

/* openSealed decrypts a JWE of namespace ns after checking its kid and pl against what was asked for. */
async function openSealed(ns, jwe, resource, wantPL) {
  const { header } = Z.parseJWE(jwe);
  const k = Z.parseKid(header.kid);
  const want = typeof wantPL === 'function' ? wantPL(header) : wantPL;
  const diff = Z.plDiff(header.pl, want);
  const checks = [
    { ok: !ns || k.ns === ns, what: `kid ${header.kid} names namespace ${k.ns}` + (ns && k.ns !== ns ? `, not ${ns}` : '') },
    { ok: !diff.length, what: diff.length ? `pl differs from the request in ${diff.join(', ')}: got ${Z.canonical(header.pl)}, want ${Z.canonical(want)}` : `pl ${Z.canonical(header.pl)} matches the request` },
  ];
  if (checks.some((c) => !c.ok)) throw Object.assign(new Error(checks.filter((c) => !c.ok).map((c) => c.what).join('; ')), { checks, header });
  const key = await contentKey(header.kid, resource);
  const o = await Z.openJWE(jwe, key);
  checks.push({ ok: true, what: `decrypted with ${resource ? 'K_r(' + k.ns + ', ' + resource + ')' : 'K_e'} of ${header.kid}` + (header.zip ? ', inflated' : '') + (/ +$/.test(o.text) ? ', padded' : '') });
  let value = o.text;
  try { value = JSON.parse(o.text); } catch (_) { /* not JSON */ }
  return { header, kid: header.kid, text: o.text, value, checks };
}

/* decrypted opens a jose response and attaches the result to its inspector entry. */
async function decrypted(r, ns, resource, wantPL) {
  if (!r.jose) return { value: r.json };
  try {
    const d = await openSealed(ns, r.text.trim(), resource, wantPL);
    r.entry.dec = d; renderEntry(r.entry);
    return d;
  } catch (err) {
    r.entry.dec = { error: err.message, checks: err.checks, header: err.header }; renderEntry(r.entry);
    return { value: null, error: err.message, checks: err.checks };
  }
}

function checkList(checks) {
  return h('ul', { class: 'checks' }, ...(checks || []).map((c) => h('li', { class: c.ok ? 'ok' : 'bad' }, (c.ok ? '✓ ' : '✗ ') + c.what)));
}
function decView(d) {
  return h('div', { class: 'dec' }, h('h3', {}, d.error ? 'Not decrypted' : 'Decrypted in this browser'),
    d.header ? h('div', { class: 'mono small' }, 'protected header ' + JSON.stringify(d.header)) : null,
    checkList(d.checks), d.error ? h('div', { class: 'errline' }, d.error) : jsonPre(typeof d.value === 'string' ? d.value : JSON.stringify(d.value, null, 2)));
}
function sealSummary(d) {
  return h('div', { class: 'seal-box' + (d.error ? ' bad' : '') },
    h('div', { class: 'state-line' }, h('span', { class: 'badge tomb' }, 'application/jose'), d.error ? h('span', { class: 'badge err' }, 'not decrypted') : h('span', { class: 'badge ok' }, 'decrypted'), d.kid ? h('span', { class: 'mono small' }, 'kid ' + d.kid) : null),
    checkList(d.checks), d.error ? h('div', { class: 'errline' }, d.error) : null);
}

async function nsLogOpen(ns, r, head) {
  const since = new URLSearchParams((r.finalPath || '').split('?')[1] || '').get('since') || '';
  const d = await decrypted(r, ns, '', { ns, range: [since, head] });
  S.nsLogSeal = d;
  return Array.isArray(d.value) ? d.value : null;
}

/* openEntries decrypts an E2 resource log (per-entry JWEs under K_r, pl {ns, name, id, kind}) and checks the chain. */
async function openEntries(ns, name, arr, last, r) {
  const since = new URLSearchParams((r.finalPath || '').split('?')[1] || '').get('since') || '';
  const out = [];
  let prev = since, err = '';
  for (const jwe of arr) {
    let hdr = null;
    try { hdr = Z.parseJWE(jwe).header; } catch (_) { /* reported below */ }
    const pl = (hdr && hdr.pl) || {};
    try {
      if (pl.kind !== 'rev' && pl.kind !== 'tombstone') throw new Error('entry of kind ' + JSON.stringify(pl.kind));
      const d = await openSealed(ns, jwe, name, { ns, name, id: pl.id, kind: pl.kind });
      const e = d.value;
      if (!e || e.id !== pl.id || e.kind !== pl.kind) throw new Error('the entry does not match its binding');
      if ((out.length || since) && (e.parent || '') !== prev) err = err || `the log does not chain at ${short(e.id)}`;
      prev = e.id;
      out.push(Object.assign({}, e, { _sealed: d.kid, _raw: jwe }));
    } catch (x) {
      out.push({ id: pl.id || '?', kind: pl.kind || '?', _err: x.message, _raw: jwe });
      prev = pl.id || prev;
    }
  }
  if (!err && last && prev !== last) err = `the log ends at ${short(prev)}, not ${short(last)}`;
  if (err) out.forEach((e) => { e._flag = e._flag || err; });
  return out;
}

/* ---- e2e (E3) folding, as internal/client/e2e.go ---- */
function foldTarget(path) { return (/\/rev\/(1[a-z2-7]{32})\/log(?:\?|$)/.exec(path || '') || [])[1] || ''; }

/* readDoc turns a 200 answer for a document into { doc, seal?, fold?, foldErr?, raw? }. */
async function readDoc(ns, name, id, r) {
  if (foldTarget(r.finalPath) && Array.isArray(r.json)) {
    const since = new URLSearchParams(r.finalPath.split('?')[1] || '').get('since') || '';
    try { const f = await foldLog(ns, name, id, since, r.json); return { doc: f.value, fold: f }; }
    catch (err) { return { doc: null, foldErr: err.message, raw: r.text }; }
  }
  if (r.jose) { const d = await decrypted(r, ns, name, { ns, name, id, kind: 'doc' }); return { doc: d.value, seal: d, raw: r.text }; }
  return { doc: r.json };
}

/* nsChainOK: a branch reads its bases' ciphertext, sealed under their keys (§F.8). */
async function nsChainOK(ns, kns) {
  for (let cur = ns, i = 0; cur && i < 16; i++) {
    if (cur === kns) return true;
    const info = await nsInfo(cur);
    cur = info.doc && info.doc.base && info.doc.base.ns;
  }
  return false;
}

const schemaCache = new Map();
/* validationInstance is what §6.2 step 5 validates: doc without its top-level
   $schema, and without a top-level $nonce of the fresh-nonce form. */
function validationInstance(doc) {
  const out = { ...doc };
  delete out.$schema;
  if (typeof out.$nonce === 'string' && /^[a-z2-7]{26}$/.test(out.$nonce)) delete out.$nonce;
  return out;
}

/* validateDoc checks doc against its $schema with the subset validator (§E.3.2: validation moves to clients). */
async function validateDoc(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc) || typeof doc.$schema !== 'string') return { errors: [] };
  const m = /^\/r\/([a-z0-9][a-z0-9_-]*)\/([^/]+)\/rev\/(1[a-z2-7]{32})$/.exec(doc.$schema);
  if (!m) return { errors: [], note: '$schema ' + doc.$schema + ' is not a revision path; not validated here' };
  let schema = schemaCache.get(doc.$schema);
  if (schema === undefined) {
    const r = await api('GET', doc.$schema, { auto: true, label: 'schema' });
    if (r.status === 200) schema = (await readDoc(m[1], m[2], m[3], r)).doc;
    else if (r.status === 404 || r.status === 410) schema = null;
    else throw new Error(`fetching the schema ${doc.$schema} answered ${r.status}`);
    schemaCache.set(doc.$schema, schema);
  }
  if (!schema || typeof schema !== 'object') return { errors: [{ pointer: '', message: 'schema_unavailable: ' + doc.$schema }] };
  const v = Z.validate(schema, validationInstance(doc));
  return { errors: v.errors, note: v.unchecked.length ? 'validated in this browser, except keywords ' + v.unchecked.join(', ') : 'validated in this browser against its $schema' };
}

const paddedLength = (n) => Z.padLen(n);

/* foldLog verifies and folds an e2e log answer that ends at id and starts after since. */
async function foldLog(ns, name, id, since, arr) {
  const out = { id, since, entries: [], flagged: [], validID: '', value: undefined, notes: [] };
  const bad = (msg) => { throw new Error(`e2e log of ${ns}/${name}: ${msg}`); };
  let doc, exists = false, prev = '', i = 0;
  const cfg = ((await nsInfo(ns)).doc || {}).encryption || {};
  if (since) {
    const m = arr[0] || {};
    if (m.kind !== 'snapshot' || m.id !== since || typeof m.snapshot !== 'string') bad(`the range after ${since} does not start with its snapshot`);
    const hdr = Z.parseJWE(m.snapshot).header;
    const kns = Z.parseKid(hdr.kid).ns;
    if (!(await nsChainOK(ns, kns))) bad('snapshot sealed under ' + hdr.kid);
    const d = await openSealed(kns, m.snapshot, '', { ns: kns, name, id: since, kind: 'snapshot' });
    doc = d.value; exists = true; prev = since; out.validID = since;
    out.entries.push({ id: since, kind: 'snapshot', _sealed: hdr.kid, _note: 'the prune snapshot the log starts from', _doc: doc });
    i = 1;
  }
  for (; i < arr.length; i++) {
    const e = Object.assign({}, arr[i]);
    out.entries.push(e);
    if ((e.parent || '') !== prev) bad(`entry ${e.id} does not chain`);
    if (e.kind === 'tombstone') {
      if ((await Z.tombstoneID(e.parent)) !== e.id) bad(`tombstone ${e.id} has the wrong id`);
      prev = e.id; continue;
    }
    if (e.kind !== 'rev') bad(`entry ${e.id} of kind ${e.kind}`);
    if (!Array.isArray(e.patches)) bad(`revision ${e.id} has no patch set`);
    const flag = (msg) => { e._flag = msg; out.flagged.push({ id: e.id, author: e.author, message: msg }); };
    const jwe = Z.sealedJWE(e.patches);
    if (jwe || !e.patches.length) {
      if ((await Z.revisionID(e.parent || '', e.patches)) !== e.id) bad(`revision ${e.id} has the wrong id`);
    }
    prev = e.id;
    if (!e.patches.length) { out.validID = e.id; e._note = 'restore with []: the last live document comes back'; continue; }
    if (!jwe) { flag('not a sealed patch set'); continue; }
    let hdr, kns;
    try { hdr = Z.parseJWE(jwe).header; kns = Z.parseKid(hdr.kid).ns; } catch (err) { flag('sealed patch set: ' + err.message); continue; }
    if (!(await nsChainOK(ns, kns))) { flag('sealed under another namespace\'s key ' + hdr.kid); continue; }
    e._sealed = hdr.kid;
    const key = await contentKey(hdr.kid, '');
    let o;
    try { o = await Z.openJWE(jwe, key); } catch (err) { flag('sealed patch set: ' + err.message); continue; }
    const diff = Z.plDiff(hdr.pl, { ns: kns, name, parent: e.parent || '' });
    if (diff.length) { flag('sealed patch set bound to another ' + diff.join(', ')); continue; }
    let plain;
    try { plain = JSON.parse(o.text); } catch (err) { flag('patch set: ' + err.message); continue; }
    e._plain = plain;
    if (cfg.pad && o.plaintext.length !== paddedLength(Z.utf8(o.text.replace(/ +$/, '')).length)) e._note = 'not padded to its size bucket (the namespace has pad; it may predate it)';
    let res;
    try { res = Z.applyPatch(doc, exists, plain); } catch (err) { flag('patch set does not apply: ' + err.message); continue; }
    const v = await validateDoc(res.doc);
    if (v.errors.length) { flag('the document does not validate against its $schema: ' + v.errors.map((x) => (x.pointer || '(root)') + ' ' + x.message).join('; ')); continue; }
    if (v.note) e._note = (e._note ? e._note + '; ' : '') + v.note;
    if (!Z.sameBlobs(Z.sealedBlobs(e.patches), Z.blobIDs(res.doc))) { flag('the declared blob list does not match the blobs the document references (\u00a7E.3.1)'); continue; }
    doc = res.doc; exists = res.exists; out.validID = e.id; e._doc = doc;
  }
  if (prev !== id) bad(`the log ends at ${prev}, not ${id}`);
  if (!exists) bad('no valid revision');
  out.value = doc;
  return out;
}

function foldSummary(f) {
  const revs = f.entries.filter((e) => e.kind === 'rev').length;
  return h('div', { class: 'seal-box' + (f.flagged.length ? ' bad' : '') },
    h('div', { class: 'state-line' }, h('span', { class: 'badge tomb' }, 'E3'), h('span', {}, `folded ${revs} sealed revision(s)` + (f.since ? ' from a prune snapshot' : '') + ' in this browser'),
      f.flagged.length ? h('span', { class: 'badge err' }, `${f.flagged.length} flagged`) : h('span', { class: 'badge ok' }, 'all valid')),
    f.validID && f.validID !== f.id ? h('div', { class: 'note' }, 'The document is that of the last valid revision ', idEl(f.validID), '.') : null,
    f.flagged.length ? h('ul', { class: 'checks' }, ...f.flagged.map((x) => h('li', { class: 'bad' }, '✗ ', idEl(x.id), ` ${x.author || ''}: ${x.message}`))) : null);
}

function renderResSeal(st) {
  const box = $('resSeal');
  const parts = [];
  if (st && st.seal) parts.push(sealSummary(st.seal));
  if (st && st.fold) parts.push(foldSummary(st.fold));
  if (st && st.foldErr) parts.push(h('div', { class: 'errbox' }, h('span', { class: 'code' }, 'e2e fold failed'), '  ' + st.foldErr));
  if (st && st.raw && (st.seal || st.foldErr)) parts.push(h('details', {}, h('summary', { class: 'muted small' }, 'raw response as served'), jsonPre(st.raw)));
  box.hidden = !parts.length;
  box.replaceChildren(...parts);
}

function withNonce(ops) {
  return ops.filter((o) => !(o && o.path === '/$nonce' && (o.op === 'add' || o.op === 'replace'))).concat([{ op: 'add', path: '/$nonce', value: Z.newNonce() }]);
}

/* syncSealBoxes presets the write options for the selected namespace's level. */
function syncSealBoxes() {
  const sealed = S.nsLevel === 'sealed' || S.nsLevel === 'e2e';
  $('addNonce').checked = sealed;
  $('sealE2E').checked = S.nsLevel === 'e2e';
  $('sealE2E').disabled = S.nsLevel !== 'e2e';
}

/* writeSealed seals a patch set in the browser and sends it, like client.E2E (§E.3.1). */
async function writeSealed(kind, patchText) {
  const { ns, res } = S;
  const p = tryParse(patchText);
  if (!p.ok || !Array.isArray(p.v)) return toast('The patch set is not a JSON array');
  const out = $('sealOut'); out.hidden = false;
  const fail = (msg) => { out.replaceChildren(h('div', { class: 'errbox' }, h('span', { class: 'code' }, 'not sent'), '  ' + msg)); };
  try {
    const parent = kind === 'create' ? '' : ($('ifMatch').value.trim().replace(/"/g, ''));
    if (kind !== 'create' && !ID_RE.test(parent)) return fail('If-Match must be the parent revision id');
    // The document the patches apply to: the parent's, or for a restore the last live one.
    let base, exists = false;
    if (kind !== 'create') {
      const at = kind === 'restore' ? (S.resState && S.resState.last) : parent;
      if (!at) return fail('no last live revision to restore onto');
      const r = await api('GET', `/r/${ns}/${res}/rev/${at}`, { auto: true });
      const d = r.status === 200 ? await readDoc(ns, res, at, r) : { foldErr: 'HTTP ' + r.status };
      if (d.foldErr || d.doc === undefined) return fail('could not fold the base document: ' + (d.foldErr || 'no document'));
      base = d.doc; exists = true;
    }
    let patches = p.v;
    const trial = Z.applyPatch(base, exists, patches);
    if ($('addNonce').checked && trial.doc && typeof trial.doc === 'object' && !Array.isArray(trial.doc)) patches = withNonce(patches);
    const result = Z.applyPatch(base, exists, patches).doc;
    const v = await validateDoc(result);
    if (v.errors.length && !confirm('The resulting document does not validate against its $schema:\n\n' + v.errors.map((x) => (x.pointer || '(root)') + ' ' + x.message).join('\n') + '\n\nReaders will flag this revision. Write it anyway?')) return fail('the document does not validate: ' + v.errors.map((x) => x.message).join('; '));
    const info = await nsInfo(ns);
    const enc = (info.doc && info.doc.encryption) || {};
    const kid = Z.kid(ns, enc.epoch || 1);
    const key = await contentKey(kid, '');
    const blobs = Z.blobIDs(result); // declared in plaintext on the sealed op (§E.3.1)
    const body = Z.canonical(await Z.sealPatchSet(key, kid, ns, res, parent, patches, !!enc.pad, blobs));
    const expect = await Z.revisionID(parent, JSON.parse(body));
    const headers = kind === 'create' ? { 'If-None-Match': '*' } : { 'If-Match': quoteId(parent) };
    S.lastSealed = { path: rpath(), headers, body, expect, patches, kid, parent, blobs };
    $('resendSealed').hidden = false;
    await sendSealed();
  } catch (err) { fail(err.message); }
}

async function sendSealed() {
  const x = S.lastSealed; if (!x) return;
  const r = await api('PATCH', x.path, { ct: PJ, headers: x.headers, body: x.body, label: 'e2e write' });
  const got = r.etag();
  $('sealOut').hidden = false;
  $('sealOut').replaceChildren(h('div', { class: 'seal-box' + (r.ok ? '' : ' bad') },
    h('div', { class: 'state-line' }, h('span', { class: 'badge tomb' }, 'sealed in this browser'), h('span', { class: 'mono small' }, 'kid ' + x.kid), h('span', { class: 'badge ' + (r.ok ? 'ok' : 'err') }, r.neterr ? 'network error' : 'HTTP ' + r.status)),
    h('div', { class: 'small' }, 'pl ', h('code', {}, Z.canonical({ ns: S.ns, name: S.res, parent: x.parent })), ' · expected id ', idEl(x.expect),
      got ? (got === x.expect ? h('span', { class: 'badge ok' }, 'server id matches') : h('span', { class: 'badge err' }, 'server id differs: ' + short(got))) : null),
    x.blobs && x.blobs.length ? h('div', { class: 'small' }, `declares ${x.blobs.length} blob(s) in plaintext: `, ...x.blobs.map((b) => idEl(b))) : null,
    h('details', {}, h('summary', { class: 'muted small' }, 'plaintext patch set (never sent)'), jsonPre(x.patches)),
    r.ok || r.status === 412 || r.status === 422 ? null : h('div', { class: 'note' }, 'Not acknowledged: resend the exact same ciphertext so a retry keeps the id (§E.3.1).')));
  if (r.status === 201 || r.status === 200) { S.ifDirty = false; S.lastSealed = null; $('resendSealed').hidden = true; await afterWrite(); }
}

/* ------------------------------------------------------------------ *
 * blobs (§7.8, §E.2.2, §E.3.1): chips for the references of a document, and attaching files
 * ------------------------------------------------------------------ */
/* Types a blob URL may be opened as in a tab. Anything else (html, svg, xml, scripts) is offered as a download
 * only: a blob: URL shares this page's origin, which holds the Bearer grant and the identity. */
const OPEN_SAFE = /^(image\/(png|jpe?g|gif|webp|avif|bmp)|text\/plain)$/;
const PREVIEW_IMG = 4 << 20, PREVIEW_TEXT = 64 << 10;
const EXT = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/gif': 'gif', 'image/webp': 'webp', 'image/svg+xml': 'svg', 'text/plain': 'txt', 'text/html': 'html', 'application/pdf': 'pdf', 'application/json': 'json' };
const blobCache = new Map(); // ns/name/bid[/key] -> { type, data }, bounded by bytes
let blobCacheBytes = 0;

const fmtBytes = (n) => (n < 1024 ? n + ' B' : n < 1 << 20 ? (n / 1024).toFixed(1) + ' KiB' : (n / (1 << 20)).toFixed(1) + ' MiB');
const ptrEsc = (k) => String(k).replace(/~/g, '~0').replace(/\//g, '~1');

/* findBlobRefs lists the references of a document: objects with a $blob string, at any depth (client.BlobIDs). */
function findBlobRefs(doc) {
  const out = [];
  if (doc && typeof doc === 'object' && !Array.isArray(doc) && doc.$schema === 'https://json-schema.org/draft/2020-12/schema') return out;
  const walk = (v, at) => {
    if (Array.isArray(v)) v.forEach((x, i) => walk(x, at + '/' + i));
    else if (v && typeof v === 'object') {
      if (typeof v.$blob === 'string') out.push({ path: at, ref: v });
      else for (const [k, x] of Object.entries(v)) walk(x, at + '/' + ptrEsc(k));
    }
  };
  walk(doc, '');
  return out;
}

const httpFail = (r) => new Error(r.neterr ? 'network error: ' + r.neterr : `HTTP ${r.status}${r.json && r.json.code ? ' ' + r.json.code : ''}${r.json && r.json.message ? ': ' + r.json.message : ''}`);

/* openE2Blob opens a blob a sealed namespace delivered sealed (§E.2.2): kid names this namespace, pl is
 * { ns, name, blob }, and the key is the resource's K_r of that epoch. A missing key is tagged noKey. */
async function openE2Blob(ns, name, bid, bytes) {
  const { header } = Z.parseBlob(bytes);
  const k = Z.parseKid(header.kid);
  if (k.ns !== ns) throw new Error(`the blob is sealed under ${header.kid}, not a key of ${ns}`);
  let key;
  try { key = await contentKey(header.kid, name); } catch (err) { throw Object.assign(err, { noKey: true, epoch: k.epoch }); }
  const o = await Z.openBlob(bytes, key);
  const diff = Z.plDiff(o.header.pl, { ns, name, blob: bid });
  if (o.header.kid !== header.kid || diff.length) throw new Error('the sealed blob is bound to another ' + (diff.join(', ') || 'kid'));
  return { data: o.data, epoch: k.epoch };
}

/* getBlob reads the blob a reference names and returns { type, data, note }, like client.GetBlobRef: a sealed namespace
 * answers 302 to …/blob/{bid}/e/{e} (fetch follows it) with the sealed-blob form, opened with the epoch's key, and
 * if this reader lacks that key, with older epochs it holds. E3 references carry their key. Ids and sizes are checked. */
async function getBlob(ns, name, ref, auto) {
  const bid = ref.$blob;
  if (!ID_RE.test(bid) || typeof ref.type !== 'string' || !Number.isInteger(ref.size)) throw new Error('malformed blob reference');
  const ck = [ns, name, bid, ref.sealed ? ref.sealed.key : ''].join('/');
  if (blobCache.has(ck)) return blobCache.get(ck);
  const base = `/r/${ns}/${name}/blob/${bid}`;
  const fetchAt = async (epoch) => {
    const r = await api('GET', base + (epoch ? '/e/' + epoch : ''), { binary: true, auto, label: 'blob' });
    if (r.status !== 200) throw Object.assign(httpFail(r), { status: r.status });
    return { bytes: r.bin, ct: Z.blobType(r.hdr('Content-Type')), via: r.finalPath, redirected: r.redirected };
  };
  const got = await fetchAt(0);
  let bytes = got.bytes, note = '';
  // Only a sealed namespace redirects to …/e/{e}: elsewhere a blob of the sealed type is bytes as stored (§E.2.2).
  const viaEpoch = got.redirected && /\/e\/\d+$/.test(got.via || '');
  if (viaEpoch && got.ct === Z.BLOB_TYPE && hasKid(bytes)) {
    let o;
    try { o = await openE2Blob(ns, name, bid, bytes); } catch (err) {
      if (!err.noKey) throw err;
      // No key for the epoch served: ask for an older one this reader holds (§E.2.2).
      for (let e = err.epoch - 1; e >= 1 && !o; e--) {
        let alt; try { alt = await fetchAt(e); } catch (x) { if (x.status === 404 || x.status === 410) continue; throw x; }
        try { o = await openE2Blob(ns, name, bid, alt.bytes); } catch (x) { if (!x.noKey) throw x; }
      }
      if (!o) throw err;
    }
    bytes = o.data; note = `sealed under epoch ${o.epoch}, opened in this browser`;
  }
  let out;
  if (ref.sealed) {
    out = await Z.decryptBlob(ref, bytes);
    note = 'end-to-end: decrypted in this browser with the key of the reference';
  } else {
    if (bytes.length !== ref.size || (await Z.blobID(ref.type, ref.nonce || '', bytes)) !== bid) throw new Error('the blob does not match its reference (id or size)');
    out = { type: Z.blobType(ref.type), data: bytes };
  }
  out.note = note;
  const res = { type: out.type, data: out.data, note: out.note };
  if (res.data.length <= 8 << 20) {
    blobCache.set(ck, res); blobCacheBytes += res.data.length;
    for (const [k, v] of blobCache) { if (blobCacheBytes <= 32 << 20) break; blobCache.delete(k); blobCacheBytes -= v.data.length; }
  }
  return res;
}
function hasKid(bytes) { try { return !!Z.parseBlob(bytes).header.kid; } catch (_) { return false; } }

/* blobChip: the reference as a chip with its type and size, Open and Download, and an inline preview. */
function blobChip(ns, name, path, ref, urls) {
  const e3 = ref.sealed && typeof ref.sealed === 'object' ? ref.sealed : null;
  const type = Z.blobType(e3 ? e3.type : ref.type), size = e3 ? e3.size : ref.size;
  const body = h('div', { class: 'blob-body' });
  let loaded = null;
  const load = async (auto) => {
    if (loaded) return loaded;
    const st = h('span', { class: 'muted small' }, 'loading…');
    body.append(st);
    try { loaded = await getBlob(ns, name, ref, auto); } catch (err) { st.replaceWith(h('span', { class: 'errline' }, err.message)); throw err; }
    st.remove();
    return loaded;
  };
  const url = (b, asType) => { const u = URL.createObjectURL(new Blob([b.data], { type: asType })); urls.push(u); return u; };
  const click = (u, attrs) => { const a = h('a', Object.assign({ href: u, rel: 'noopener' }, attrs)); document.body.append(a); a.click(); a.remove(); };
  const fname = () => (path.split('/').filter((x) => x && !/^\d+$/.test(x)).pop() || 'blob') + '-' + short(ref.$blob).replace('…', '') + (EXT[type] ? '.' + EXT[type] : '');
  const preview = async (auto) => {
    try {
      const b = await load(auto);
      if (/^image\//.test(b.type)) body.append(h('img', { class: 'blob-img', src: url(b, b.type), alt: path }));
      else if (/^text\//.test(b.type)) {
        const t = new TextDecoder().decode(b.data.slice(0, PREVIEW_TEXT));
        body.append(h('pre', { class: 'blob-text' }, t + (b.data.length > PREVIEW_TEXT ? '\n…' : '')));
      }
      if (b.note) body.append(h('div', { class: 'muted small' }, b.note));
    } catch (_) { /* shown by load */ }
  };
  const previewable = (/^image\//.test(type) && size <= PREVIEW_IMG) || (/^text\//.test(type) && size <= PREVIEW_TEXT);
  const chip = h('div', { class: 'blob-chip' },
    h('div', { class: 'row' },
      h('span', { class: 'badge info' }, type), h('span', { class: 'muted small' }, fmtBytes(size)),
      e3 ? h('span', { class: 'badge tomb', title: 'encrypted in the browser of the writer; the key is inside the sealed reference (§E.3.1)' }, 'E3 sealed') : null,
      ref.nonce ? h('span', { class: 'badge', title: 'blob nonce ' + ref.nonce }, 'nonce') : null,
      h('span', { class: 'mono small' }, path || '(root)'), idEl(ref.$blob),
      h('button', { class: 'tiny', onclick: async () => { try { const b = await load(); click(url(b, OPEN_SAFE.test(b.type) ? b.type : 'application/octet-stream'), OPEN_SAFE.test(b.type) ? { target: '_blank' } : { download: fname() }); } catch (_) { /* shown */ } } }, 'Open'),
      h('button', { class: 'tiny', onclick: async () => { try { const b = await load(); click(url(b, 'application/octet-stream'), { download: fname() }); } catch (_) { /* shown */ } } }, 'Download'),
      !previewable && /^(image|text)\//.test(type) ? h('button', { class: 'tiny', onclick: (ev) => { ev.target.remove(); preview(false); } }, 'Preview') : null),
    body);
  if (previewable) preview(true);
  return chip;
}

/* blobsPanel renders every reference of doc, of resource ns/name (the selected ones by default), or null if none. */
function blobsPanel(doc, ns = S.ns, name = S.res) {
  const refs = findBlobRefs(doc);
  if (!refs.length) return null;
  const urls = [];
  const box = h('div', { class: 'blobs' }, h('h3', {}, `Blobs (${refs.length})`));
  box.append(...refs.map((x) => blobChip(ns, name, x.path, x.ref, urls)));
  box._urls = urls;
  return box;
}
/* renderBlobs fills the Resource tab's panel, freeing the object URLs of the last one. */
function renderBlobs(doc) {
  const box = $('resBlobs');
  (box._urls || []).forEach((u) => URL.revokeObjectURL(u));
  const p = doc ? blobsPanel(doc) : null;
  box._urls = p ? p._urls : [];
  box.hidden = !p;
  box.replaceChildren(...(p ? [p] : []));
}

/* attachFile uploads the chosen file as a blob of the selected resource (PUT …/blob/{bid}, §7.8) and inserts
 * its reference into the patch set in the editor. Sealed namespaces get a Blob-Nonce (§C.7); e2e ones get the
 * file encrypted here first (§E.3.1), with the key in the reference. */
async function attachFile() {
  if (!S.ns || !S.res) return toast('Select a namespace and a resource name');
  const f = $('attachFile').files[0];
  if (!f) return toast('Choose a file');
  const out = $('attachOut'); out.hidden = false;
  const fail = (msg) => out.replaceChildren(h('div', { class: 'errbox' }, h('span', { class: 'code' }, 'not attached'), '  ' + msg));
  out.replaceChildren(h('span', { class: 'muted small' }, 'uploading\u2026'));
  try {
    const data = new Uint8Array(await f.arrayBuffer());
    const info = await nsInfo(S.ns);
    const level = S.nsLevel || info.level;
    const type = Z.blobType(f.type) || 'application/octet-stream';
    let body = data, ct = type, nonce = '', ref;
    if (level === 'e2e') {
      const enc = (info.doc && info.doc.encryption) || {};
      const e = await Z.encryptBlob(type, data, !!enc.pad);
      body = e.sealed; ct = Z.BLOB_TYPE; ref = e.ref;
    } else {
      if (level === 'sealed') nonce = Z.newNonce();
      ref = { $blob: await Z.blobID(type, nonce, data), type, size: data.length };
      if (nonce) ref.nonce = nonce;
    }
    const r = await api('PUT', `/r/${S.ns}/${S.res}/blob/${ref.$blob}`, { raw: true, body, ct, headers: { 'Blob-Nonce': nonce }, label: 'blob upload' });
    if (r.status !== 201) return fail(r.neterr ? 'network error: ' + r.neterr : `HTTP ${r.status}${r.json && r.json.code ? ' ' + r.json.code : ''}${r.json && r.json.message ? ': ' + r.json.message : ''}`);
    // Where it goes: the path the user picked, else /attachments/- on an existing array, else a new /attachments array.
    let path = $('attachPath').value.trim(), value = ref;
    if (!path) {
      const doc = S.resState && S.resState.kind === 'live' ? S.resState.doc : null;
      if (doc && Array.isArray(doc.attachments)) path = '/attachments/-';
      else { path = '/attachments'; value = [ref]; }
    }
    insertOp($('patch'), { op: 'add', path, value });
    out.replaceChildren(h('div', { class: 'seal-box' },
      h('div', { class: 'state-line' }, h('span', { class: 'badge ok' }, 'uploaded'), idEl(ref.$blob), h('span', { class: 'muted small' }, `${type}, ${fmtBytes(data.length)}` + (level === 'e2e' ? ', encrypted here' : nonce ? ', with a nonce' : ''))),
      h('div', { class: 'small' }, 'Inserted ', h('code', {}, `add ${path}`), ' into the patch set. The blob stays pending, visible to nobody else, until a write references it: press Create or Append.'),
      h('details', {}, h('summary', { class: 'muted small' }, 'reference'), jsonPre(ref))));
  } catch (err) { fail(err.message); }
}

/* ---- Keys tab ---- */
function renderIdentity() {
  const box = $('idStatus');
  $('idDot').hidden = !ID;
  if (!ID) { box.className = 'muted'; box.textContent = 'No identity yet: generate one, or import a private key.'; return; }
  box.className = '';
  const jwk = Z.recipientJWK(ID.x);
  const rid = h('span', { class: 'muted' }, '…');
  Z.recipientID(ID.x).then((v) => { rid.replaceWith(idEl(v)); });
  const block = { kid: '<key id>', sub: 'user:you', ns: [S.ns || 'ns'], can: ['read'], exp: '2026-12-31T00:00:00Z', enc: jwk };
  box.replaceChildren(
    h('dl', { class: 'kv' }, h('dt', {}, 'public key'), h('dd', { class: 'mono' }, ID.x), h('dt', {}, 'recipient id'), h('dd', {}, rid)),
    h('div', { class: 'row' }, h('button', { class: 'tiny', onclick: () => copy(JSON.stringify(jwk), 'public JWK') }, 'Copy public JWK'),
      h('button', { class: 'tiny', onclick: () => { $('krReader').value = JSON.stringify(jwk); toast('Reader field set'); } }, 'Use as reader below')),
    jsonPre(jwk),
    h('details', {}, h('summary', { class: 'muted small' }, 'a read grant that carries it (E2)'),
      h('pre', { class: 'raw' }, `patchlog grant mint -key SEED -block '${JSON.stringify(block)}'`)));
}

function renderKeysHeld() {
  const tb = $('keysTbl').tBodies[0];
  const rows = [...KEYS.from.entries()].sort();
  if (!rows.length) { tb.replaceChildren(h('tr', {}, h('td', { class: 'empty', colspan: 3 }, 'No keys yet.'))); return; }
  tb.replaceChildren(...rows.map(([k, from]) => { const [kid, res] = k.split('\n'); return h('tr', {}, h('td', { class: 'mono' }, kid), h('td', { class: 'mono' }, res || '—'), h('td', { class: 'small' }, from)); }));
}

async function fetchKeysForm() {
  const ns = $('keysNs').value.trim() || S.ns;
  if (!ns) return toast('Enter a namespace');
  const body = {};
  const ep = $('keysEpochs').value.split(',').map((s) => s.trim()).filter(Boolean);
  if (ep.length) body.epochs = ep.map(Number);
  const rs = $('keysRes').value.split(',').map((s) => s.trim()).filter(Boolean);
  if (rs.length) body.resources = rs;
  const r = await api('POST', `/ns/${ns}/keys`, { body });
  if (r.ok && r.json) {
    try { toast(`${await takeKeys(r.json.keys)} key(s) stored`); } catch (err) { toast(err.message); }
  }
}

async function genIdentity() {
  if (ID && !confirm('Replace the current identity? Keys wrapped to it can no longer be opened here.')) return;
  try { saveIdentity(await Z.generateIdentity()); toast('Identity generated'); } catch (err) { toast('X25519 is not available in this browser: ' + err.message); }
}
async function importIdentity() {
  const t = $('idImport').value.trim();
  if (!t) return toast('Paste a private key');
  try {
    let d = t;
    if (t.startsWith('{')) { const j = JSON.parse(t); if (j.kty !== 'OKP' || j.crv !== 'X25519' || !j.d) throw new Error('want an OKP/X25519 JWK with d'); d = j.d; }
    saveIdentity(await Z.identityFromPrivate(d));
    $('idImport').value = '';
    toast('Identity imported');
  } catch (err) { toast('Import failed: ' + err.message); }
}

/* ---- E3 keyring administration (client.E2E InitKeyring / AddReader / RotateEpoch) ---- */
const KR = { ns: '', doc: null, head: '', status: 0 };
async function loadKeyring() {
  KR.ns = S.ns; KR.doc = null; KR.head = ''; KR.status = 0;
  if (!S.ns || S.nsLevel !== 'e2e') return renderKeyring();
  const r = await api('GET', `/r/${S.ns}/keyring`, { auto: true, label: 'keyring' });
  KR.status = r.status;
  if (r.status === 200) { try { KR.doc = Z.parseKeyring(r.json); KR.head = r.hdr('X-Revision') || r.etag(); } catch (err) { KR.err = err.message; } }
  renderKeyring();
}
async function renderKeyring() {
  const box = $('krStatus');
  const lvl = S.nsLevel;
  $('krMeta').textContent = S.ns ? `${S.ns}${lvl ? ' · ' + lvl : ''}` : '';
  ['krInit', 'krAdd', 'krRotate'].forEach((b) => { $(b).disabled = lvl !== 'e2e'; });
  if (!S.ns || lvl !== 'e2e') { box.className = 'muted'; box.textContent = S.ns ? `${S.ns} is not an e2e namespace (encryption.level ${lvl || 'none'}).` : 'Select an e2e namespace above.'; return; }
  const epoch = ((S.nsDoc || {}).encryption || {}).epoch || 1;
  box.className = '';
  if (!KR.doc) {
    box.replaceChildren(h('div', { class: 'state-line' }, h('b', {}, S.ns), h('span', { class: 'badge warn' }, KR.status === 404 ? 'no keyring yet' : 'keyring not readable (' + KR.status + ')'), h('span', { class: 'muted' }, 'encryption.epoch ' + epoch)),
      h('p', { class: 'note' }, 'Init keyring creates it with a fresh key for epoch ' + epoch + ', wrapped for this identity.'));
    return;
  }
  const mine = ID ? await Z.recipientID(ID.x) : '';
  const rows = Object.entries(KR.doc.recipients).map(([rid, jwk]) => {
    const eps = Object.keys(KR.doc.epochs).filter((e) => KR.doc.epochs[e][rid]).sort((a, b) => a - b);
    return h('tr', {}, h('td', {}, h('input', { type: 'checkbox', class: 'kr-keep', 'data-x': jwk.x, checked: eps.includes(String(KR.doc.current)) || rid === mine, title: 'keep in a rotation' })),
      h('td', {}, idEl(rid), rid === mine ? h('span', { class: 'badge ok' }, 'this identity') : null), h('td', { class: 'mono small' }, eps.join(', ')));
  });
  box.replaceChildren(
    h('div', { class: 'state-line' }, h('b', {}, S.ns), h('span', { class: 'muted' }, 'keyring head'), idEl(KR.head), h('span', { class: 'muted' }, `current epoch ${KR.doc.current} · encryption.epoch ${epoch}`),
      KR.doc.current !== epoch ? h('span', { class: 'badge warn' }, 'epoch mismatch') : null,
      mine && KR.doc.epochs[String(epoch)] && KR.doc.epochs[String(epoch)][mine] ? h('span', { class: 'badge ok' }, 'this identity can read and write') : h('span', { class: 'badge err' }, 'this identity holds no current key')),
    h('div', { class: 'scroll' }, h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'keep'), h('th', {}, 'recipient'), h('th', {}, 'epochs'))), h('tbody', {}, ...rows))));
}
function readerX() {
  const t = $('krReader').value.trim();
  if (!t) return '';
  return t.startsWith('{') ? Z.parseJWK(t) : Z.parseJWK({ kty: 'OKP', crv: 'X25519', x: t });
}
async function krInit() {
  if (!ID) return toast('Generate or import an identity first');
  try {
    const epoch = ((S.nsDoc || {}).encryption || {}).epoch || 1;
    const key = Z.randomBytes(32);
    const kr = Z.buildKeyring(S.ns, epoch);
    await Z.keyringAdd(kr, ID.x, epoch, key);
    const other = readerX();
    if (other) await Z.keyringAdd(kr, other, epoch, key);
    let r;
    if (KR.doc && KR.doc.ns === S.ns) return toast('The namespace already has a keyring');
    if (KR.doc) r = await api('PATCH', `/r/${S.ns}/keyring`, { ct: PJ, headers: { 'If-Match': quoteId(KR.head) }, body: [{ op: 'replace', path: '', value: kr }], label: 'keyring' });
    else r = await api('PATCH', `/r/${S.ns}/keyring`, { ct: PJ, headers: { 'If-None-Match': '*' }, body: [{ op: 'add', path: '', value: kr }], label: 'keyring' });
    if (r.ok) { holdEpoch(Z.kid(S.ns, epoch), key, 'generated here (Init keyring)'); toast('Keyring created'); await refreshNS(); await loadKeyring(); }
  } catch (err) { toast(err.message); }
}
async function krAdd() {
  try {
    const x = readerX();
    if (!x) return toast('Paste the reader\'s public key');
    await loadKeyring();
    if (!KR.doc) return toast('No keyring');
    const kr = JSON.parse(JSON.stringify(KR.doc));
    for (const e of Object.keys(kr.epochs).map(Number)) {
      if (e !== kr.current && !$('krHistory').checked) continue;
      let key;
      try { key = await contentKey(Z.kid(S.ns, e), ''); } catch (err) { if (e === kr.current) throw err; continue; }
      await Z.keyringAdd(kr, x, e, key);
    }
    const r = await api('PATCH', `/r/${S.ns}/keyring`, { ct: PJ, headers: { 'If-Match': quoteId(KR.head) }, body: [{ op: 'replace', path: '', value: kr }], label: 'keyring' });
    if (r.ok) { toast('Reader added'); await loadKeyring(); }
  } catch (err) { toast(err.message); }
}
async function krRotate() {
  try {
    if (!ID) return toast('Generate or import an identity first');
    await loadKeyring();
    if (!KR.doc) return toast('No keyring');
    const epoch = ((S.nsDoc || {}).encryption || {}).epoch || 1;
    if (KR.doc.current !== epoch) return toast(`The keyring is at epoch ${KR.doc.current} but encryption.epoch is ${epoch}`);
    const keep = new Set([...document.querySelectorAll('.kr-keep')].filter((c) => c.checked).map((c) => c.dataset.x));
    keep.add(ID.x);
    if (!confirm(`Rotate ${S.ns} to epoch ${epoch + 1} for ${keep.size} recipient(s)? Recipients left out cannot read anything written afterwards.`)) return;
    const kr = JSON.parse(JSON.stringify(KR.doc));
    const e = kr.current + 1, key = Z.randomBytes(32);
    kr.epochs[String(e)] = {};
    for (const x of keep) await Z.keyringAdd(kr, x, e, key);
    kr.current = e;
    const r = await api('POST', `/ns/${S.ns}/batch`, { label: 'rotate', body: {
      config: { ifMatch: S.config, patches: [{ op: 'add', path: '/encryption/epoch', value: e }] },
      items: [{ resource: 'keyring', ifMatch: KR.head, steps: [[{ op: 'replace', path: '', value: kr }]] }] } });
    if (r.ok) { holdEpoch(Z.kid(S.ns, e), key, 'generated here (rotation)'); nsInfoCache.delete(S.ns); toast('Rotated to epoch ' + e); await refreshNS(); await loadKeyring(); }
  } catch (err) { toast(err.message); }
}

async function decryptPasted() {
  const out = $('jweOut');
  const jwe = $('jweIn').value.trim();
  if (!jwe) return;
  try {
    const { header } = Z.parseJWE(jwe);
    const res = $('jweRes').value.trim() || (header.pl && header.pl.name && header.pl.kind && header.pl.kind !== 'snapshot' ? header.pl.name : '');
    const d = await openSealed('', jwe, res, header.pl);
    d.checks.splice(1, 1, { ok: true, what: 'pl ' + Z.canonical(header.pl) + ' (not compared: no request to compare with)' });
    out.replaceChildren(decView(d));
  } catch (err) { out.replaceChildren(h('div', { class: 'errbox' }, h('span', { class: 'code' }, 'failed'), '  ' + err.message)); }
}

async function runSelfTest() {
  const out = $('selfOut');
  out.className = ''; out.textContent = 'Running…';
  try {
    const r = await api('GET', '/playground/selftest.json', { label: 'self-test' });
    if (!r.ok || !r.json) throw new Error('selftest.json: HTTP ' + r.status);
    const res = await Z.selfTest(r.json);
    const ok = res.every((x) => x.ok);
    out.replaceChildren(h('div', { class: 'state-line' }, h('span', { class: 'badge ' + (ok ? 'ok' : 'err') }, ok ? 'all passed' : 'failures'), h('span', { class: 'muted' }, `${res.filter((x) => x.ok).length}/${res.length}`)),
      checkList(res.map((x) => ({ ok: x.ok, what: x.name + (x.detail ? ': ' + x.detail : '') }))));
  } catch (err) { out.replaceChildren(h('div', { class: 'errbox' }, h('span', { class: 'code' }, 'error'), '  ' + err.message)); }
}

/* ------------------------------------------------------------------ *
 * catalog (Addendum B)
 * ------------------------------------------------------------------ */
const TREE = '/playground/tree';
const NODE_RE = /^[a-z0-9][a-z0-9_-]*$/;
const C = {
  ns: '', head: '', config: '', doc: null, nodes: new Map(), trust: [], mode: 'tree', contentDocs: {}, contentHeads: {},
  source: '', proxy: null, proxyCatalogs: [], listing: null, at: '', view: '', note: '', problems: null, sel: '', min: [], loading: false, gen: 0,
  catalogs: null, discovering: false, // discovered catalog namespaces: [{ ns, mode }], null until found
};

const cmpCU = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const hrefOf = (name) => `/r/${C.ns}/${name}`;
function nodeName(href) {
  const m = /^\/r\/([^/]+)\/([^/]+)$/.exec(href || '');
  return m && m[1] === C.ns ? m[2] : '';
}
function itemOf(name) { const i = name.indexOf('.'); return i > 0 ? { ns: name.slice(0, i), name: name.slice(i + 1), href: `/r/${name.slice(0, i)}/${name.slice(i + 1)}` } : null; }
function parentsOf(n) { return n && n.doc && Array.isArray(n.doc.parents) ? n.doc.parents.filter((p) => p && typeof p.href === 'string') : []; }

async function mapLimit(items, n, fn) {
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); } }));
  return out;
}
async function allHeads(ns, head) {
  let items = [], after = '';
  for (let page = 0; page < 20; page++) {
    const r = await api('GET', `/ns/${ns}/rev/${head}/heads` + (after ? `?after=${encodeURIComponent(after)}` : ''), { auto: true, label: 'catalog' });
    if (r.status !== 200 || !r.json) break;
    items = items.concat(r.json.items || []);
    if (!r.json.next) break;
    after = r.json.next;
  }
  return items;
}
/* nsHeadDoc reads a namespace document (decrypting a sealed one) and its head. */
async function nsHeadDoc(ns) {
  const r = await api('GET', `/ns/${ns}`, { auto: true, label: 'catalog' });
  if (r.status !== 200) return { status: r.status };
  const head = r.etag() || ((/\/rev\/([^/]+)$/.exec(r.finalPath) || [])[1] || '');
  const doc = r.jose ? (await decrypted(r, ns, '', { ns, id: head, kind: 'config' })).value : r.json;
  return { status: 200, head, config: r.hdr('X-Config-Revision') || '', doc, sealed: r.jose };
}

/* probeProxy asks the core whether it proxies a tree service (-tree-url), and which catalogs it maps to their own. */
async function probeProxy() {
  const p = await api('GET', `${TREE}/`, { auto: true, label: 'tree' });
  C.proxy = p.status === 200 && p.json && p.json.proxy === 'tree';
  C.proxyCatalogs = C.proxy && Array.isArray(p.json.catalogs) ? p.json.catalogs.filter((c) => typeof c === 'string') : [];
}

/* discoverCatalogs finds namespaces with a catalog config (§B.6). There is no namespace listing, so the
 * candidates are what the tree service serves (/_status), the proxy's mappings, the demo's catalogs and
 * the namespaces this browser has used; each is kept if its namespace document has a "catalog". */
async function discoverCatalogs() {
  if (C.proxy === null) await probeProxy();
  const cands = new Set(['cat', 'topics', ...known, ...C.proxyCatalogs, C.ns].filter((c) => c && NODE_RE.test(c)));
  if (C.proxy) {
    const st = await api('GET', `${TREE}/_status`, { auto: true, label: 'tree' });
    if (st.status === 200 && st.json && Array.isArray(st.json.catalogs)) st.json.catalogs.forEach((c) => typeof c === 'string' && cands.add(c));
  }
  const found = await mapLimit([...cands].sort(), 4, async (ns) => {
    const r = await api('GET', `/ns/${ns}`, { auto: true, label: 'catalog' });
    if (r.status !== 200) return null;
    if (r.jose) return { ns, mode: '?' }; // a sealed namespace document: kept, its mode shows once loaded
    const cat = r.json && r.json.catalog;
    return cat && typeof cat === 'object' ? { ns, mode: cat.mode === 'dag' ? 'dag' : 'tree' } : null;
  });
  C.catalogs = found.filter(Boolean);
  renderCatPick();
}

function renderCatPick() {
  const sel = $('catPick');
  const list = (C.catalogs || []).slice();
  if (C.ns && C.head && !list.some((c) => c.ns === C.ns) && C.doc && C.doc.catalog) list.push({ ns: C.ns, mode: C.mode });
  list.sort((a, b) => cmpCU(a.ns, b.ns));
  sel.replaceChildren(h('option', { value: '' }, C.catalogs === null ? 'finding catalogs…' : list.length ? '— pick —' : '— none found —'),
    ...list.map((c) => h('option', { value: c.ns, selected: c.ns === C.ns }, `${c.ns} (${c.ns === C.ns && C.head ? C.mode : c.mode})`)));
  $('catNsList').replaceChildren(...[...new Set([...list.map((c) => c.ns), ...known])].map((v) => h('option', { value: v })));
}

async function loadCatalog() {
  const ns = ($('catNs').value.trim() || 'cat');
  $('catNs').value = ns;
  store.set('pl.catNs', ns);
  if (C.catalogs === null && !C.discovering) { C.discovering = true; discoverCatalogs().finally(() => { C.discovering = false; }); }
  if (ns !== C.ns) C.sel = '';
  const gen = ++C.gen;
  C.ns = ns; C.loading = true;
  renderCatStatus();
  // Everything is read into x and published at once, so a slower earlier load can't overwrite a newer one.
  const x = { head: '', config: '', doc: null, nodes: new Map(), trust: [], mode: 'tree', contentDocs: {}, contentHeads: {} };
  // 1. The catalog namespace itself, from the core.
  const nd = await nsHeadDoc(ns);
  if (gen !== C.gen) return;
  if (nd.status !== 200) {
    Object.assign(C, x, { listing: null, loading: false, source: '', note: `GET /ns/${ns} answered ${nd.status}: not a readable namespace.` });
    return renderCatalog();
  }
  x.head = nd.head; x.config = nd.config; x.doc = nd.doc || {};
  const cat = x.doc.catalog || {};
  x.trust = Array.isArray(cat.trust) ? cat.trust.filter((t) => typeof t === 'string') : [];
  x.mode = cat.mode === 'dag' ? 'dag' : 'tree';
  C.min = treeMins(ns, x.trust);
  // 2. Every node document at the catalog's head (needed for $access and for If-Match).
  const heads = (await allHeads(ns, x.head)).filter((e) => e.kind === 'head');
  const docs = await mapLimit(heads.slice(0, 500), 6, async (e) => {
    const r = await api('GET', `/r/${ns}/${e.resource}/rev/${e.target}`, { auto: true, label: 'catalog' });
    if (r.status !== 200) return null;
    const d = await readDoc(ns, e.resource, e.target, r);
    return { name: e.resource, head: e.target, doc: d.doc && typeof d.doc === 'object' ? d.doc : {}, kind: e.resource.includes('.') ? 'item' : 'folder', sealed: !!d.seal };
  });
  x.nodes = new Map(docs.filter(Boolean).map((n) => [n.name, n]));
  // 3. Trusted content namespaces: their roles (what a role means, includes) and which items exist.
  await Promise.all(x.trust.map(async (t) => {
    const cd = await nsHeadDoc(t);
    if (cd.status !== 200) return;
    x.contentDocs[t] = cd.doc || {};
    x.contentHeads[t] = new Map((await allHeads(t, cd.head)).map((e) => [e.resource, e]));
  }));
  // 4. The tree service, through the core's same-origin proxy (-tree-url).
  Object.assign(x, await loadTreeListing());
  if (x.listing) addDangling(x);
  if (gen !== C.gen) return;
  Object.assign(C, x, { loading: false });
  renderCatalog();
}

/* addDangling puts dangling placements, which drop out of the service's listings (§B.7), back under
 * their folders, marked, so a placement of a not-yet-existing item is visible where it was placed. */
function addDangling(x) {
  const folders = new Map();
  // In a DAG a folder is listed once per path to it: add to every listing of it.
  const walk = (e) => { if (e.kind === 'folder') { (folders.get(e.name) || folders.set(e.name, []).get(e.name)).push(e); (e.children || []).forEach(walk); } };
  x.listing.forEach(walk);
  for (const d of ((x.problems && x.problems.body && x.problems.body.danglingItems) || [])) {
    const name = nodeName(d.href), n = x.nodes.get(name);
    if (!n) continue;
    for (const p of parentsOf(n)) {
      for (const f of folders.get(nodeName(p.href)) || []) {
        if (f.children && !f.children.some((c) => c.name === name)) f.children.push({ name, href: d.href, kind: 'item', item: d.item, dangling: d.reason || 'dangling', order: p.order, unlisted: true });
      }
    }
  }
}

/* treeMins is ?min= for the tree service: {ns}:{ns_id} of this page's last write to the catalog and to each
 * namespace it trusts (WRITES, from X-Namespace-Revision), the namespaces its listings depend on (§A.5, §B.5). */
function treeMins(ns, trust) {
  return [ns, ...trust].filter((n) => WRITES.has(n)).map((n) => `${n}:${WRITES.get(n).id}`);
}

/* treeGet fetches a tree service listing through the proxy, following its redirect to /at/{at}/…,
 * retrying while the service is behind ?min, and opening sealed views (§E.2.6). It uses the HTTP cache:
 * listings at an at never change, and the redirect to the current at is a head pointer, which a browser may
 * serve stale for a few seconds. So after its own write the page relists with ?min= from the write's
 * X-Namespace-Revision: a new URL, which the service answers once it has caught up (§B.5), rather than
 * fetching with no-store. */
async function treeGet(path) {
  const q = C.min.map((m, i) => (i === 0 && !path.includes('?') ? '?' : '&') + 'min=' + encodeURIComponent(m)).join('');
  let r;
  for (let i = 0; i < 4; i++) {
    r = await api('GET', `${TREE}/${C.ns}/${path}${q}`, { auto: true, label: 'tree', cache: 'default' });
    if (r.status !== 503) break;
    await sleep(800);
  }
  if (r.status !== 200) return { r };
  const view = r.finalPath.startsWith(TREE + '/') ? r.finalPath.slice(TREE.length) : r.finalPath;
  let body = r.json;
  if (r.jose) {
    let pl = {};
    try { pl = Z.parseJWE(r.text.trim()).header.pl || {}; } catch (_) { /* reported by decrypted */ }
    const d = await decrypted(r, pl.ns || C.ns, '', { ns: pl.ns || C.ns, view });
    if (d.error) return { r, view, sealedWhole: d };
    body = d.value;
  }
  if (body && typeof body === 'object') await openSealedEntries(body, view);
  return { r, view, body };
}

/* openSealedEntries decrypts per-entry sealed values ("sealed": JWE, pl {ns, name, view}) in place. */
async function openSealedEntries(v, view) {
  if (Array.isArray(v)) { for (const x of v) await openSealedEntries(x, view); return; }
  if (!v || typeof v !== 'object') return;
  if (typeof v.sealed === 'string') {
    try {
      const hdr = Z.parseJWE(v.sealed).header;
      const ens = Z.parseKid(hdr.kid).ns;
      // The entry's resource key K_r (what the tree service and the index use), else the epoch key K_e.
      // (The tree service names its entries "name", the index its hits "resource".)
      const rname = v.name !== undefined ? v.name : v.resource;
      const want = { ns: ens, name: rname, view };
      let d;
      try { d = await openSealed(ens, v.sealed, rname, want); } catch (err) { if (err.checks) throw err; d = await openSealed(ens, v.sealed, '', want); }
      if (d.value && typeof d.value === 'object') Object.assign(v, d.value);
      v._opened = hdr.kid;
    } catch (err) { v._sealedErr = err.message; }
  }
  for (const k of Object.keys(v)) if (k !== 'sealed' && typeof v[k] === 'object') await openSealedEntries(v[k], view);
}

async function loadTreeListing() {
  const x = { listing: null, at: '', view: '', problems: null, note: '', source: 'core', treeStatus: null, sealedView: false };
  if (C.proxy === null) await probeProxy();
  if (!C.proxy) { x.note = 'Computed listings (the combined checkpoint, ordering and dangling detection by the service, access filtering, manifests) need the tree service. Start the core with -tree-url (compose does) to read it through the same-origin proxy at /playground/tree/. Showing the catalog documents read directly from the core API.'; return x; }
  const roots = await treeGet('roots');
  if (!roots.body) {
    const r = roots.r;
    x.note = roots.sealedWhole ? 'The tree service answered with a sealed listing this browser has no key for: ' + roots.sealedWhole.error
      : r.status === 502 ? 'The tree service is not reachable through the proxy (502): it may still be starting. Showing core documents.'
        : r.status === 404 ? `No tree service behind the proxy serves a catalog named ${C.ns} (404): add it to the tree service's -catalog flags, or map it to its own with the core's -tree-url ${C.ns}=URL. Showing core documents.`
          : `The tree service answered ${r.status}${r.json && r.json.code ? ' ' + r.json.code : ''}. Showing core documents.`;
    return x;
  }
  x.source = 'tree';
  x.at = roots.body.at || ''; x.view = roots.view;
  // What the service follows, and whether it seals listings or skips a namespace (§E.2.6).
  const st = await api('GET', `${TREE}/_status?catalog=${encodeURIComponent(C.ns)}`, { auto: true, label: 'tree' });
  x.treeStatus = st.status === 200 && st.json ? st.json : null;
  x.sealedView = roots.r.jose;
  const trees = [];
  for (const root of roots.body.roots || []) {
    if (root.kind !== 'folder') { trees.push(root); continue; }
    const st = await treeGet(`subtree?of=${encodeURIComponent(root.href)}&depth=64`);
    trees.push(st.body && st.body.tree ? st.body.tree : root);
    if (st.body && st.body.at) x.at = st.body.at;
  }
  x.listing = trees;
  const [pr, or] = [await treeGet('problems'), await treeGet('orphans')];
  x.problems = { service: true, body: pr.body, orphans: or.body ? or.body.orphans : [] };
  return x;
}

/* ---- the local graph: derived access, problems ---- */
function ownAccess(n) {
  const a = n && n.doc && n.doc.$access;
  const out = {};
  if (a && typeof a === 'object' && !Array.isArray(a)) for (const [s, roles] of Object.entries(a)) if (s !== 'inherit' && Array.isArray(roles)) out[s] = roles.filter((x) => typeof x === 'string');
  return out;
}
function inherits(n) { const a = n && n.doc && n.doc.$access; return !(a && a.inherit === false); }
function isLive(name) { return C.nodes.has(name); }
function liveFolderParents(n) {
  return parentsOf(n).map((p) => nodeName(p.href)).filter((pn) => pn && NODE_RE.test(pn) && isLive(pn));
}
/* cyclicSet: the folders on a cycle through parents, i.e. in a strongly connected component, as the tree
 * service computes them (§B.5). Walks never pass through them, and they contribute no access (§B.11.2). */
function cyclicSet() {
  if (C.cycFor === C.nodes) return C.cyc;
  const cyc = new Set();
  for (const n of C.nodes.values()) {
    if (n.kind !== 'folder') continue;
    const seen = new Set(), stack = liveFolderParents(n);
    while (stack.length) {
      const x = stack.pop();
      if (x === n.name) { cyc.add(n.name); break; }
      if (!seen.has(x)) { seen.add(x); stack.push(...liveFolderParents(C.nodes.get(x))); }
    }
  }
  C.cycFor = C.nodes; C.cyc = cyc;
  return cyc;
}
/* walkableParents: live parent folders, where neither end is on a cycle (§B.5). */
function walkableParents(n) {
  const cyc = cyclicSet();
  if (!n || cyc.has(n.name)) return [];
  return liveFolderParents(n).filter((pn) => !cyc.has(pn));
}
function itemExists(name) {
  const it = itemOf(name);
  if (!it || !C.contentHeads[it.ns]) return null; // unknown: namespace not trusted or not readable
  const x = C.contentHeads[it.ns].get(it.name);
  return !!(x && x.kind === 'head');
}
/* effective: subject -> role -> Set(nodes where assigned), over every walkable path up to a root (§B.11.2). */
function effectiveAccess(name) {
  const eff = {};
  const walk = (nm, path, depth) => {
    const n = C.nodes.get(nm);
    if (!n || path.has(nm) || depth > 64 || cyclicSet().has(nm)) return;
    for (const [s, roles] of Object.entries(ownAccess(n))) for (const role of roles) ((eff[s] = eff[s] || {})[role] = eff[s][role] || new Set()).add(nm);
    if (!inherits(n)) return;
    const next = new Set(path); next.add(nm);
    for (const p of walkableParents(n)) walk(p, next, depth + 1);
  };
  walk(name, new Set(), 0);
  return eff;
}
/* roleInfo describes a role as the namespace that owns its meaning defines it. */
function roleInfo(role, itemNs) {
  if (itemNs) {
    const roles = (C.contentDocs[itemNs] || {}).roles || {};
    const d = roles[role];
    if (!d) return `${itemNs} defines no role "${role}": it grants nothing there`;
    const inc = [], seen = new Set([role]);
    const q = [...(d.includes || [])];
    while (q.length) { const x = q.shift(); if (seen.has(x)) continue; seen.add(x); inc.push(x); q.push(...(((roles[x] || {}).includes) || [])); }
    return `${itemNs}: ${role} can ${(d.can || []).join(', ') || 'nothing'}${d.rules ? ' (with rules)' : ''}${inc.length ? '; includes ' + inc.join(', ') : ''}`;
  }
  const d = ((C.doc || {}).roles || {})[role];
  return d ? `catalog role ${role}: ${Object.keys(d).filter((k) => d[k] === true).join(', ') || 'no tree powers'}` : `the catalog defines no role "${role}"`;
}
function treePowers(n) {
  const roles = (C.doc || {}).roles || {};
  const out = [];
  for (const [s, rs] of Object.entries(ownAccess(n))) {
    const p = ['move', 'place'].filter((k) => rs.some((r) => roles[r] && roles[r][k] === true));
    if (p.length) out.push({ s, p });
  }
  return out;
}
function localProblems() {
  const dangling = [], parents = [], orphans = [], cycles = [];
  for (const n of C.nodes.values()) {
    if (n.kind === 'item' && itemExists(n.name) === false) dangling.push(n.name);
    const ps = parentsOf(n);
    for (const p of ps) {
      const pn = nodeName(p.href);
      if (!pn) parents.push({ node: n.name, parent: p.href, why: 'not a folder of this catalog' });
      else if (!NODE_RE.test(pn)) parents.push({ node: n.name, parent: p.href, why: 'a placement cannot be a parent' });
      else if (!isLive(pn)) parents.push({ node: n.name, parent: p.href, why: 'missing or deleted' });
    }
    if (ps.length && !walkableParents(n).length) orphans.push(n.name);
  }
  // cycles: folders that reach themselves through parents
  cycles.push(...[...cyclicSet()].sort());
  return { dangling, parents, orphans, cycles };
}
/* localTree builds the listing from the documents: children ordered as §B.2 (ordered first, by code unit, then by name). */
function localTree() {
  const kids = new Map();
  for (const n of C.nodes.values()) {
    parentsOf(n).forEach((p) => {
      const pn = nodeName(p.href);
      if (!pn || !isLive(pn) || !NODE_RE.test(pn) || cyclicSet().has(pn) || cyclicSet().has(n.name)) return;
      (kids.get(pn) || kids.set(pn, []).get(pn)).push({ name: n.name, order: typeof p.order === 'string' ? p.order : undefined });
    });
  }
  const sortKids = (a, b) => (a.order !== undefined) !== (b.order !== undefined) ? (a.order !== undefined ? -1 : 1) : (a.order !== b.order ? cmpCU(a.order, b.order) : cmpCU(a.name, b.name));
  const build = (name, onPath, depth) => {
    const n = C.nodes.get(name);
    const e = { name, href: hrefOf(name), kind: n.kind, title: n.doc.title };
    if (n.kind === 'item') { const it = itemOf(name); e.item = it.href; const x = C.contentHeads[it.ns] && C.contentHeads[it.ns].get(it.name); if (x && x.kind === 'head') e.head = x.target; else if (itemExists(name) === false) e.dangling = 'item missing'; }
    if (n.kind === 'folder') {
      e.children = [];
      if (depth < 64 && !onPath.has(name)) {
        const next = new Set(onPath); next.add(name);
        for (const k of (kids.get(name) || []).sort(sortKids)) if (!next.has(k.name)) { const c = build(k.name, next, depth + 1); if (k.order !== undefined) c.order = k.order; e.children.push(c); }
      }
    }
    return e;
  };
  return [...C.nodes.values()].filter((n) => !parentsOf(n).length && !cyclicSet().has(n.name)).sort((a, b) => cmpCU(a.name, b.name)).map((n) => build(n.name, new Set(), 0));
}

/* ---- rendering ---- */
function renderCatStatus() {
  const box = $('catStatus');
  if (!C.ns) { box.className = 'muted'; box.textContent = 'Load a catalog namespace.'; return; }
  if (C.loading) { box.className = 'muted'; box.textContent = `Loading ${C.ns}…`; return; }
  box.className = '';
  if (!C.head) { box.replaceChildren(h('div', { class: 'errbox' }, C.note || 'not loaded')); return; }
  const kv = h('dl', { class: 'kv' },
    h('dt', {}, 'source'), h('dd', {}, C.source === 'tree' ? h('span', { class: 'badge ok' }, 'tree service via /playground/tree/') : h('span', { class: 'badge warn' }, 'core documents only')),
    h('dt', {}, 'catalog ns_id'), h('dd', {}, idEl(C.head), h('span', { class: 'muted small' }, ' the catalog namespace head (what catalog grants carry as at, §B.11.4)')),
    C.at ? h('dt', {}, 'listing at') : null, C.at ? h('dd', {}, idEl(C.at), h('span', { class: 'muted small' }, ' combined checkpoint over the catalog and ' + (C.trust.join(', ') || 'no') + ' (§B.5); listings at an at never change')) : null,
    C.view ? h('dt', {}, 'listing URL') : null, C.view ? h('dd', { class: 'mono small' }, C.view, C.sealedView ? h('span', { class: 'badge tomb', title: 'served as one JWE, pl { ns, view } (§E.2.6)' }, 'sealed listing') : null) : null,
    C.treeStatus ? h('dt', {}, 'service status') : null, C.treeStatus ? h('dd', {}, h('details', {}, h('summary', { class: 'muted small' }, 'GET /_status: followed namespaces, encryption, skipped'), jsonPre(C.treeStatus))) : null,
    C.min.length ? h('dt', {}, 'read-your-writes') : null, C.min.length ? h('dd', { class: 'mono small' }, C.min.map((m) => '?min=' + m).join(' ')) : null,
    h('dt', {}, 'trust'), h('dd', { class: 'mono' }, C.trust.join(', ') || '(none: catalog.trust is empty)'),
    h('dt', {}, 'mode'), h('dd', {}, C.mode + (C.mode === 'tree' ? ' (one parent per node)' : ' (several parents allowed)')),
    h('dt', {}, 'nodes'), h('dd', {}, `${[...C.nodes.values()].filter((n) => n.kind === 'folder').length} folder(s), ${[...C.nodes.values()].filter((n) => n.kind === 'item').length} placement(s)`));
  const roles = (C.doc || {}).roles;
  if (roles) kv.append(h('dt', {}, 'catalog roles'), h('dd', {}, ...Object.keys(roles).map((r) => h('span', { class: 'badge', title: roleInfo(r) }, r + (Object.keys(roles[r]).filter((k) => roles[r][k] === true).length ? ': ' + Object.keys(roles[r]).filter((k) => roles[r][k] === true).join('+') : '')))));
  box.replaceChildren(kv, C.note ? h('p', { class: 'note' }, C.note) : '');
}

function accessChips(name, itemNs) {
  const eff = effectiveAccess(name);
  const own = ownAccess(C.nodes.get(name));
  const chips = [];
  for (const s of Object.keys(eff).sort()) for (const role of Object.keys(eff[s]).sort()) {
    const where = [...eff[s][role]];
    chips.push(h('span', { class: 'badge info chip' + ((own[s] || []).includes(role) ? ' own' : ''), title: `${roleInfo(role, itemNs)}\nassigned on: ${where.join(', ')}` }, `${s}: ${role}`));
  }
  return chips;
}

const titleOf = (name) => { const n = C.nodes.get(name); return (n && n.doc.title) || name; };

/* treeRow renders one listing entry. In a DAG a node is listed under each of its parents (the tree service's
 * subtree does that too): path is the chain of folders it is listed under here, and seen maps each folder
 * already expanded to where, so a shared folder's children are expanded once and folded elsewhere. */
function treeRow(e, path = [], seen = new Map()) {
  const n = C.nodes.get(e.name);
  const parent = path[path.length - 1];
  const others = n ? walkableParents(n).filter((p) => p !== parent) : [];
  const shared = n && walkableParents(n).length > 1;
  // A folder listed again under another parent: the tree service marks it "repeat" and leaves its
  // children out (§B.5); a listing built here has them, and is folded the same way.
  const repeat = e.kind === 'folder' && (e.repeat || seen.has(e.name));
  const kids = e.children && e.children.length ? e.children : repeat ? ((seen.kids && seen.kids.get(e.name)) || []) : [];
  const it = e.kind === 'item' ? itemOf(e.name) : null;
  const dangling = e.dangling || (it && itemExists(e.name) === false ? 'item missing' : '');
  const row = h('div', { class: 'cat-row' + (e.name === C.sel ? ' sel' : '') + (dangling ? ' dangling' : ''), tabindex: 0, role: 'button' },
    h('span', { class: 'cat-kind ' + e.kind }, e.kind === 'folder' ? 'dir' : 'item'),
    e.title ? h('b', {}, e.title) : null,
    it ? h('button', { class: 'link mono', title: 'open ' + it.href + ' in the Resource tab', onclick: (ev) => { ev.stopPropagation(); openItem(it.ns, it.name); } }, it.href) : h('span', { class: 'mono muted' }, e.name),
    e.order !== undefined ? h('span', { class: 'muted small', title: 'order among siblings' }, '↕' + e.order) : null,
    e.head ? idEl(e.head) : null,
    dangling ? h('span', { class: 'badge err', title: 'dangling (' + dangling + '): drops out of listings and access (§B.7)' + (e.unlisted ? '; shown here from /problems, not in the service listing' : '') }, 'dangling') : null,
    e.self ? h('span', { class: 'badge' }, 'self-placed') : null,
    shared ? h('span', { class: 'badge info', title: `${walkableParents(n).length} parents (a DAG node, §B.2): listed under each of them` }, 'shared') : null,
    shared && others.length ? h('span', { class: 'muted small', title: others.join(', ') }, 'also in ' + others.map(titleOf).join(', ')) : null,
    e._sealedErr ? h('span', { class: 'badge tomb', title: e._sealedErr }, 'sealed') : e._opened ? h('span', { class: 'badge ok', title: 'decrypted with ' + e._opened }, 'decrypted') : null,
    n && n.doc.$access && n.doc.$access.inherit === false ? h('span', { class: 'badge warn', title: 'inherit: false stops the ancestor walk here' }, 'no inherit') : null,
    !n ? h('span', { class: 'badge warn', title: 'the tree service lists it, but its document was not read' }, 'no doc') : null,
    n ? accessChips(e.name, it && it.ns) : null,
    n ? treePowers(n).map((x) => h('span', { class: 'badge', title: 'tree powers of ' + x.s + ' here (not inherited)' }, `${x.s}: ${x.p.join('+')}`)) : null,
    e.more ? h('span', { class: 'muted small' }, '… deeper levels not listed') : null);
  row.onclick = () => selectNode(e.name);
  row.onkeydown = (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); selectNode(e.name); } };
  const li = h('li', {}, row);
  if (kids.length) {
    const here = [...path, e.name];
    if (repeat) {
      // Listed again under another parent: fold its children, which are expanded where it was first listed.
      const first = seen.get(e.name);
      const d = h('details', {}, h('summary', { class: 'muted small' }, `${kids.length} child(ren), expanded where first listed${first ? ', under ' + (first.map(titleOf).join(' / ') || 'a root') : ''}`));
      d.addEventListener('toggle', () => { if (d.open && d.children.length === 1) d.append(h('ul', {}, ...kids.map((c) => treeRow(c, here, seen)))); });
      li.append(d);
    } else {
      if (e.kind === 'folder') {
        seen.set(e.name, path);
        (seen.kids || (seen.kids = new Map())).set(e.name, kids);
      }
      li.append(h('ul', {}, ...kids.map((c) => treeRow(c, here, seen))));
    }
  } else if (e.repeat) {
    li.append(h('div', { class: 'muted small' }, 'listed again: expanded where first listed'));
  }
  return li;
}

/* cycleNote lists the folders on cycles, which no listing traverses (§B.5). */
function cycleNote() {
  const svc = C.source === 'tree' && C.problems && C.problems.body;
  const groups = svc ? (C.problems.body.cycles || []).map((c) => [].concat(c).map((x) => nodeName(x) || x)) : (cyclicSet().size ? [[...cyclicSet()].sort()] : []);
  if (!groups.length) return null;
  return h('p', { class: 'note' }, h('span', { class: 'badge err' }, 'cycle'), ' not traversed: ',
    ...groups.map((g, i) => [i ? '; ' : '', ...g.map((x, j) => [j ? ' ⇄ ' : '', h('button', { class: 'link mono', onclick: () => selectNode(x) }, x)])]),
    h('span', { class: 'muted small' }, svc ? ' (flagged by the tree service: every edge inside a cycle is excluded, so these folders and anything only below them are listed under Problems, not here)' : ' (computed here: every edge inside a cycle is excluded from walks)'));
}

function renderCatalog() {
  renderCatStatus();
  const box = $('catTree');
  const trees = C.source === 'tree' && C.listing ? C.listing : localTree();
  $('catTreeMeta').textContent = C.head ? (C.source === 'tree' ? `tree service listing at ${short(C.at)}` : `built here from the documents at ns_id ${short(C.head)}`) : '';
  const seen = new Map();
  box.replaceChildren(trees.length ? h('ul', { class: 'cat-tree' }, ...trees.map((e) => treeRow(e, [], seen))) : h('p', { class: 'muted' }, C.head ? 'No nodes yet: create a folder.' : '—'));
  const cn = C.head ? cycleNote() : null;
  if (cn) box.append(cn);
  // folder pickers and item suggestions
  const folders = [...C.nodes.values()].filter((n) => n.kind === 'folder').map((n) => n.name).sort();
  const opt = (f) => h('option', { value: f }, (C.nodes.get(f).doc.title ? C.nodes.get(f).doc.title + ' — ' : '') + f);
  for (const id of ['catFParent', 'catPParent']) {
    const sel = $(id), cur = sel.value;
    sel.replaceChildren(...(id === 'catFParent' ? [h('option', { value: '' }, '(none: a new root)')] : []), ...folders.map(opt));
    if (folders.includes(cur) || cur === '') sel.value = cur; else if (id === 'catFParent' && C.sel && folders.includes(C.sel)) sel.value = C.sel;
  }
  const items = [];
  for (const t of Object.keys(C.contentHeads)) for (const [name, x] of C.contentHeads[t]) if (x.kind === 'head' && !C.nodes.has(`${t}.${name}`)) items.push(`/r/${t}/${name}`);
  $('catItemList').replaceChildren(...items.map((v) => h('option', { value: v })));
  renderCatPick();
  renderCatSel();
  renderCatProblems();
}

function renderCatProblems() {
  const box = $('catProblems');
  if (!C.head) { box.className = 'muted'; box.textContent = '—'; $('catProbMeta').textContent = ''; return; }
  box.className = '';
  const lp = localProblems();
  const line = (label, list, f) => list.length ? h('div', {}, h('b', {}, label + ': '), ...list.map((x, i) => [i ? ', ' : '', f(x)])) : null;
  const nodeLink = (name) => h('button', { class: 'link mono', onclick: () => selectNode(name) }, name);
  const parts = [];
  if (C.problems && C.problems.service && C.problems.body) {
    const p = C.problems.body;
    $('catProbMeta').textContent = 'from the tree service (/problems, /orphans)';
    parts.push(line('cycles', p.cycles || [], (c) => h('span', { class: 'mono' }, [].concat(c).map((x) => nodeName(x) || x).join(' → '))),
      line('dangling items', p.danglingItems || [], (x) => [nodeLink(nodeName(x.href)), h('span', { class: 'muted small' }, ` (${x.reason || 'dangling'})`)]),
      line('dangling parents', p.danglingParents || [], (x) => [nodeLink(nodeName(x.href)), h('span', { class: 'muted small' }, ` → ${x.parent || ''} ${x.state || ''}`)]),
      line('too deep', p.tooDeep || [], (x) => nodeLink(nodeName(x.href))),
      line('orphans', C.problems.orphans || [], (x) => nodeLink(x.name)));
  } else {
    $('catProbMeta').textContent = 'computed here from the documents';
    parts.push(line('cycles', lp.cycles, nodeLink), line('dangling items', lp.dangling, nodeLink),
      line('dangling parents', lp.parents, (x) => [nodeLink(x.node), h('span', { class: 'muted small' }, ` → ${x.parent} (${x.why})`)]),
      line('orphans', lp.orphans, nodeLink));
  }
  const shown = parts.filter(Boolean);
  box.replaceChildren(...(shown.length ? shown : [h('span', { class: 'muted' }, 'No problems.')]));
}

function breadcrumbs(name) {
  const paths = [];
  const walk = (nm, acc, depth) => {
    const n = C.nodes.get(nm);
    if (!n || acc.includes(nm) || depth > 64 || paths.length > 20) return;
    const next = [nm, ...acc];
    const ps = walkableParents(n);
    if (!parentsOf(n).length) paths.push(next); else ps.forEach((p) => walk(p, next, depth + 1));
  };
  walk(name, [], 0);
  return paths;
}

function renderCatSel() {
  const box = $('catSel');
  const n = C.nodes.get(C.sel);
  $('catSelMeta').textContent = n ? n.kind : '';
  const moveTo = $('catMoveTo');
  moveTo.multiple = C.mode === 'dag';
  moveTo.size = C.mode === 'dag' ? 5 : 1;
  if (!n) { box.className = 'muted'; box.textContent = C.sel ? `${C.sel} is not a live node.` : 'Select a node in the tree.'; moveTo.replaceChildren(); return; }
  box.className = '';
  // folders it may move under: not itself, not a descendant (that would close a cycle)
  const below = new Set([n.name]);
  let grew = true;
  while (grew) { grew = false; for (const m of C.nodes.values()) if (!below.has(m.name) && walkableParents(m).some((p) => below.has(p))) { below.add(m.name); grew = true; } }
  const cur = new Set(parentsOf(n).map((p) => nodeName(p.href)));
  moveTo.replaceChildren(...[...C.nodes.values()].filter((m) => m.kind === 'folder' && !below.has(m.name)).map((m) => m.name).sort()
    .map((f) => h('option', { value: f, selected: cur.has(f) }, (C.nodes.get(f).doc.title ? C.nodes.get(f).doc.title + ' — ' : '') + f)));
  const p0 = parentsOf(n)[0];
  $('catMoveOrder').value = p0 && typeof p0.order === 'string' ? p0.order : '';
  const it = itemOf(n.name);
  const crumbs = breadcrumbs(n.name);
  box.replaceChildren(
    h('div', { class: 'state-line' }, h('span', { class: 'cat-kind ' + n.kind }, n.kind === 'folder' ? 'dir' : 'item'), h('b', { class: 'mono' }, n.name), h('span', { class: 'muted' }, 'head'), idEl(n.head)),
    h('dl', { class: 'kv' },
      it ? h('dt', {}, 'item') : null, it ? h('dd', {}, h('button', { class: 'link mono', onclick: () => openItem(it.ns, it.name) }, it.href),
        itemExists(n.name) === false ? h('span', { class: 'badge err' }, 'dangling') : itemExists(n.name) === null ? h('span', { class: 'badge warn', title: 'the item namespace is not in catalog.trust or not readable' }, 'unknown') : null) : null,
      h('dt', {}, 'paths'), h('dd', {}, crumbs.length ? h('div', {}, ...crumbs.map((p) => pathRow(p, it && it.ns)),
        crumbs.length > 1 ? h('div', { class: 'note' }, `${crumbs.length} paths to a root: the effective roles below are the union of what each path collects (§B.11.2).`) : null)
        : h('span', { class: 'muted' }, cyclicSet().has(n.name) ? 'none: on a cycle, which walks never pass (§B.5)' : 'none: an orphan or a root')),
      h('dt', {}, 'effective'), h('dd', {}, ...accessChips(n.name, it && it.ns), (it && itemExists(n.name) === false) ? h('div', { class: 'note' }, 'A dangling placement grants nothing, except create for an item that never existed (§B.11.4).') : null)),
    h('div', { class: 'row' },
      h('button', { class: 'tiny', onclick: () => openItem(C.ns, n.name) }, 'Open node in Resource tab'),
      it ? h('button', { class: 'tiny', onclick: () => openItem(it.ns, it.name) }, 'Open item') : null,
      C.proxy && C.source === 'tree' ? h('button', { class: 'tiny', onclick: () => showWhere(n) }, it ? 'where? (tree service)' : 'ancestors (tree service)') : null),
    h('div', { id: 'catWhere' }),
    jsonPre(n.doc));
}

/* pathAccess collects $access along one path (root … node), from the node up, stopping after a node with
 * inherit: false (§B.11.2). */
function pathAccess(path) {
  const grants = []; let stop = '';
  for (let i = path.length - 1; i >= 0; i--) {
    const n = C.nodes.get(path[i]);
    for (const [s, roles] of Object.entries(ownAccess(n))) for (const role of roles) grants.push({ s, role, at: path[i] });
    if (!inherits(n)) { if (i > 0) stop = path[i]; break; }
  }
  return { grants, stop };
}
function pathRow(path, itemNs) {
  const { grants, stop } = pathAccess(path);
  const by = new Map();
  for (const g of grants) { const k = `${g.s}: ${g.role}`; (by.get(k) || by.set(k, { g, at: [] }).get(k)).at.push(g.at); }
  return h('div', { class: 'cat-path' },
    h('span', { class: 'mono small' }, path.map(titleOf).join(' / ')),
    ...[...by.keys()].sort().map((k) => h('span', { class: 'badge info chip', title: `${roleInfo(by.get(k).g.role, itemNs)}
assigned on: ${by.get(k).at.join(', ')}` }, k)),
    !by.size ? h('span', { class: 'muted small' }, 'no roles along this path') : null,
    stop ? h('span', { class: 'badge warn', title: `${stop} has inherit: false: nothing above it counts on this path` }, 'stops at ' + titleOf(stop)) : null);
}

async function showWhere(n) {
  const it = itemOf(n.name);
  const r = await asUser(() => treeGet(it ? `where?item=${encodeURIComponent(it.href)}` : `ancestors?of=${encodeURIComponent(hrefOf(n.name))}`));
  const box = document.getElementById('catWhere');
  if (box) box.replaceChildren(r.body ? jsonPre(r.body) : h('div', { class: 'errbox' }, 'HTTP ' + r.r.status));
}

function selectNode(name) { C.sel = name; renderCatalog(); }

function openItem(ns, name) {
  asUser(async () => { if (S.ns !== ns) await selectNS(ns); await selectRes(name); });
  showTab('res');
}

/* ---- writes (to the catalog namespace, through the core API) ---- */
function commonSchema(kind) {
  const counts = {};
  for (const n of C.nodes.values()) if (n.kind === kind && typeof n.doc.$schema === 'string') counts[n.doc.$schema] = (counts[n.doc.$schema] || 0) + 1;
  return Object.keys(counts).sort((a, b) => counts[b] - counts[a])[0] || '';
}
function parseAccessField(id) {
  const t = $(id).value.trim();
  if (!t) return { ok: true };
  const p = tryParse(t);
  if (!p.ok || !p.v || typeof p.v !== 'object' || Array.isArray(p.v)) return { ok: false };
  return { ok: true, v: p.v };
}
async function catWrite(what, method, name, o) {
  const r = await api(method, `/r/${C.ns}/${name}`, Object.assign({ label: 'catalog' }, o));
  const out = $('catOut');
  out.className = '';
  out.replaceChildren(
    h('div', { class: 'state-line' }, h('b', {}, what), h('span', { class: 'mono' }, `${method} /r/${C.ns}/${name}`), h('span', { class: 'badge ' + (r.ok ? 'ok' : 'err') }, r.neterr ? 'network error' : `HTTP ${r.status}`),
      r.hdr('X-Namespace-Revision') ? h('span', { class: 'muted small' }, 'catalog ns_id ') : null, r.hdr('X-Namespace-Revision') ? idEl(r.hdr('X-Namespace-Revision')) : null),
    h('div', { class: 'split' },
      h('div', {}, h('h3', {}, 'Request'), h('div', { class: 'mono small' }, Object.entries(o.headers || {}).map(([k, v]) => `${k}: ${v}`).join('  ')), o.body !== undefined ? jsonPre(typeof o.body === 'string' ? pretty(o.body) : o.body) : h('span', { class: 'muted small' }, '(no body)')),
      h('div', {}, h('h3', {}, 'Response'), r.json && !r.ok ? errBox(r.entry) : null, jsonPre(r.text ? pretty(r.text) : (r.neterr || '(empty)')))));
  // The write's X-Namespace-Revision is in WRITES (noteWrite): relisting adds it as ?min= (treeMins).
  if (r.ok) await loadCatalog();
  return r;
}

async function catCreateFolder() {
  if (!C.head) return toast('Load a catalog first');
  const name = $('catFName').value.trim();
  if (!NODE_RE.test(name)) return toast('A folder name has no dot: [a-z0-9][a-z0-9_-]*');
  const acc = parseAccessField('catFAccess');
  if (!acc.ok) return toast('$access must be a JSON object');
  const doc = {};
  const schema = commonSchema('folder');
  if (schema) doc.$schema = schema;
  if ($('catFTitle').value.trim()) doc.title = $('catFTitle').value.trim();
  const parent = $('catFParent').value;
  if (parent) { const p = { href: hrefOf(parent) }; if ($('catFOrder').value.trim()) p.order = $('catFOrder').value.trim(); doc.parents = [p]; }
  if (acc.v) doc.$access = acc.v;
  const r = await catWrite('New folder', 'PATCH', name, { ct: PJ, headers: { 'If-None-Match': '*' }, body: [{ op: 'add', path: '', value: doc }] });
  if (r.ok) { C.sel = name; $('catFName').value = ''; renderCatalog(); }
}

async function catPlace() {
  if (!C.head) return toast('Load a catalog first');
  const t = $('catPItem').value.trim();
  const m = /^(?:\/r\/)?([a-z0-9][a-z0-9_-]*)[/.]([a-z0-9][a-z0-9._-]*)$/.exec(t);
  if (!m) return toast('Item: /r/{ns}/{name}');
  if (m[1] === C.ns) return toast('Items are content documents, not nodes of this catalog');
  if (C.trust.length && !C.trust.includes(m[1])) toast(`${m[1]} is not in catalog.trust; the catalog's rules may refuse it`);
  const parent = $('catPParent').value;
  if (!parent) return toast('Pick a folder');
  const acc = parseAccessField('catPAccess');
  if (!acc.ok) return toast('$access must be a JSON object');
  const p = { href: hrefOf(parent) };
  if ($('catPOrder').value.trim()) p.order = $('catPOrder').value.trim();
  const doc = {};
  const schema = commonSchema('item');
  if (schema) doc.$schema = schema;
  doc.parents = [p];
  if (acc.v) doc.$access = acc.v;
  doc.$nonce = Z.newNonce();
  const name = `${m[1]}.${m[2]}`;
  const r = await catWrite('Place', 'PATCH', name, { ct: PJ, headers: { 'If-None-Match': '*' }, body: [{ op: 'add', path: '', value: doc }] });
  if (r.ok) { C.sel = name; $('catPItem').value = ''; renderCatalog(); }
}

async function catMove() {
  const n = C.nodes.get(C.sel);
  if (!n) return toast('Select a node first');
  const to = [...$('catMoveTo').selectedOptions].map((o) => o.value);
  if (!to.length) return toast('Pick the new parent folder');
  const order = $('catMoveOrder').value.trim();
  if (order && !/^[0-9A-Za-z]{1,64}$/.test(order)) return toast('An order key is [0-9A-Za-z]{1,64}');
  const cur = parentsOf(n);
  const curNames = cur.map((p) => nodeName(p.href));
  let ops;
  if (to.length === 1 && curNames.length === 1 && curNames[0] === to[0]) {
    // Reorder: only the order key of the existing edge changes (§B.2).
    if ((cur[0].order || '') === order) return toast('Nothing to change');
    ops = order ? [{ op: cur[0].order !== undefined ? 'replace' : 'add', path: '/parents/0/order', value: order }] : [{ op: 'remove', path: '/parents/0/order' }];
  } else {
    const parents = to.map((f) => {
      const keep = cur.find((p) => nodeName(p.href) === f);
      const e = { href: hrefOf(f) };
      if (order && (to.length === 1 || !keep)) e.order = order; else if (keep && keep.order !== undefined) e.order = keep.order;
      return e;
    });
    ops = [{ op: Array.isArray(n.doc.parents) ? 'replace' : 'add', path: '/parents', value: parents }];
  }
  await catWrite('Move', 'PATCH', n.name, { ct: PJ, headers: { 'If-Match': quoteId(n.head) }, body: ops });
}

async function catRemove() {
  const n = C.nodes.get(C.sel);
  if (!n) return toast('Select a node first');
  const kids = [...C.nodes.values()].filter((m) => walkableParents(m).includes(n.name)).length;
  const msg = n.kind === 'folder'
    ? `Delete folder ${n.name}?` + (kids ? `\n\nIts ${kids} child node(s) are not deleted: they become orphans (§B.7).` : '')
    : `Remove ${itemOf(n.name).href} from the catalog ${C.ns}?\n\nThe content document is unaffected.`;
  if (!confirm(msg)) return;
  const r = await catWrite('Remove', 'DELETE', n.name, { headers: { 'If-Match': quoteId(n.head) } });
  if (r.ok) { C.sel = ''; renderCatalog(); }
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
 * search (Addendum A): the index service through the core's proxy
 * ------------------------------------------------------------------ */
const INDEX = '/playground/index';
const SR = {
  proxy: null, status: null, indexed: [], // the proxy exists (-index-url); GET /_status of the index
  ns: '', info: null, q: null, next: '', at: '', view: '', hits: [], counts: null, state: '', note: '', busy: false, gen: 0,
};

/* probeIndex asks the core whether it proxies a search index (-index-url), and what the index follows (/_status). */
async function probeIndex() {
  const p = await api('GET', `${INDEX}/`, { auto: true, label: 'index' });
  SR.proxy = p.status === 200 && !!p.json && p.json.proxy === 'index';
  SR.status = null; SR.indexed = [];
  if (!SR.proxy) return;
  const st = await api('GET', `${INDEX}/_status`, { auto: true, label: 'index' });
  if (st.status === 200 && st.json && Array.isArray(st.json.namespaces)) {
    SR.status = st.json.namespaces.filter((n) => n && typeof n.ns === 'string');
    SR.indexed = SR.status.map((n) => n.ns);
  }
}

function srStatusOf(ns) { return (SR.status || []).find((n) => n.ns === ns) || null; }

function renderSrPick() {
  const sel = $('srPick');
  const list = SR.indexed.slice().sort(cmpCU);
  sel.replaceChildren(h('option', { value: '' }, SR.proxy === null ? 'finding namespaces…' : SR.proxy === false ? '— no index configured —' : list.length ? '— pick —' : '— none reported —'),
    ...list.map((n) => {
      const st = srStatusOf(n);
      const tag = st && st.skipped ? ' (skipped)' : st && st.sealed ? ' (sealed)' : '';
      return h('option', { value: n, selected: n === SR.ns }, n + tag);
    }));
  $('srNsList').replaceChildren(...[...new Set([...list, ...known])].map((v) => h('option', { value: v })));
}

/* The last write this browser made to each namespace (X-Namespace-Revision), for ?min= (§A.5). */
function renderSrRyw() {
  const ns = ($('srNs').value || '').trim();
  const w = WRITES.get(ns);
  $('srRyw').disabled = !w;
  $('srRywInfo').replaceChildren(w
    ? h('span', {}, `your last write in ${ns}: `, idEl(w.id), h('span', { class: 'muted small' }, ' ' + w.at.toTimeString().slice(0, 8)))
    : h('span', { class: 'muted small' }, ns ? `no write to ${ns} made in this page yet: write something in the Resource tab` : 'pick a namespace'));
}

/* srFilters turns the filter lines into query parameters: raw (facet[/league]=cup, ge[/kickoff]=2026-10-10)
 * or short (/league=cup, /kickoff>=2026-10-10). */
function srFilters(text) {
  const out = [], ops = { '>=': 'ge', '>': 'gt', '<=': 'le', '<': 'lt', '=': 'facet' };
  for (const line of text.split('\n').map((l) => l.trim()).filter(Boolean)) {
    const m = /^(\/[^=<>]*)(>=|<=|>|<|=)(.*)$/.exec(line);
    if (m) { out.push([`${ops[m[2]]}[${m[1]}]`, m[3].trim()]); continue; }
    const i = line.indexOf('=');
    if (i > 0) out.push([line.slice(0, i).trim(), line.slice(i + 1).trim()]);
    else throw new Error(`filter "${line}": want /path=value, /path>=value or facet[/path]=value`);
  }
  return out;
}

function srParams(ns) {
  const p = new URLSearchParams();
  const q = $('srQ').value.trim();
  if (q) p.set('q', q);
  if ($('srSchema').value.trim()) p.set('schema', $('srSchema').value.trim());
  for (const [k, v] of srFilters($('srFilters').value)) p.append(k, v);
  for (const s of $('srSort').value.split(',').map((x) => x.trim()).filter(Boolean)) p.append('sort', s);
  for (const c of $('srCounts').value.split(',').map((x) => x.trim()).filter(Boolean)) p.append('counts', c);
  if ($('srLimit').value.trim()) p.set('limit', $('srLimit').value.trim());
  const w = WRITES.get(ns);
  if ($('srRyw').checked && w) p.set('min', w.id);
  return p;
}

function srMessage(kind, ...kids) {
  $('srResults').className = '';
  $('srResults').replaceChildren(h('div', { class: kind === 'info' ? 'note' : 'errbox' }, ...kids));
  $('srMore').hidden = true; $('srCountsOut').replaceChildren(); $('srMeta').textContent = '';
}

/* srGet fetches one result through the proxy, following the checkpoint redirect (fetch does), retrying while the
 * index is behind ?min (503), and opening sealed results (§E.2.6): the whole JWE, then per-hit "sealed" values. */
async function srGet(path, ns) {
  let r;
  for (let i = 0; i < 4; i++) {
    r = await api('GET', path, { label: 'search' });
    if (r.status !== 503 || !(r.json && r.json.code === 'behind')) break;
    await sleep(800);
  }
  if (r.status !== 200) return { r };
  const view = r.finalPath.startsWith(INDEX + '/') ? r.finalPath.slice(INDEX.length) : r.finalPath;
  let body = r.json;
  if (r.jose) {
    let pl = {};
    try { pl = Z.parseJWE(r.text.trim()).header.pl || {}; } catch (_) { /* reported by decrypted */ }
    const d = await decrypted(r, pl.ns || ns, '', { ns: pl.ns || ns, view });
    if (d.error) return { r, view, sealedWhole: d };
    body = d.value;
  }
  if (body && typeof body === 'object') await openSealedEntries(body, view);
  return { r, view, body };
}

/* runSearch queries the namespace in the page's fields, or fetches the next page of the last result. */
async function runSearch(more) {
  if (SR.busy) return;
  if (SR.proxy === null) await probeIndex();
  renderSrPick();
  if (!SR.proxy) return renderSearch();
  const ns = more ? SR.ns : $('srNs').value.trim();
  if (!more) store.set('pl.srNs', ns);
  if (!ns) return toast('Pick a namespace');
  if (!NODE_RE.test(ns)) return toast('Not a namespace name');
  let path;
  if (more) path = INDEX + SR.next;
  else {
    let p;
    try { p = srParams(ns); } catch (err) { return srMessage('err', err.message); }
    path = `${INDEX}/${ns}` + (p.toString() ? '?' + p : '');
  }
  const gen = ++SR.gen;
  SR.busy = true; $('srGo').disabled = true;
  $('srStatus').textContent = `Searching ${ns}…`;
  try {
    if (!more) {
      SR.ns = ns; SR.info = await nsInfo(ns);
      renderSrRyw();
      if (SR.info.level === 'e2e') {
        SR.hits = []; SR.next = ''; SR.at = ''; SR.view = '';
        $('srStatus').textContent = '';
        return srMessage('info', `${ns} is an end-to-end encrypted (E3) namespace: the server holds only ciphertext, so an index service cannot read its documents and there is nothing to search here (§E.3). Search it by opening its resources, or index it in a client that holds the keys.`);
      }
    }
    const res = await srGet(path, ns);
    if (gen !== SR.gen) return;
    $('srStatus').textContent = '';
    const r = res.r;
    if (!res.body) {
      const st = srStatusOf(ns);
      const why = res.sealedWhole ? 'The index answered with a sealed result this browser has no key for: ' + res.sealedWhole.error
        : r.neterr ? 'Network error: ' + r.neterr
          : r.status === 502 ? 'The search index is not reachable through the proxy (502): it may still be starting.'
            : r.status === 404 ? `The index does not serve a namespace named ${ns} (404): it follows ${SR.indexed.length ? SR.indexed.join(', ') : 'only what its -ns flag lists'}.`
              : r.status === 401 || r.status === 403 ? `The index refused the read (${r.status}): ${ns} is not public; put a read grant in the connection bar's bearer field.`
                : r.status === 503 && r.json && r.json.code === 'skipped' ? `The index does not consume ${ns}: ${r.json.message || (st && st.reason) || ''}`
                  : r.status === 503 ? `The index has not reached ${ns} yet (503 ${(r.json && r.json.code) || ''}): ${(r.json && r.json.message) || ''}`
                    : `The index answered ${r.status}${r.json && r.json.code ? ' ' + r.json.code : ''}${r.json && r.json.message ? ': ' + r.json.message : ''}`;
      return srMessage('err', why);
    }
    const b = res.body;
    SR.at = b.at || ''; SR.view = res.view; SR.next = typeof b.next === 'string' ? b.next : '';
    SR.hits = more ? SR.hits.concat(b.hits || []) : (b.hits || []);
    if (b.counts) SR.counts = b.counts; else if (!more) SR.counts = null;
    SR.sealedView = r.jose; SR.perEntry = !r.jose && SR.hits.some((x) => x && x._opened);
    SR.state = 'ok'; SR.rev = r.hdr('X-Namespace-Revision') || ''; SR.min = new URLSearchParams(path.split('?')[1] || '').get('min') || '';
    renderSearch();
  } finally {
    SR.busy = false; $('srGo').disabled = false;
  }
}

function srAddFilter(path, value) {
  const line = `${path}=${typeof value === 'string' ? value : JSON.stringify(value)}`;
  const t = $('srFilters');
  if (!t.value.split('\n').map((l) => l.trim()).includes(line)) t.value = (t.value.trim() ? t.value.trim() + '\n' : '') + line;
  $('srMoreBox').open = true;
  asUser(() => runSearch(false));
}

function renderSearch() {
  const res = $('srResults');
  if (SR.proxy === false) {
    $('srStatus').replaceChildren();
    return srMessage('info', 'Search needs the index service (Addendum A). Start the core with -index-url (compose does) to read it through the same-origin proxy at /playground/index/. Without it there is nothing to query: the core has no search of its own.');
  }
  if (SR.state !== 'ok') return;
  const st = srStatusOf(SR.ns);
  $('srStatus').replaceChildren(h('dl', { class: 'kv' },
    h('dt', {}, 'index checkpoint'), h('dd', {}, idEl(SR.at), h('span', { class: 'muted small' }, ' the result is immutable at this ns_id (§A.4): the index redirected the query to it')),
    h('dt', {}, 'result URL'), h('dd', { class: 'mono small' }, SR.view,
      SR.sealedView ? h('span', { class: 'badge tomb', title: 'served as one JWE, pl { ns, view } (§E.2.6)' }, 'sealed result') : null,
      SR.perEntry ? h('span', { class: 'badge tomb', title: 'each hit sealed under its resource key, pl { ns, name, view } (§E.2.6)' }, 'sealed per hit') : null),
    SR.min ? h('dt', {}, 'read-your-writes') : null, SR.min ? h('dd', { class: 'mono small' }, '?min=' + SR.min + ' (waited until the index had applied it)') : null,
    st ? h('dt', {}, 'namespace') : null, st ? h('dd', {}, h('span', { class: 'badge' }, st.level || 'plain'), st.epoch ? h('span', { class: 'muted small' }, ' epoch ' + st.epoch) : null, st.skipped ? h('span', { class: 'badge warn' }, 'skipped: ' + (st.reason || '')) : null) : null));
  $('srMeta').textContent = `${SR.hits.length} hit(s)${SR.next ? ', more available' : ''}`;
  if (!SR.hits.length) {
    res.className = 'muted';
    res.textContent = 'No hits. Plain listings show untyped documents too; text, facet and sort queries only match documents whose $schema marks fields with x-index.';
  } else {
    res.className = '';
    const rows = SR.hits.map((x) => {
      const facets = Object.keys(x).filter((k) => k.startsWith('/')).sort();
      return h('tr', {},
        h('td', {}, h('button', { class: 'link mono', title: `open ${SR.ns}/${x.resource} in the Resource tab`, onclick: () => openItem(SR.ns, x.resource) }, x.resource)),
        h('td', { class: 'mono small' }, x.schema ? x.schema.replace(/^\/r\//, '').replace(/\/rev\/(1[a-z2-7]{32})$/, (m, id) => ' @' + short(id)) : (x._sealedErr ? '' : h('span', { class: 'muted' }, 'untyped'))),
        h('td', { class: 'mono small' }, typeof x.score === 'number' ? x.score.toFixed(3) : ''),
        h('td', {}, facets.map((p) => (Array.isArray(x[p]) ? x[p] : [x[p]]).map((v) => h('button', { class: 'badge info chip', title: `filter on ${p} = ${v}`, onclick: () => srAddFilter(p, v) }, `${p}: ${v}`)))),
        h('td', { class: 'mono small' }, x.id ? idEl(x.id) : ''),
        h('td', {}, x.sealed && !x._opened ? h('span', { class: 'badge err', title: x._sealedErr || 'no key' }, 'sealed: ' + (x._sealedErr ? 'not opened' : 'no key')) : x._opened ? h('span', { class: 'badge ok', title: 'opened with ' + x._opened }, 'opened') : ''));
    });
    res.replaceChildren(h('div', { class: 'scroll' }, h('table', {}, h('thead', {}, h('tr', {}, ['resource', 'schema', 'score', 'facets', 'revision', ''].map((c) => h('th', {}, c)))), h('tbody', {}, rows))));
  }
  $('srMore').hidden = !SR.next;
  const counts = SR.counts && typeof SR.counts === 'object' ? Object.keys(SR.counts).sort() : [];
  $('srCountsOut').replaceChildren(...counts.map((p) => h('div', { class: 'chips' }, h('span', {}, 'counts ' + p + ':'),
    ...(SR.counts[p] || []).map((c) => h('button', { class: 'badge info chip', title: `filter on ${p} = ${c.value}`, onclick: () => srAddFilter(p, c.value) }, `${c.value} × ${c.count}`)))));
}

function initSearch() {
  $('srNs').value = store.get('pl.srNs', 'demo');
  $('srGo').onclick = () => asUser(() => runSearch(false));
  for (const id of ['srQ', 'srNs', 'srSchema', 'srSort', 'srCounts', 'srLimit']) $(id).onkeydown = (e) => { if (e.key === 'Enter') asUser(() => runSearch(false)); };
  $('srNs').oninput = renderSrRyw;
  $('srPick').onchange = () => { const v = $('srPick').value; if (v) { $('srNs').value = v; renderSrRyw(); asUser(() => runSearch(false)); } };
  $('srMore').onclick = () => asUser(() => runSearch(true));
  $('srRefresh').onclick = () => asUser(async () => { SR.proxy = null; await probeIndex(); renderSrPick(); renderSearch(); });
  document.querySelector('.tab[data-tab="sr"]').addEventListener('click', async () => {
    if (SR.proxy === null) { await probeIndex(); renderSrPick(); renderSearch(); }
    renderSrRyw();
  });
  renderSrRyw();
}

/* ------------------------------------------------------------------ *
 * schemas: import external JSON Schemas (§6.1)
 *
 * The core plans (fetch, convert, rewrite refs to pinned revision paths, predict ids) and writes nothing; this page
 * writes the plan through the normal API, as the user: the batches the plan carries, each atomic.
 * ------------------------------------------------------------------ */
const SI_URL = '/playground/schema-import/';
const SI = { probe: null, files: [], plan: null, stale: false, busy: false, imported: null, pasted: 0 };

async function probeSI() {
  const r = await api('GET', SI_URL, { auto: true, label: 'schema import' });
  SI.probe = r.status === 200 && r.json && r.json.proxy === 'schema-import' ? r.json : false;
  renderSIFetch();
}

function renderSIFetch() {
  const p = SI.probe, ta = $('siUrls'), note = $('siFetchNote');
  ta.disabled = p === null ? false : !(p && p.fetch);
  if (p === null) { note.textContent = 'Asking the core whether it fetches URLs…'; return; }
  if (!p) { note.textContent = 'The core has no schema import endpoint (this playground is served without it): nothing to plan with.'; $('siPlan').disabled = true; return; }
  $('siPlan').disabled = SI.busy;
  if (!p.fetch) { note.textContent = 'URL fetching is disabled on this server (serve -schema-fetch). Upload or paste schema files instead; $refs between them are resolved by file name.'; return; }
  note.textContent = p.hosts && p.hosts.length
    ? 'The core fetches URLs from these hosts only: ' + p.hosts.join(', ') + '.'
    : 'The core fetches URLs from public addresses only (private, loopback and link-local ones are refused).';
}

function renderSIPick() {
  const sel = $('siPick');
  const list = known.slice().sort(cmpCU);
  sel.replaceChildren(h('option', { value: '' }, list.length ? '— pick —' : '— add a namespace above —'),
    ...list.map((n) => h('option', { value: n, selected: n === $('siNs').value.trim() }, n)));
}

function siDirty() {
  if (SI.plan && !SI.stale) { SI.stale = true; renderSIStatus(); }
}

function renderSIFiles() {
  $('siFiles').replaceChildren(...SI.files.map((f, i) => h('span', { class: 'badge info chip', title: f.content.length + ' bytes' },
    f.name, h('button', { type: 'button', title: 'remove', 'aria-label': 'remove ' + f.name, onclick: () => { SI.files.splice(i, 1); renderSIFiles(); siDirty(); } }, '×'))));
}

function siAddFile(name, content) {
  name = String(name || '').trim();
  const at = SI.files.findIndex((f) => f.name === name);
  if (at >= 0) SI.files[at] = { name, content }; else SI.files.push({ name, content });
  renderSIFiles(); siDirty();
}

async function siReadFiles(list) {
  for (const f of Array.from(list || [])) {
    try { siAddFile(f.name, await f.text()); } catch (e) { toast('Could not read ' + f.name); }
  }
}

function siRequest() {
  const sources = $('siUrls').value.split(/\s+/).map((s) => s.trim()).filter(Boolean);
  const body = { ns: $('siNs').value.trim(), sources, files: SI.files };
  const name = $('siName').value.trim();
  if (name) body.name = name;
  return body;
}

function renderSIStatus(msg, cls) {
  const st = $('siStatus');
  if (msg !== undefined) { st.className = cls || 'muted'; st.textContent = msg; SI.msg = [msg, cls]; }
  else if (SI.stale) { st.className = 'muted'; st.textContent = 'The inputs changed since the plan: plan again.'; }
  $('siImport').disabled = SI.busy || !SI.plan || SI.stale || !SI.plan.changed || !!SI.imported;
  $('siPlan').disabled = SI.busy || SI.probe === false;
}

const siActionClass = { create: 'ok', append: 'info', restore: 'warn', unchanged: '' };
const siRoots = (plan) => (plan.entries || []).filter((e) => e.root);

async function siPlan() {
  if (SI.busy) return;
  const req = siRequest();
  if (!req.ns) return toast('Pick or type a namespace');
  if (!req.sources.length && !req.files.length) return toast('Give a URL or add a file');
  store.set('pl.siNs', req.ns);
  SI.busy = true; SI.imported = null; renderSIStatus('Planning…');
  const r = await api('POST', SI_URL + 'plan', { body: req, label: 'schema import' });
  SI.busy = false;
  if (!r.ok) {
    SI.plan = null; $('siPlanCard').hidden = true; $('siResultCard').hidden = true;
    const msg = r.neterr ? 'network error: ' + r.neterr : (r.json && r.json.message) || `HTTP ${r.status}${r.json && r.json.code ? ' ' + r.json.code : ''}`;
    renderSIStatus(msg, 'bad');
    return;
  }
  SI.plan = r.json; SI.stale = false;
  addKnown(req.ns); renderSIPick();
  renderSIPlan();
  const n = SI.plan.batches.reduce((a, b) => a + b.items.length, 0);
  renderSIStatus(SI.plan.changed ? `${n} resource${n === 1 ? '' : 's'} to write in ${SI.plan.batches.length} batch${SI.plan.batches.length === 1 ? '' : 'es'}.` : 'Nothing to write: every schema is unchanged.', SI.plan.changed ? 'good' : 'muted');
  if (!SI.plan.changed) renderSIResult();
  else $('siResultCard').hidden = true;
}

function renderSIPlan() {
  const p = SI.plan;
  $('siPlanCard').hidden = !p;
  if (!p) return;
  const notes = $('siNotes');
  notes.replaceChildren(
    ...(p.bundled || []).map((b) => h('div', { class: 'warn-box' }, 'These documents reference each other in a cycle and were merged into one resource (the others under $defs): ' + b.join(', '))),
    ...(p.warnings || []).map((w) => h('div', { class: 'warn-box' }, 'warning: ' + w)));
  const tb = $('siTbl').tBodies[0];
  tb.replaceChildren(...(p.entries || []).map((e) => h('tr', {},
    h('td', { class: 'mono wrap' }, e.source, e.root ? h('span', { class: 'badge info', style: 'margin-left:6px' }, 'root') : null),
    h('td', { class: 'mono' }, e.resource),
    h('td', {}, h('span', { class: 'badge ' + (siActionClass[e.action] || '') }, e.action)),
    h('td', { class: 'mono wrap' }, h('span', { class: 'id', title: 'click to copy', onclick: () => copy(e.path) }, e.path)),
    h('td', {}, h('button', { class: 'tiny', onclick: () => siView(e.resource) }, 'view')))));
  $('siPlanMeta').textContent = `${(p.resources || []).length} resource${(p.resources || []).length === 1 ? '' : 's'} in ${p.ns}`;
  $('siViewBox').hidden = true;
}

function siView(name) {
  const r = (SI.plan.resources || []).find((x) => x.name === name);
  if (!r) return;
  $('siViewBox').hidden = false;
  $('siViewName').textContent = `${r.name}  →  ${r.path}  (rewritten schema)`;
  setJSON($('siView'), r.content);
}

async function siImport() {
  const p = SI.plan;
  if (SI.busy || !p || !p.changed || SI.stale || SI.imported) return;
  SI.busy = true; renderSIStatus('Writing…');
  const mismatch = [];
  let done = 0, failed = null;
  await asUser(async () => {
    for (const b of p.batches) {
      const r = await api('POST', `/ns/${p.ns}/batch`, { label: 'schema import', body: { items: b.items } });
      if (r.status !== 201 && r.status !== 200) { failed = r; break; }
      const got = (r.json && r.json.items) || [];
      b.items.forEach((it, i) => {
        const id = got[i] && got[i].ids && got[i].ids[0];
        if (id !== b.ids[i]) mismatch.push({ resource: it.resource, want: b.ids[i], got: id || '(none)' });
      });
      done++;
    }
  });
  SI.busy = false;
  if (failed) {
    SI.stale = true;
    const j = failed.json;
    renderSIStatus((failed.neterr ? 'network error: ' + failed.neterr : `HTTP ${failed.status}${j && j.code ? ' ' + j.code : ''}${j && j.message ? ': ' + j.message : ''}`) +
      (done ? ` (${done} of ${p.batches.length} batches were written)` : ' (nothing was written)') + '. Plan again.', 'bad');
    if (failed.json && failed.entry) $('siStatus').append(errBox(failed.entry));
    return;
  }
  SI.imported = { mismatch };
  renderSIStatus(`Written: ${p.batches.reduce((a, b) => a + b.items.length, 0)} resource(s) in ${p.batches.length} batch(es).`, 'good');
  renderSIResult();
  if (p.ns === S.ns) await refreshNS();
}

function renderSIResult() {
  const p = SI.plan, box = $('siResult');
  $('siResultCard').hidden = !p;
  if (!p) return;
  const roots = siRoots(p);
  const kids = [];
  if (SI.imported && SI.imported.mismatch.length) {
    kids.push(h('div', { class: 'warn-box' }, 'The server assigned other revision ids than predicted, so references between these schemas may not point where intended: ',
      SI.imported.mismatch.map((m) => `${m.resource}: expected ${m.want}, got ${m.got}`).join('; ')));
  }
  roots.forEach((e, i) => {
    const docName = h('input', { class: 'mono', value: store.get('pl.siDoc', 'example'), spellcheck: 'false', autocomplete: 'off', 'aria-label': 'name of the new document', style: 'flex:0 1 180px' });
    kids.push(h('div', { class: 'row' },
      h('b', { class: 'mono' }, e.resource), h('span', { class: 'muted' }, '$schema'),
      h('code', { class: 'siPath', style: 'overflow-wrap:anywhere' }, e.path),
      h('button', { class: 'tiny', onclick: () => copy(e.path, '$schema path') }, 'Copy')));
    kids.push(h('div', { class: 'row' },
      h('label', {}, 'New document'), docName,
      h('button', { class: 'tiny primary', title: 'opens the Resource tab with a create patch that sets this $schema', onclick: () => { store.set('pl.siDoc', docName.value.trim()); siNewDoc(p.ns, docName.value.trim(), e.path); } }, 'Start in the Resource editor')));
  });
  kids.push(h('p', { class: 'note' }, 'A document that names this path in its $schema is validated against it when written (§6.2); the path is a revision, so it never changes under the document.'));
  box.replaceChildren(...kids);
  $('siResultMeta').textContent = SI.imported ? 'written' : 'already in place';
}

async function siNewDoc(ns, name, path) {
  if (!name) return toast('Name the new document');
  await asUser(async () => {
    if (!S.ns) await selectNS(ns); // documents usually live elsewhere than their schemas: keep the namespace in use
    await selectRes(name);
  });
  $('patch').value = fmtPatch([{ op: 'add', path: '', value: { $schema: path } }]);
  $('patch').dispatchEvent(new Event('input'));
  showTab('res');
  toast('Edit the patch, then Create');
}

function initSchemas() {
  $('siNs').value = store.get('pl.siNs', '');
  $('siPick').onchange = () => { const v = $('siPick').value; if (v) { $('siNs').value = v; siDirty(); } };
  $('siNs').oninput = siDirty; $('siUrls').oninput = siDirty; $('siName').oninput = siDirty;
  $('siFileIn').onchange = async () => { await siReadFiles($('siFileIn').files); $('siFileIn').value = ''; };
  const drop = $('siDrop');
  drop.ondragover = (e) => { e.preventDefault(); drop.classList.add('over'); };
  drop.ondragleave = () => drop.classList.remove('over');
  drop.ondrop = async (e) => { e.preventDefault(); drop.classList.remove('over'); await siReadFiles(e.dataTransfer && e.dataTransfer.files); };
  drop.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); $('siFileIn').click(); } };
  drop.onclick = () => $('siFileIn').click();
  $('siPasteAdd').onclick = () => {
    const text = $('siPaste').value;
    if (!text.trim()) return toast('Paste a schema first');
    const p = tryParse(text);
    if (!p.ok) return toast('Not valid JSON: ' + p.err);
    siAddFile($('siPasteName').value.trim() || `pasted-${++SI.pasted}.json`, text);
    $('siPaste').value = ''; $('siPasteName').value = '';
  };
  $('siPlan').onclick = () => asUser(siPlan);
  $('siImport').onclick = siImport;
  $('siViewClose').onclick = () => { $('siViewBox').hidden = true; };
  $('siRefresh').onclick = () => asUser(async () => { SI.probe = null; renderSIFetch(); await probeSI(); });
  document.querySelector('.tab[data-tab="si"]').addEventListener('click', () => {
    if (!$('siNs').value.trim() && S.ns) $('siNs').value = S.ns;
    renderSIPick();
    if (SI.probe === null) asUser(probeSI);
  });
  renderSIPick(); renderSIFiles(); renderSIStatus();
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
  $('attachBtn').onclick = attachFile;
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

  // encryption: identity, keys, keyring, write options
  loadIdentity(); renderIdentity(); renderKeysHeld(); renderKeyring();
  $('idGen').onclick = genIdentity;
  $('idImportBtn').onclick = importIdentity;
  $('idForget').onclick = () => { if (ID && confirm('Forget this identity? Keys wrapped to it can no longer be opened here.')) saveIdentity(null); };
  $('idShowPriv').onclick = () => { if (!ID) return toast('No identity'); $('idImport').value = ID.d; toast('Private key shown in the import field: keep it secret'); };
  $('keysClear').onclick = () => { KEYS.epoch.clear(); KEYS.res.clear(); KEYS.from.clear(); schemaCache.clear(); renderKeysHeld(); };
  $('keysFetch').onclick = fetchKeysForm;
  $('krRefresh').onclick = () => asUser(loadKeyring);
  $('krInit').onclick = krInit;
  $('krAdd').onclick = krAdd;
  $('krRotate').onclick = krRotate;
  $('jweOpen').onclick = decryptPasted;
  $('selfTest').onclick = runSelfTest;
  $('resendSealed').onclick = sendSealed;
  $('sealE2E').disabled = true;

  // catalog
  $('catNs').value = store.get('pl.catNs', 'cat');
  $('catLoad').onclick = () => asUser(() => loadCatalog());
  $('catNs').onkeydown = (e) => { if (e.key === 'Enter') asUser(() => loadCatalog()); };
  $('catRefresh').onclick = () => asUser(() => { C.proxy = null; C.catalogs = null; return loadCatalog(); });
  $('catPick').onchange = () => { const v = $('catPick').value; if (v) { $('catNs').value = v; asUser(() => loadCatalog()); } };
  $('catFCreate').onclick = catCreateFolder;
  $('catPCreate').onclick = catPlace;
  $('catMove').onclick = catMove;
  $('catRemove').onclick = catRemove;
  document.querySelector('.tab[data-tab="cat"]').addEventListener('click', () => { if (!C.ns && !C.loading) loadCatalog(); });
  document.querySelector('.tab[data-tab="keys"]').addEventListener('click', () => { if (KR.ns !== S.ns) loadKeyring(); });

  // search
  initSearch();
  initSchemas();

  // restore session
  showTab(store.get('pl.tab', 'ns'));
  renderNsSelect(); renderNsAll(); renderResAll(); renderHistory(); updateLiveUrls();
  const ns = store.get('pl.ns', ''), res = store.get('pl.res', '');
  if (ns) { S.res = res; asUser(() => selectNS(ns, { keepRes: true })); $('resName').value = res; }
  if (store.get('pl.tab', 'ns') === 'cat') loadCatalog();
  if (store.get('pl.tab', 'ns') === 'si') asUser(probeSI);
  if (store.get('pl.tab', 'ns') === 'sr') probeIndex().then(() => { renderSrPick(); renderSearch(); });
}

document.addEventListener('DOMContentLoaded', init);
})();
