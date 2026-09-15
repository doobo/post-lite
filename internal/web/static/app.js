'use strict';
/* PostLite SPA — vanilla JS, no CDN, no build step. */

const state = {
  user: null,
  view: 'editor',
  collections: [],
  treeData: {},       // collId -> {collection, folders, requests}
  treeCollapsed: {},  // nodeKey -> true (collections/folders start expanded)
  current: null,      // request being edited
  envs: [],
  results: null,
  reqTab: 'headers',  // active tab of the request editor
  resTab: 'body',     // active tab of the response panel
};

const $ = (s, el) => (el || document).querySelector(s);
const $$ = (s, el) => Array.from((el || document).querySelectorAll(s));
const esc = (s) => String(s == null ? '' : s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
const escAttr = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/* ---------- theme ---------- */

// Three palettes live in app.css as html[data-theme=...] blocks; the choice is a
// browser preference, not a server-side setting, so it stays in localStorage and
// survives a logout. Applied at parse time (this script sits at the end of body,
// before the first paint) so a reload does not flash the default palette.
const THEMES = ['dark', 'light', 'black'];
const THEME_KEY = 'postlite.theme';

function storedTheme() {
  try {
    const v = localStorage.getItem(THEME_KEY);
    return THEMES.indexOf(v) >= 0 ? v : 'dark';
  } catch (e) {
    return 'dark';   // storage can be blocked; the UI must still render
  }
}

function applyTheme(name) {
  const theme = THEMES.indexOf(name) >= 0 ? name : 'dark';
  document.documentElement.dataset.theme = theme;
  const sel = $('#theme-select');
  if (sel) sel.value = theme;
  try { localStorage.setItem(THEME_KEY, theme); } catch (e) { /* ignore */ }
}

applyTheme(storedTheme());

/* ---------- in-page notifications ---------- */

// Actions report their outcome with a pill in the header. alert() blocks the
// page, cannot be styled and steals focus, so it is not used anywhere: pills
// stack, can be dismissed and expire on their own.
const TOAST_TTL = 8000;

function notify(msg, kind) {
  const host = $('#flash');
  if (!host || !msg) return;
  const pill = document.createElement('div');
  pill.className = 'toast ' + (kind === 'err' ? 'err' : kind === 'warn' ? 'warn' : 'ok');
  const text = document.createElement('span');
  text.textContent = msg;
  const close = document.createElement('button');
  close.type = 'button';
  close.className = 'x';
  close.setAttribute('aria-label', 'Dismiss');
  close.textContent = '×';
  close.addEventListener('click', () => pill.remove());
  pill.append(text, close);
  host.appendChild(pill);
  setTimeout(() => pill.remove(), TOAST_TTL);
}

function clearToasts() {
  const host = $('#flash');
  if (host) host.innerHTML = '';
}

// flash() is the historical name for "say something", kept for the call sites.
function flash(msg, isErr) {
  if (msg) notify(msg, isErr ? 'err' : 'ok');
  else clearToasts();
}

/* ---------- in-page dialogs ---------- */

// confirm() and prompt() are both this dialog: one place that handles focus,
// Escape (cancel), Enter (confirm), a backdrop click (cancel) and a red button
// on destructive actions.
function openDialog(opts) {
  return new Promise((resolve) => {
    const wrap = $('#dialog');
    const card = $('#dialog-card');
    const input = $('#dialog-input');
    const field = $('#dialog-field');
    const copyBtn = $('#dialog-copy');
    const ok = $('#dialog-ok');
    const cancel = $('#dialog-cancel');

    $('#dialog-title').textContent = opts.title || '';
    $('#dialog-msg').textContent = opts.message || '';
    $('#dialog-msg').hidden = !opts.message;

    field.hidden = !opts.input;
    if (opts.input) {
      $('#dialog-field-label').textContent = opts.input.label || '';
      input.value = opts.input.value || '';
      input.readOnly = !!opts.input.readOnly;
      input.placeholder = opts.input.placeholder || '';
      copyBtn.hidden = !opts.input.copy;
    }

    ok.textContent = opts.confirmLabel || 'OK';
    ok.className = opts.danger ? 'solid-danger' : 'primary';
    cancel.hidden = opts.cancelLabel === '';

    wrap.hidden = false;
    if (opts.input && !opts.input.readOnly) { input.focus(); input.select(); }
    else ok.focus();

    const done = (value) => {
      wrap.hidden = true;
      card.removeEventListener('submit', onSubmit);
      cancel.removeEventListener('click', onCancel);
      document.removeEventListener('keydown', onKey, true);
      wrap.removeEventListener('mousedown', onBackdrop);
      resolve(value);
    };
    const onSubmit = (ev) => { ev.preventDefault(); done(opts.input ? input.value.trim() : true); };
    // type="button" does nothing on its own: without this the Cancel button is
    // dead and only Escape / a backdrop click can close the dialog.
    const onCancel = () => done(null);
    const onKey = (ev) => { if (ev.key === 'Escape') { ev.stopPropagation(); done(null); } };
    const onBackdrop = (ev) => { if (ev.target === wrap) done(null); };

    card.addEventListener('submit', onSubmit);
    cancel.addEventListener('click', onCancel);
    document.addEventListener('keydown', onKey, true);
    wrap.addEventListener('mousedown', onBackdrop);
  });
}

// Resolves true only when the user confirms.
async function askConfirm(title, message, confirmLabel) {
  return (await openDialog({ title, message, confirmLabel, danger: true })) === true;
}

// Resolves the entered text, or null when cancelled.
function askInput(title, label, value, opts) {
  opts = opts || {};
  return openDialog({
    title,
    message: opts.message,
    input: {
      label,
      value,
      placeholder: opts.placeholder,
      readOnly: opts.readOnly,
      copy: opts.copy,
    },
    confirmLabel: opts.confirmLabel || 'OK',
  });
}

function copyDialogInput() {
  const input = $('#dialog-input');
  if (input) copyText(input.value, 'to clipboard');
}

async function api(path, opts) {
  opts = opts || {};
  const res = await fetch('/api' + path, {
    method: opts.method || 'GET',
    credentials: 'same-origin',
    headers: opts.body ? { 'Content-Type': 'application/json' } : {},
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (res.status === 401 && !path.startsWith('/auth/login')) {
    showLogin();
    throw new Error('session expired, please sign in again');
  }
  let data = null;
  try { data = await res.json(); } catch (e) { /* non-JSON */ }
  if (!data || data.ok === false) {
    throw new Error((data && data.error && data.error.message) || res.statusText || ('HTTP ' + res.status));
  }
  return data.data === undefined ? null : data.data;
}

/* ---------- login encryption ---------- */

const b64ToBytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
const bytesToB64 = (bytes) => { let s = ''; bytes.forEach((b) => { s += String.fromCharCode(b); }); return btoa(s); };

// encryptPassword runs the client half of the login handshake: the server hands
// out an ephemeral RSA public key plus a single-use challenge, and the password
// travels only inside {"c":challenge,"p":password} encrypted with RSA-OAEP.
// A captured request body is therefore useless to proxies, access logs and
// anyone replaying it (the challenge is burned on use).
async function encryptPassword(password) {
  const lk = await api('/auth/login-key');
  const payload = JSON.stringify({ c: lk.challenge, p: password });

  // crypto.subtle exists only in a secure context (HTTPS or localhost). A
  // plain-HTTP intranet address therefore falls through to loginenc.js, which is
  // embedded with the rest of the UI — no CDN, no build step.
  if (window.crypto && window.crypto.subtle) {
    try {
      const key = await crypto.subtle.importKey(
        'spki', b64ToBytes(lk.key), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
      const ct = await crypto.subtle.encrypt(
        { name: 'RSA-OAEP' }, key, new TextEncoder().encode(payload));
      return bytesToB64(new Uint8Array(ct));
    } catch (e) {
      // Fall through: an old browser or a broken import should not strand the
      // user on the login page when the bundled implementation can do the job.
    }
  }
  if (!window.LoginEnc) {
    throw new Error('this browser cannot encrypt the login request — use HTTPS');
  }
  return LoginEnc.encrypt(payload, lk.n, lk.e);
}

/* ---------- login / shell ---------- */

function showLogin() {
  $('#login-view').hidden = false;
  $('#app-view').hidden = true;
  state.user = null;
  flash('');
}

async function startApp() {
  const me = await api('/auth/me');
  state.user = me.user;
  $('#login-view').hidden = true;
  $('#app-view').hidden = false;
  $('#who').innerHTML = '<b>' + esc(state.user.username) + '</b>'
    + ' <span class="badge' + (state.user.role === 'admin' ? ' admin' : '') + '">' + esc(state.user.role) + '</span>';
  $$('.admin-only').forEach((b) => { b.style.display = state.user.role === 'admin' ? '' : 'none'; });
  await reloadAll();
  setView('editor');
}

function setView(name) {
  // Nothing to render before sign-in: a stale async caller (an expired session
  // resolving late) must not crash on a missing state.user.
  if (!state.user) return;
  state.view = name;
  $$('#main-nav button').forEach((b) => b.classList.toggle('active', b.dataset.view === name));
  const renderers = {
    collections: renderCollections,
    editor: renderEditor,
    environments: renderEnvironments,
    history: renderHistory,
    secrets: renderSecrets,
    users: renderUsers,
    settings: renderSettings,
  };
  const fn = renderers[name] || renderEditor;
  if ((name === 'secrets' || name === 'users' || name === 'settings') && state.user.role !== 'admin') {
    return setView('editor');
  }
  fn().catch((e) => { $('#content').innerHTML = '<div class="card"><p class="err">' + esc(e.message) + '</p></div>'; });
}

async function reloadAll() {
  await loadCollections();
  await loadEnvs();
}

/* ---------- collections + tree ---------- */

async function loadCollections() {
  const cols = await api('/collections');
  state.collections = cols || [];
  state.treeData = {};
  for (const c of state.collections) {
    try {
      state.treeData[c.id] = await api('/collections/' + c.id);
    } catch (e) { /* skip inaccessible */ }
  }
  renderTree();
}

// One hue per HTTP verb (see --method-*-color in app.css) so a request reads at
// a glance in the tree and in the method picker.
function methodClass(m) { return 'm-' + String(m || '').toUpperCase(); }

// Collections and folders collapse independently. Nodes start expanded, so the
// whole tree is reachable without extra clicks; collapsed children stay in the
// DOM (just display:none) which keeps find-in-page and the UI tests working.
function toggleTree(ev, key) {
  if (ev) ev.stopPropagation();
  const node = document.querySelector('[data-node="' + key + '"]');
  const sub = document.querySelector('[data-sub="' + key + '"]');
  if (!node || !sub) return;
  sub.classList.toggle('hidden', node.classList.toggle('collapsed'));
}

function renderTree() {
  const t = $('#tree');
  if (state.collections.length === 0) {
    t.innerHTML = '<h3>Collections</h3><div class="empty">No collections yet.</div>';
    return;
  }
  const reqRow = (r, depth) => {
    const active = state.current && state.current.id === r.id;
    return '<div class="node req' + (active ? ' active' : '') + '" data-req="' + r.id + '"'
      + ' style="padding-left:' + (10 + depth * 13) + 'px" onclick="loadRequest(' + r.id + ')"'
      + ' title="' + escAttr(r.name) + '">'
      + '<span class="verb ' + methodClass(r.method) + '">' + esc(r.method) + '</span>'
      + '<span class="name">' + esc(r.name) + '</span></div>';
  };
  let html = '<h3>Collections</h3>';
  for (const c of state.collections) {
    const d = state.treeData[c.id];
    const collapsed = !!state.treeCollapsed['coll-' + c.id];
    const tag = c.owner_id == null ? ' <span class="badge">global</span>' : '';
    html += '<div class="node coll' + (collapsed ? ' collapsed' : '') + '" data-node="coll-' + c.id + '"'
      + ' onclick="toggleTree(event,\'coll-' + c.id + '\')" title="Expand / collapse">'
      + '<span class="caret">▾</span><span class="name">' + esc(c.name) + '</span>' + tag + '</div>';
    if (!d) continue;
    const folders = d.folders || [];
    const reqs = d.requests || [];
    const byParent = {};
    folders.forEach((f) => {
      const k = f.parent_id == null ? 'root' : String(f.parent_id);
      (byParent[k] = byParent[k] || []).push(f);
    });
    const reqByFolder = {};
    reqs.forEach((r) => {
      const k = r.folder_id == null ? 'root' : String(r.folder_id);
      (reqByFolder[k] = reqByFolder[k] || []).push(r);
    });
    const renderFolder = (f, depth) => {
      const kids = (byParent[String(f.id)] || []).length + (reqByFolder[String(f.id)] || []).length;
      const fCollapsed = !!state.treeCollapsed['fold-' + f.id];
      let h = '<div class="node fold' + (fCollapsed ? ' collapsed' : '') + '" data-node="fold-' + f.id + '"'
        + ' style="padding-left:' + (10 + depth * 13) + 'px" onclick="toggleTree(event,\'fold-' + f.id + '\')">'
        + '<span class="caret">' + (kids ? '▾' : '·') + '</span><span class="name">' + esc(f.name) + '</span></div>';
      if (!kids) return h;
      let sub = '';
      (reqByFolder[String(f.id)] || []).forEach((r) => { sub += reqRow(r, depth + 1); });
      (byParent[String(f.id)] || []).forEach((sf) => { sub += renderFolder(sf, depth + 1); });
      return h + '<div data-sub="fold-' + f.id + '"' + (fCollapsed ? ' class="hidden"' : '') + '>' + sub + '</div>';
    };
    let body = '';
    (byParent.root || []).forEach((f) => { body += renderFolder(f, 0); });
    (reqByFolder.root || []).forEach((r) => { body += reqRow(r, 0); });
    html += '<div data-sub="coll-' + c.id + '"' + (collapsed ? ' class="hidden"' : '') + '>' + body + '</div>';
  }
  t.innerHTML = html;
}

async function renderCollections() {
  const isAdmin = state.user.role === 'admin';
  let html = '<div class="card"><h2>Collections</h2>'
    + '<div class="row"><input id="new-coll-name" placeholder="New collection name">'
    + (isAdmin ? '<label><input type="checkbox" id="new-coll-global"> global</label>' : '')
    + '<button class="primary" onclick="createCollection()">Create</button></div>'
    + '<div class="row"><input type="file" id="import-file" accept=".json">'
    + (isAdmin ? '<label><input type="checkbox" id="import-global"> import as global</label>' : '')
    + '<button onclick="importCollection()">Import JSON</button></div>'
    + '</div>';
  for (const c of state.collections) {
    const d = state.treeData[c.id];
    const nReq = d ? (d.requests || []).length : 0;
    const tag = c.owner_id == null ? ' <span class="badge">global</span>' : '';
    html += '<div class="card" style="margin-top:10px"><div class="row"><strong>' + esc(c.name) + '</strong>' + tag
      + '<span class="muted">' + nReq + ' requests</span>'
      + '<button class="ghost" onclick="newRequest(' + c.id + ')">+ Request</button>'
      + '<button class="ghost" onclick="createFolderPrompt(' + c.id + ')">+ Folder</button>'
      + '<button class="ghost" onclick="exportCollection(' + c.id + ')">Export</button>'
      + '<button class="danger" onclick="deleteCollection(' + c.id + ')">Delete</button></div></div>';
  }
  $('#content').innerHTML = html;
}

async function createCollection() {
  const name = $('#new-coll-name').value.trim();
  if (!name) return notify('Collection name is required', 'err');
  const global = $('#new-coll-global') ? $('#new-coll-global').checked : false;
  await api('/collections', { method: 'POST', body: { name: name, global: global } });
  await loadCollections();
  renderCollections();
}

async function deleteCollection(id) {
  const okd = await askConfirm('Delete collection', 'Collection #' + id + ' and all of its requests will be removed.', 'Delete');
  if (!okd) return;
  await api('/collections/' + id, { method: 'DELETE' });
  state.collections = state.collections.filter((c) => c.id !== id);
  delete state.treeData[id];
  renderTree();
  renderCollections();
}

async function createFolderPrompt(collId) {
  const name = await askInput('New folder', 'Folder name', '', { placeholder: 'e.g. auth' });
  if (!name) return;
  await api('/collections/' + collId + '/folders', { method: 'POST', body: { name: name } });
  await loadCollections();
  renderCollections();
}

async function exportCollection(id) {
  const res = await fetch('/api/collections/' + id + '/export', { method: 'POST', credentials: 'same-origin' });
  if (!res.ok) return notify('export failed: ' + res.statusText, 'err');
  const text = await res.text();
  const blob = new Blob([text], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'collection-' + id + '.json';
  a.click();
  URL.revokeObjectURL(a.href);
}

async function importCollection() {
  const f = $('#import-file').files[0];
  if (!f) return notify('choose a JSON file first', 'err');
  const text = await f.text();
  const global = $('#import-global') ? $('#import-global').checked : false;
  const data = await api('/collections/import', { method: 'POST', body: { json: text, global: global } });
  await loadCollections();
  renderCollections();
  notify('imported as collection #' + data.id);
}

/* ---------- request editor ---------- */

function objPairs(obj) {
  return Object.keys(obj || {}).map((k) => ({ k: k, v: obj[k] }));
}

function parseHeaders(s) {
  try { return JSON.parse(s || '{}') || {}; } catch (e) { return {}; }
}

function parseQuery(s) {
  try {
    const a = JSON.parse(s || '[]') || [];
    return a.map((p) => ({ k: p.k || '', v: p.v || '' }));
  } catch (e) { return []; }
}

function kvRows(pairs, keyPh, valPh) {
  const html = (pairs || []).map((p) =>
    '<div class="kvrow"><input class="k" placeholder="' + escAttr(keyPh) + '" value="' + escAttr(p.k) + '" oninput="updateTabCounts()">'
    + '<input class="v" placeholder="' + escAttr(valPh) + '" value="' + escAttr(p.v) + '" oninput="updateTabCounts()">'
    + '<button class="ghost del" onclick="delRow(this)" title="Remove row" aria-label="Remove row">&times;</button></div>'
  ).join('');
  return html + '<div><button class="ghost" onclick="addRow(this)">+ row</button></div>';
}

function addRow(btn) {
  const row = document.createElement('div');
  row.className = 'kvrow';
  row.innerHTML = '<input class="k" placeholder="key" oninput="updateTabCounts()">'
    + '<input class="v" placeholder="value" oninput="updateTabCounts()">'
    + '<button class="ghost del" onclick="delRow(this)" title="Remove row" aria-label="Remove row">&times;</button>';
  btn.parentElement.before(row);
  $('.k', row).focus();
  updateTabCounts();
}

function delRow(btn) { btn.parentElement.remove(); updateTabCounts(); }

function collectKV(container) {
  return $$('.kvrow', container).map((r) => ({
    k: $('.k', r).value,
    v: $('.v', r).value,
  })).filter((p) => p.k !== '' || p.v !== '');
}

/* ---------- panels / tabs ---------- */

// Tabs are grouped ('req' for the editor, 'res' for the response) so switching
// one never touches the other. Panels stay in the DOM while hidden, so every
// field is still collected by save/send and by find-in-page.
function setPanel(group, name) {
  $$('#content .tab[data-group="' + group + '"]').forEach((b) => {
    b.classList.toggle('active', b.dataset.tab === name);
  });
  $$('#content .tabpanel[data-group="' + group + '"]').forEach((p) => {
    p.hidden = p.dataset.panel !== name;
  });
}

function setReqTab(name) { state.reqTab = name; setPanel('req', name); }
function setResTab(name) { state.resTab = name; setPanel('res', name); }

function updateMethodColor() {
  const sel = $('#req-method');
  if (sel) sel.className = methodClass(sel.value);
}

// Tab badges show how many rows the panel actually carries, so a hidden panel
// with content is still noticeable.
function updateTabCounts() {
  const filled = (sel) => {
    const box = $(sel);
    if (!box) return 0;
    return $$('.kvrow', box).filter((r) => $('.k', r).value.trim() !== '' || $('.v', r).value.trim() !== '').length;
  };
  const set = (name, n) => {
    const el = document.querySelector('[data-count="' + name + '"]');
    if (el) el.textContent = n ? String(n) : '';
  };
  set('headers', filled('#req-headers'));
  set('params', filled('#req-query'));
  set('vars', filled('#req-vars'));
}

function collOptions(selected) {
  return state.collections.map((c) =>
    '<option value="' + c.id + '"' + (String(c.id) === String(selected) ? ' selected' : '') + '>' + esc(c.name) + (c.owner_id == null ? ' (global)' : '') + '</option>'
  ).join('');
}

function folderOptions(collId, selected) {
  const d = state.treeData[collId];
  if (!d) return '<option value="">(root)</option>';
  return '<option value="">(root)</option>' + (d.folders || []).map((f) =>
    '<option value="' + f.id + '"' + (String(f.id) === String(selected) ? ' selected' : '') + '>' + esc(f.name) + '</option>'
  ).join('');
}

async function newRequest(collId) {
  state.current = {
    id: null,
    collection_id: collId || (state.collections[0] ? state.collections[0].id : null),
    folder_id: null,
    name: 'Untitled',
    method: 'GET',
    url: 'http://',
    headers: {},
    query: [],
    body_type: 'none',
    body: '',
    variables: '',
    use_proxy: false,
  };
  state.results = null;
  setView('editor');
}

async function loadRequest(id) {
  const rq = await api('/requests/' + id);
  state.current = {
    id: rq.id,
    collection_id: rq.collection_id,
    folder_id: rq.folder_id,
    name: rq.name,
    method: rq.method,
    url: rq.url,
    headers: parseHeaders(rq.headers),
    query: parseQuery(rq.query),
    body_type: rq.body_type || 'none',
    body: rq.body || '',
    variables: rq.variables || '',
    use_proxy: !!rq.use_proxy,
  };
  state.results = null;
  setView('editor');
  renderTree();   // highlight the row that is now open
}

async function renderEditor() {
  if (!state.current) {
    if (state.collections.length === 0) {
      $('#content').innerHTML = '<div class="card empty-state"><h2>No collections yet</h2>'
        + '<p class="muted">A request lives inside a collection. Create your first one, then add requests to it.</p>'
        + '<div class="row"><button class="primary" onclick="setView(\'collections\')">Open Collections</button></div></div>';
      return;
    }
    await newRequest(state.collections[0].id);
    return;
  }
  const c = state.current;
  const gEnvs = state.envs.filter((e) => e.scope === 'global');
  const uEnvs = state.envs.filter((e) => e.scope === 'user');
  const reqTab = (name, label) => '<button class="tab' + (state.reqTab === name ? ' active' : '') + '"'
    + ' data-group="req" data-tab="' + name + '" onclick="setReqTab(\'' + name + '\')">' + label
    + '<span class="count" data-count="' + name + '"></span></button>';
  const reqPanel = (name, body) => '<div class="tabpanel" data-group="req" data-panel="' + name + '"'
    + (state.reqTab === name ? '' : ' hidden') + '>' + body + '</div>';

  $('#content').innerHTML =
    '<div class="card">'
    + '<div class="row">'
    + '<select id="req-method" class="' + methodClass(c.method) + '" onchange="updateMethodColor()">'
    + ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map((m) => '<option' + (c.method === m ? ' selected' : '') + '>' + m + '</option>').join('')
    + '</select>'
    + '<input id="req-url" class="url" placeholder="http://host:5680/path — {{VAR}} / {{sec.NAME}} supported" value="' + escAttr(c.url) + '">'
    + '<button id="btn-save" class="ghost" onclick="saveRequest()" title="Save request (Ctrl+S)">Save</button>'
    + '<button id="btn-send" class="primary" onclick="sendRequest()" title="Send request (Ctrl+Enter)">Send</button>'
    // Deleting is admin-only (the server enforces it with requireAdmin), so the
    // button is rendered from the role rather than hidden with CSS after render.
    + (c.id && state.user && state.user.role === 'admin'
      ? '<button id="btn-del-req" class="danger admin-only" onclick="deleteRequest()" title="Delete this saved request">Delete</button>'
      : '')
    + '</div>'
    + '<div class="row meta">'
    + '<label>Name <input id="req-name" style="max-width:190px" value="' + escAttr(c.name) + '"></label>'
    + '<label>Collection <select id="req-coll" onchange="onCollChange()">' + collOptions(c.collection_id) + '</select></label>'
    + '<label>Folder <select id="req-folder">' + folderOptions(c.collection_id, c.folder_id) + '</select></label>'
    + '<label>Global env <select id="req-genv"><option value="">(active)</option>' + gEnvs.map((e) => '<option value="' + e.id + '">' + esc(e.name) + '</option>').join('') + '</select></label>'
    + '<label>User env <select id="req-uenv"><option value="">(active)</option>' + uEnvs.map((e) => '<option value="' + e.id + '">' + esc(e.name) + '</option>').join('') + '</select></label>'
    + '<label><input type="checkbox" id="req-follow"> follow redirects</label>'
    // Per-request opt-in; the admin decides whether a proxy exists at all (Settings).
    + '<label title="Send this request through the proxy configured in Settings"><input type="checkbox" id="req-proxy"'
    + (c.use_proxy ? ' checked' : '') + '> use proxy</label>'
    + '<span class="hint"><kbd>Ctrl</kbd>+<kbd>Enter</kbd> send · <kbd>Ctrl</kbd>+<kbd>S</kbd> save</span>'
    + '<span id="send-status" class="muted"></span>'
    + '</div>'
    + '<div class="tabs">' + reqTab('headers', 'Headers') + reqTab('params', 'Params') + reqTab('body', 'Body') + reqTab('vars', 'Vars') + '</div>'
    + reqPanel('headers', '<div id="req-headers">' + kvRows(objPairs(c.headers), 'Header', 'value') + '</div>')
    + reqPanel('params', '<div id="req-query">' + kvRows(c.query, 'key', 'value') + '</div>')
    + reqPanel('body', '<div class="row"><select id="req-bodytype" onchange="onBodyTypeChange()">'
      + ['none', 'json', 'raw', 'graphql'].map((t) => '<option value="' + t + '"' + (c.body_type === t ? ' selected' : '') + '>' + t + '</option>').join('')
      + '</select><span class="hint" id="req-body-hint"></span></div>'
      + '<textarea id="req-body" rows="8" placeholder=\'{"key":"value"}\'>' + esc(c.body || '') + '</textarea>'
      // GraphQL only: the body above is the query document, this is the
      // variables object. Kept in the DOM while hidden so save/send still
      // collect it and Ctrl+F finds it.
      + '<div id="req-gql" hidden>'
      + '<p class="hint">Variables — a JSON object, e.g. <code>{"id":"42"}</code>. Sent as <code>variables</code> next to the query.</p>'
      + '<textarea id="req-gql-vars" rows="5" placeholder=\'{"id":"42"}\'>' + esc(c.variables || '') + '</textarea>'
      + '</div>')
    + reqPanel('vars', '<div id="req-vars">' + kvRows([], 'name', 'value') + '</div>'
      + '<p class="hint">Temporary variables win over environments and secrets, and are never stored.</p>')
    + '<div id="result"></div>'
    + '</div>';
  updateMethodColor();
  onBodyTypeChange();
  updateTabCounts();
  if (state.results) renderResult();
}

// BODY_HINTS and onBodyTypeChange() keep the Body panel honest about what will
// actually be sent for the selected type.
const BODY_HINTS = {
  none: 'no body is sent',
  json: 'sent as-is as application/json; <code>{{VAR}}</code> and <code>{{sec.NAME}}</code> are resolved server-side',
  raw: 'sent as-is; <code>{{VAR}}</code> and <code>{{sec.NAME}}</code> are resolved server-side',
  graphql: 'the query above is POSTed as <code>{"query": …}</code>; placeholders resolve in the query and in the variables',
};

function onBodyTypeChange() {
  const sel = $('#req-bodytype');
  if (!sel) return;
  const type = sel.value;
  const gql = $('#req-gql');
  if (gql) gql.hidden = type !== 'graphql';
  const hint = $('#req-body-hint');
  if (hint) hint.innerHTML = BODY_HINTS[type] || BODY_HINTS.raw;
  const body = $('#req-body');
  if (body) {
    body.placeholder = type === 'graphql' ? 'query ($id: ID!) { user(id: $id) { name } }' : '{"key":"value"}';
    body.rows = type === 'graphql' ? 10 : 8;
  }
  // A GraphQL query travels in a POST body; leaving GET selected would send the
  // query as a query-string parameter, which no endpoint accepts.
  const method = $('#req-method');
  if (type === 'graphql' && method && method.value === 'GET') {
    method.value = 'POST';
    updateMethodColor();
  }
}

function onCollChange() {
  $('#req-folder').innerHTML = folderOptions(Number($('#req-coll').value), null);
}

function buildAdHoc() {
  const headers = {};
  collectKV($('#req-headers')).forEach((p) => { headers[p.k] = p.v; });
  return {
    method: $('#req-method').value,
    url: $('#req-url').value,
    headers: headers,
    query: collectKV($('#req-query')),
    body_type: $('#req-bodytype').value,
    body: $('#req-body').value,
    variables: $('#req-gql-vars') ? $('#req-gql-vars').value : '',
    use_proxy: $('#req-proxy').checked,
  };
}

async function saveRequest() {
  const c = state.current;
  const ad = buildAdHoc();
  const payload = {
    collection_id: Number($('#req-coll').value),
    folder_id: $('#req-folder').value ? Number($('#req-folder').value) : null,
    name: $('#req-name').value || 'Untitled',
    method: ad.method,
    url: ad.url,
    headers: JSON.stringify(ad.headers),
    query: JSON.stringify(ad.query),
    body_type: ad.body_type,
    body: ad.body,
    variables: ad.variables,
    use_proxy: ad.use_proxy,
  };
  $('#send-status').textContent = 'saving…';
  try {
    if (c.id) {
      await api('/requests/' + c.id, { method: 'PUT', body: payload });
    } else {
      const data = await api('/requests', { method: 'POST', body: payload });
      c.id = data.id;
    }
    Object.assign(c, payload, { headers: ad.headers, query: ad.query });
    await loadCollections();
    $('#send-status').textContent = 'saved #' + c.id;
  } catch (e) {
    $('#send-status').textContent = 'save failed: ' + e.message;
  }
}

async function deleteRequest() {
  const c = state.current;
  if (!c || !c.id) return;
  const okd = await askConfirm('Delete request',
    'Request #' + c.id + ' "' + c.name + '" will be removed. History rows that point at it are kept.', 'Delete');
  if (!okd) return;
  try {
    await api('/requests/' + c.id, { method: 'DELETE' });
  } catch (e) {
    return flash('delete failed: ' + e.message, true);
  }
  state.current = null;
  state.results = null;
  await loadCollections();
  renderTree();
  await renderEditor();   // falls back to the first collection / empty state
  flash('request deleted');
}

async function sendRequest() {
  const btn = $('#btn-send');
  if (!btn || btn.disabled) return;
  const vars = {};
  collectKV($('#req-vars')).forEach((p) => { vars[p.k] = p.v; });
  const active = {};
  if ($('#req-genv').value) active.global_env_id = Number($('#req-genv').value);
  if ($('#req-uenv').value) active.user_env_id = Number($('#req-uenv').value);
  const body = {
    ad_hoc: buildAdHoc(),
    vars: vars,
    active_env: active,
    follow_redirects: $('#req-follow').checked,
  };
  // Disable while in flight: a double click must not fire two outbound requests.
  const label = btn.textContent.trim() || 'Send';
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Sending…';
  $('#send-status').textContent = 'sending…';
  $('#result').innerHTML = '<div class="notice"><span class="spinner dark"></span><span>Waiting for the server-side request…</span></div>';
  try {
    state.results = await api('/execute', { method: 'POST', body: body });
    $('#send-status').textContent = '';
    renderResult();
  } catch (e) {
    state.results = null;
    $('#send-status').textContent = 'error: ' + e.message;
    $('#result').innerHTML = '<div class="notice err"><b>Not executed</b><span>' + esc(e.message) + '</span></div>';
  } finally {
    btn.disabled = false;
    btn.textContent = label;
  }
}

function statusClass(s) {
  if (s >= 200 && s < 300) return 'status-2xx';
  if (s >= 300 && s < 400) return 'status-3xx';
  if (s >= 400 && s < 500) return 'status-4xx';
  if (s >= 500) return 'status-5xx';
  return 'status-err';
}

function renderResult() {
  const d = state.results;
  if (!d) return;
  const headers = d.headers || {};
  const headerLines = Object.keys(headers).map((k) => k + ': ' + (headers[k] || []).join(', ')).join('\n');
  const bytes = (d.body || '').length;
  const resTab = (name, label) => '<button class="tab' + (state.resTab === name ? ' active' : '') + '"'
    + ' data-group="res" data-tab="' + name + '" onclick="setResTab(\'' + name + '\')">' + label + '</button>';
  const resPanel = (name, inner) => '<div class="tabpanel" data-group="res" data-panel="' + name + '"'
    + (state.resTab === name ? '' : ' hidden') + '>' + inner + '</div>';

  let html = '<div class="result">'
    + '<div class="resp-head">'
    + '<h2>Response <span class="pill ' + statusClass(d.status) + '">' + d.status + ' ' + esc(d.status_text || '') + '</span></h2>'
    + '<span class="meta-line"><span>' + d.duration_ms + ' ms</span><span class="sep">·</span><span>' + bytes + ' B</span>'
    + '<span class="sep">·</span><span>secrets masked as ***</span>'
    + (d.proxied ? '<span class="sep">·</span><span class="badge on">via proxy</span>' : '') + '</span>'
    + '<span class="spacer"></span>'
    + '<button class="ghost" onclick="copyResponse()" title="Copy the response body">Copy</button>'
    + '</div>';
  if (d.final_url) html += '<div class="meta-line"><span>final URL</span><code>' + esc(d.final_url) + '</code></div>';
  if (d.body_truncated) html += '<div class="notice"><b>Truncated</b><span>body cut off at 10MB</span></div>';
  if (d.warnings && d.warnings.length) {
    html += '<div class="notice"><b>Unresolved</b><span>' + d.warnings.map(esc).join(', ') + ' — sent as-is</span></div>';
  }
  html += '<div class="tabs">' + resTab('body', 'Body') + resTab('headers', 'Headers') + '</div>'
    + resPanel('body', '<pre>' + esc(d.body || '') + '</pre>')
    + resPanel('headers', '<pre>' + esc(headerLines) + '</pre>')
    + '</div>';
  $('#result').innerHTML = html;
}

// The async clipboard API needs a secure context (a plain-HTTP intranet page is
// not one) and a focused document, so keep the legacy execCommand path as a
// fallback for both cases.
function legacyCopy(text) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.style.position = 'fixed';
  ta.style.top = '-1000px';
  document.body.appendChild(ta);
  ta.select();
  const okd = document.execCommand('copy');
  ta.remove();
  if (!okd) throw new Error('clipboard is blocked by the browser');
}

async function copyText(text, what) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(text);
      } catch (e) {
        legacyCopy(text);   // unfocused document / permission denied
      }
    } else {
      legacyCopy(text);
    }
    flash('copied ' + what);
  } catch (e) {
    flash('copy failed: ' + e.message, true);
  }
}

function copyResponse() { copyText((state.results && state.results.body) || '', 'response body'); }

/* ---------- environments ---------- */

async function loadEnvs() {
  state.envs = (await api('/environments')) || [];
}

async function renderEnvironments() {
  await loadEnvs();
  const g = state.envs.filter((e) => e.scope === 'global');
  const u = state.envs.filter((e) => e.scope === 'user');
  const isAdmin = state.user.role === 'admin';
  let html = '<div class="card"><h2>Environments</h2>'
    + '<div class="row"><input id="new-env-name" placeholder="Name">'
    + '<select id="new-env-scope"><option value="user">user</option>' + (isAdmin ? '<option value="global">global</option>' : '') + '</select>'
    + '<button class="primary" onclick="createEnv()">Create</button></div></div>';
  const section = (title, list, slot) => {
    let h = '<div class="card" style="margin-top:10px"><h2>' + title + '</h2>';
    if (!list.length) h += '<p class="muted">none</p>';
    list.forEach((e) => {
      const pairs = Object.keys(e.vars_map || {}).map((k) => ({ k: k, v: e.vars_map[k] }));
      h += '<details><summary><strong>' + esc(e.name) + '</strong> <span class="muted">' + Object.keys(e.vars_map || {}).length + ' vars</span></summary>'
        + '<div id="env-vars-' + e.id + '">' + kvRows(pairs, 'name', 'value') + '</div>'
        + '<div class="row"><button onclick="saveEnv(' + e.id + ')">Save vars</button>'
        + '<button class="ghost" onclick="activateEnv(' + e.id + ",'" + slot + '\')">Set active ' + slot + '</button>'
        + '<button class="danger" onclick="deleteEnv(' + e.id + ')">Delete</button></div></details>';
    });
    return h + '</div>';
  };
  html += section('Global', g, 'global');
  html += section('User', u, 'user');
  $('#content').innerHTML = html;
}

async function createEnv() {
  const name = $('#new-env-name').value.trim();
  if (!name) return notify('Environment name is required', 'err');
  await api('/environments', {
    method: 'POST',
    body: { name: name, scope: $('#new-env-scope').value, vars: {} },
  });
  renderEnvironments();
}

async function saveEnv(id) {
  const vars = {};
  collectKV($('#env-vars-' + id)).forEach((p) => { vars[p.k] = p.v; });
  const e = state.envs.find((x) => x.id === id);
  await api('/environments/' + id, { method: 'PUT', body: { name: e.name, vars: vars } });
  notify('Environment vars saved');
}

async function deleteEnv(id) {
  const okd = await askConfirm('Delete environment', 'Environment #' + id + ' will be removed.', 'Delete');
  if (!okd) return;
  await api('/environments/' + id, { method: 'DELETE' });
  renderEnvironments();
}

async function activateEnv(id, slot) {
  const body = slot === 'global' ? { global_env_id: id } : { user_env_id: id };
  await api('/environments/activate', { method: 'POST', body: body });
  notify('active ' + slot + ' environment set');
}

/* ---------- secrets (admin) ---------- */

async function renderSecrets() {
  const list = (await api('/secrets')) || [];
  let html = '<div class="card"><h2>Secrets <span class="muted">— write-only, values are never readable</span></h2>'
    + '<div class="row"><input id="new-sec-name" placeholder="name (e.g. api_key)">'
    + '<input id="new-sec-value" type="password" placeholder="value" style="flex:1;min-width:200px">'
    + '<button class="primary" onclick="createSecret()">Store encrypted</button></div>'
    + '<p class="muted">Use <code>{{sec.NAME}}</code> in URLs / headers / bodies. Values are injected server-side and masked as *** everywhere else.</p></div>';
  html += '<div class="card" style="margin-top:10px"><table><tr><th>name</th><th>updated</th><th>overwrite</th><th></th></tr>';
  list.forEach((s) => {
    html += '<tr><td><code>' + esc(s.name) + '</code></td><td class="muted">' + esc(s.updated_at || '') + '</td>'
      + '<td><input id="sec-val-' + s.id + '" type="password" placeholder="new value"> <button class="ghost" onclick="updateSecret(\'' + escAttr(s.name) + '\',' + s.id + ')">Overwrite</button></td>'
      + '<td><button class="danger" onclick="deleteSecret(' + s.id + ')">Delete</button></td></tr>';
  });
  html += '</table></div>';
  $('#content').innerHTML = html;
}

async function createSecret() {
  const name = $('#new-sec-name').value.trim();
  const value = $('#new-sec-value').value;
  if (!name || !value) return notify('Secret name and value are required', 'err');
  await api('/secrets', { method: 'POST', body: { name: name, value: value } });
  renderSecrets();
}

async function updateSecret(name, id) {
  const value = $('#sec-val-' + id).value;
  if (!value) return notify('Enter the new value first', 'err');
  await api('/secrets/' + encodeURIComponent(name), { method: 'PUT', body: { value: value } });
  renderSecrets();
}

async function deleteSecret(id) {
  const okd = await askConfirm('Delete secret', 'Secret #' + id + ' is destroyed and cannot be recovered.', 'Delete');
  if (!okd) return;
  await api('/secrets/' + id, { method: 'DELETE' });
  renderSecrets();
}

/* ---------- history ---------- */

async function renderHistory() {
  const items = (await api('/history?limit=100')) || [];
  let html = '<div class="card"><h2>History <span class="muted">(redacted snapshots)</span></h2><table>'
    + '<tr><th>#</th><th>method</th><th>url</th><th>status</th><th>ms</th><th>time</th><th></th></tr>';
  items.forEach((h) => {
    html += '<tr><td>' + h.id + '</td><td><span class="badge">' + esc(h.method) + '</span></td>'
      + '<td>' + esc((h.url || '').slice(0, 80)) + '</td>'
      + '<td class="' + statusClass(h.status) + '">' + h.status + '</td>'
      + '<td>' + h.duration_ms + '</td><td class="muted">' + esc(h.created_at || '') + '</td>'
      + '<td><button class="ghost" onclick="viewHistory(' + h.id + ')">View</button> '
      + '<button class="danger" onclick="deleteHistory(' + h.id + ')">Delete</button></td></tr>';
  });
  html += '</table><div id="hist-detail"></div></div>';
  $('#content').innerHTML = html;
}

async function viewHistory(id) {
  const h = await api('/history/' + id);
  $('#hist-detail').innerHTML = '<h3>Request #' + id + '</h3><pre>' + esc(h.req_redacted || '') + '</pre>'
    + '<h3>Response</h3><pre>' + esc(h.res_redacted || '') + '</pre>';
}

async function deleteHistory(id) {
  const okd = await askConfirm('Delete history entry', 'History entry #' + id + ' will be removed.', 'Delete');
  if (!okd) return;
  await api('/history/' + id, { method: 'DELETE' });
  renderHistory();
}

/* ---------- users (admin) ---------- */

async function renderUsers() {
  const users = (await api('/users')) || [];
  let html = '<div class="card"><h2>Users</h2>'
    + '<div class="row"><input id="new-user-name" placeholder="username">'
    + '<input id="new-user-pass" type="password" placeholder="password (≥6 chars)">'
    + '<select id="new-user-role"><option value="user">user</option><option value="admin">admin</option></select>'
    + '<button class="primary" onclick="createUser()">Create</button></div></div>';
  html += '<div class="card" style="margin-top:10px"><table><tr><th>#</th><th>username</th><th>role</th><th>enabled</th><th>created</th><th></th></tr>';
  users.forEach((u) => {
    const badge = u.role === 'admin' ? ' <span class="badge admin">admin</span>' : '';
    const en = u.enabled ? '<span class="badge on">on</span>' : '<span class="badge off">off</span>';
    html += '<tr><td>' + u.id + '</td><td>' + esc(u.username) + badge + '</td><td>' + esc(u.role) + '</td><td>' + en + '</td>'
      + '<td class="muted">' + esc(u.created_at || '') + '</td><td>'
      + (u.enabled
        ? '<button class="ghost" onclick="setUserEnabled(' + u.id + ',false)">Disable</button>'
        : '<button class="ghost" onclick="setUserEnabled(' + u.id + ',true)">Enable</button>')
      + ' <button class="ghost" onclick="resetPassword(' + u.id + ')">Reset password</button>'
      + ' <button class="danger" onclick="deleteUser(' + u.id + ')">Delete</button></td></tr>';
  });
  html += '</table></div>';
  $('#content').innerHTML = html;
}

async function createUser() {
  const username = $('#new-user-name').value.trim();
  const password = $('#new-user-pass').value;
  const role = $('#new-user-role').value;
  if (!username || !password) return notify('Username and password are required', 'err');
  await api('/users', { method: 'POST', body: { username: username, password: password, role: role } });
  renderUsers();
}

async function setUserEnabled(id, enabled) {
  await api('/users/' + id + (enabled ? '/enable' : '/disable'), { method: 'POST' });
  renderUsers();
}

async function resetPassword(id) {
  const data = await api('/users/' + id + '/reset-password', { method: 'POST', body: {} });
  await askInput('One-time password', 'password', data.password, {
    message: 'Copy it now — the server never shows it again.',
    readOnly: true,
    copy: true,
    confirmLabel: 'Done',
  });
  renderUsers();
}

async function deleteUser(id) {
  const okd = await askConfirm('Delete user', 'User #' + id + ' and their requests and history will be removed.', 'Delete');
  if (!okd) return;
  await api('/users/' + id, { method: 'DELETE' });
  renderUsers();
}

/* ---------- settings (admin) ---------- */

async function renderSettings() {
  const s = await api('/settings');
  $('#content').innerHTML = '<div class="card"><h2>Settings</h2>'
    + '<div class="col">'
    + '<label>SSRF whitelist (CIDRs)<input id="set-whitelist" style="width:100%" value="' + escAttr(s.ssrf_whitelist || '') + '"></label>'
    + '<label>Execution timeout (e.g. 60s, 2m)<input id="set-timeout" value="' + escAttr(s.exec_timeout || '') + '"></label>'
    + '<label>History retention (rows)<input id="set-maxhist" value="' + escAttr(s.max_history || '') + '"></label>'
    + '<label>Proxy URL <input id="set-proxy" style="width:100%" placeholder="http://10.0.0.9:3128 (empty = direct)" value="' + escAttr(s.proxy_url || '') + '"></label>'
    + '<p class="hint">http:// or https:// only. A request uses it only when its own <b>use proxy</b> box is ticked'
    + ' (off by default). While a request goes through the proxy, the SSRF whitelist no longer filters the target —'
    + ' the proxy resolves it — so point this at a host you trust.</p>'
    + '<div class="row"><button class="primary" onclick="saveSettings()">Save</button><span id="set-status" class="muted"></span></div>'
    + '</div></div>';
}

async function saveSettings() {
  const body = {
    ssrf_whitelist: $('#set-whitelist').value,
    exec_timeout: $('#set-timeout').value,
    max_history: $('#set-maxhist').value,
    proxy_url: $('#set-proxy').value,
  };
  $('#set-status').textContent = 'saving…';
  try {
    await api('/settings', { method: 'PUT', body: body });
    $('#set-status').textContent = 'saved';
  } catch (e) {
    $('#set-status').textContent = 'failed: ' + e.message;
  }
}

/* ---------- wiring ---------- */

document.addEventListener('DOMContentLoaded', () => {
  // Button handlers are fire-and-forget. Without this their failures vanish
  // into the console and the UI looks like it ignored the click.
  window.addEventListener('unhandledrejection', (ev) => {
    const reason = ev.reason;
    flash('failed: ' + ((reason && reason.message) || reason), true);
    ev.preventDefault();
  });
  $('#theme-select').addEventListener('change', (ev) => applyTheme(ev.target.value));
  $('#login-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    $('#login-err').textContent = '';
    try {
      const enc = await encryptPassword($('#login-pass').value);
      await api('/auth/login', {
        method: 'POST',
        body: { username: $('#login-user').value, enc },
      });
      $('#login-pass').value = '';
      await startApp();
    } catch (e) {
      $('#login-err').textContent = e.message;
    }
  });
  $('#btn-logout').addEventListener('click', async () => {
    try { await api('/auth/logout', { method: 'POST' }); } catch (e) { /* ignore */ }
    showLogin();
  });
  $('#main-nav').addEventListener('click', (ev) => {
    const btn = ev.target.closest('button[data-view]');
    if (btn) setView(btn.dataset.view);
  });
  // Keyboard first, buttons second: Enter in the URL field and Ctrl/Cmd+Enter
  // both send, Ctrl/Cmd+S saves without opening the browser's save dialog.
  document.addEventListener('keydown', (ev) => {
    if (!$('#btn-send')) return;              // not in the editor
    if (!$('#dialog').hidden) return;         // a dialog owns the keyboard
    if (ev.key === 'Enter' && ev.target && ev.target.id === 'req-url') {
      ev.preventDefault();
      sendRequest();
      return;
    }
    if (!(ev.ctrlKey || ev.metaKey)) return;
    if (ev.key === 'Enter') {
      ev.preventDefault();
      sendRequest();
    } else if (ev.key.toLowerCase() === 's') {
      ev.preventDefault();
      saveRequest();
    }
  });
  // Try to resume an existing session.
  api('/auth/me').then(() => startApp()).catch(() => showLogin());
});
