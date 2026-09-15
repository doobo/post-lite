'use strict';
/* PostLite SPA — vanilla JS, no CDN, no build step. */

const state = {
  user: null,
  view: 'editor',
  collections: [],
  treeData: {},   // collId -> {collection, folders, requests}
  current: null,  // request being edited
  envs: [],
  results: null,
};

const $ = (s, el) => (el || document).querySelector(s);
const $$ = (s, el) => Array.from((el || document).querySelectorAll(s));
const esc = (s) => String(s == null ? '' : s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
const escAttr = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// flash shows a short-lived status line in the header, so actions triggered
// from a button always report their outcome.
let flashTimer = null;
function flash(msg, isErr) {
  const el = $('#flash');
  if (!el) return;
  el.textContent = msg;
  el.className = isErr ? 'err' : 'ok';
  if (flashTimer) clearTimeout(flashTimer);
  flashTimer = setTimeout(() => { el.textContent = ''; }, 8000);
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
  $('#who').textContent = state.user.username + ' (' + state.user.role + ')';
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

function renderTree() {
  const t = $('#tree');
  let html = '<h3>Collections</h3>';
  for (const c of state.collections) {
    const d = state.treeData[c.id];
    const tag = c.owner_id == null ? ' <span class="badge">global</span>' : '';
    html += '<div class="node coll" onclick="openCollection(' + c.id + ')"><span class="icon">▸</span><span>' + esc(c.name) + tag + '</span></div>';
    if (!d) continue;
    const folders = d.folders || [];
    const reqs = d.requests || [];
    const topFolders = folders.filter((f) => f.parent_id == null);
    const topReqs = reqs.filter((r) => r.folder_id == null);
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
      html += '<div class="node fold" style="margin-left:' + (12 + depth * 12) + 'px"><span class="icon">▹</span><span>' + esc(f.name) + '</span></div>';
      (reqByFolder[String(f.id)] || []).forEach((r) => {
        html += '<div class="node req" style="margin-left:' + (24 + depth * 12) + 'px" onclick="loadRequest(' + r.id + ')"><span class="badge">' + esc(r.method) + '</span><span>' + esc(r.name) + '</span></div>';
      });
      (byParent[String(f.id)] || []).forEach((sf) => renderFolder(sf, depth + 1));
    };
    (byParent.root || []).forEach((f) => renderFolder(f, 0));
    (reqByFolder.root || []).forEach((r) => {
      html += '<div class="node req" onclick="loadRequest(' + r.id + ')"><span class="badge">' + esc(r.method) + '</span><span>' + esc(r.name) + '</span></div>';
    });
  }
  t.innerHTML = html;
}

async function openCollection(id) {
  setView('collections');
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
  if (!name) return alert('name required');
  const global = $('#new-coll-global') ? $('#new-coll-global').checked : false;
  await api('/collections', { method: 'POST', body: { name: name, global: global } });
  await loadCollections();
  renderCollections();
}

async function deleteCollection(id) {
  if (!confirm('Delete collection #' + id + ' and all its requests?')) return;
  await api('/collections/' + id, { method: 'DELETE' });
  state.collections = state.collections.filter((c) => c.id !== id);
  delete state.treeData[id];
  renderTree();
  renderCollections();
}

async function createFolderPrompt(collId) {
  const name = prompt('Folder name:');
  if (!name) return;
  await api('/collections/' + collId + '/folders', { method: 'POST', body: { name: name } });
  await loadCollections();
  renderCollections();
}

async function exportCollection(id) {
  const res = await fetch('/api/collections/' + id + '/export', { method: 'POST', credentials: 'same-origin' });
  if (!res.ok) return alert('export failed: ' + res.statusText);
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
  if (!f) return alert('choose a JSON file first');
  const text = await f.text();
  const global = $('#import-global') ? $('#import-global').checked : false;
  const data = await api('/collections/import', { method: 'POST', body: { json: text, global: global } });
  await loadCollections();
  renderCollections();
  alert('imported as collection #' + data.id);
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
  let html = (pairs || []).map(() => '').join('');
  html = (pairs || []).map((p) =>
    '<div class="kvrow"><input class="k" placeholder="' + escAttr(keyPh) + '" value="' + escAttr(p.k) + '">'
    + '<input class="v" placeholder="' + escAttr(valPh) + '" value="' + escAttr(p.v) + '">'
    + '<button class="ghost" onclick="delRow(this)" title="Remove">&times;</button></div>'
  ).join('');
  return html + '<div><button class="ghost" onclick="addRow(this)">+ row</button></div>';
}

function addRow(btn) {
  const row = document.createElement('div');
  row.className = 'kvrow';
  row.innerHTML = '<input class="k" placeholder="key"><input class="v" placeholder="value"><button class="ghost" onclick="delRow(this)">&times;</button>';
  btn.parentElement.before(row);
}

function delRow(btn) { btn.parentElement.remove(); }

function collectKV(container) {
  return $$('.kvrow', container).map((r) => ({
    k: $('.k', r).value,
    v: $('.v', r).value,
  })).filter((p) => p.k !== '' || p.v !== '');
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
  };
  state.results = null;
  setView('editor');
}

async function renderEditor() {
  if (!state.current) {
    if (state.collections.length === 0) {
      $('#content').innerHTML = '<div class="card"><p class="muted">No collections yet. Create one under <b>Collections</b> first.</p></div>';
      return;
    }
    await newRequest(state.collections[0].id);
    return;
  }
  const c = state.current;
  const gEnvs = state.envs.filter((e) => e.scope === 'global');
  const uEnvs = state.envs.filter((e) => e.scope === 'user');
  $('#content').innerHTML =
    '<div class="card"><div class="row">'
    + '<input id="req-name" placeholder="Request name" value="' + escAttr(c.name) + '" style="max-width:220px">'
    + '<select id="req-method">' + ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map((m) => '<option' + (c.method === m ? ' selected' : '') + '>' + m + '</option>').join('') + '</select>'
    + '<input id="req-url" class="url" placeholder=http://host:8080/path — {{VAR}} / {{sec.NAME}} supported" value="' + escAttr(c.url) + '">'
    + '<button id="btn-save" onclick="saveRequest()">Save</button>'
    + '</div>'
    + '<div class="row"><label>Collection <select id="req-coll" onchange="onCollChange()">' + collOptions(c.collection_id) + '</select></label>'
    + '<label>Folder <select id="req-folder">' + folderOptions(c.collection_id, c.folder_id) + '</select></label>'
    + '<label>Global env <select id="req-genv"><option value="">(active)</option>' + gEnvs.map((e) => '<option value="' + e.id + '">' + esc(e.name) + '</option>').join('') + '</select></label>'
    + '<label>User env <select id="req-uenv"><option value="">(active)</option>' + uEnvs.map((e) => '<option value="' + e.id + '">' + esc(e.name) + '</option>').join('') + '</select></label>'
    + '<label><input type="checkbox" id="req-follow"> follow redirects</label>'
    + '</div>'
    + '<h3>Headers</h3><div id="req-headers">' + kvRows(objPairs(c.headers), 'Header', 'value') + '</div>'
    + '<h3>Query</h3><div id="req-query">' + kvRows(c.query, 'key', 'value') + '</div>'
    + '<h3>Body</h3><div class="row"><select id="req-bodytype">'
    + ['none', 'json', 'raw'].map((t) => '<option value="' + t + '"' + (c.body_type === t ? ' selected' : '') + '>' + t + '</option>').join('')
    + '</select></div>'
    + '<textarea id="req-body" rows="6" placeholder=\'{"key":"value"} — {{VAR}} / {{sec.NAME}} allowed\'>' + esc(c.body || '') + '</textarea>'
    + '<h3>Temporary vars (highest priority)</h3><div id="req-vars">' + kvRows([], 'name', 'value') + '</div>'
    + '<div class="row"><button id="btn-send" class="primary" onclick="sendRequest()">Send</button>'
    + '<span id="send-status" class="muted"></span></div>'
    + '<div id="result"></div></div>';
  if (state.results) renderResult();
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

async function sendRequest() {
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
  $('#send-status').textContent = 'sending…';
  $('#result').innerHTML = '';
  try {
    state.results = await api('/execute', { method: 'POST', body: body });
    $('#send-status').textContent = '';
    renderResult();
  } catch (e) {
    $('#send-status').textContent = 'error: ' + e.message;
  }
}

function statusClass(s) {
  if (s >= 200 && s < 300) return 'status-2xx';
  if (s >= 300 && s < 400) return 'status-3xx';
  return 'status-5xx';
}

function renderResult() {
  const d = state.results;
  if (!d) return;
  let html = '<div class="result"><h2>Response <span class="' + statusClass(d.status) + '">' + d.status + ' ' + esc(d.status_text || '') + '</span>'
    + ' <span class="muted">' + d.duration_ms + ' ms</span>'
    + (d.body_truncated ? ' <span class="badge">truncated 10MB</span>' : '')
    + '</h2>';
  if (d.final_url) html += '<p class="muted">final URL: ' + esc(d.final_url) + '</p>';
  if (d.warnings && d.warnings.length) {
    html += '<p class="warn">unresolved: ' + d.warnings.map(esc).join(', ') + '</p>';
  }
  html += '<h3>Headers</h3><pre>' + esc(Object.keys(d.headers || {}).map((k) => k + ': ' + (d.headers[k] || []).join(', ')).join('\n')) + '</pre>';
  html += '<h3>Body <span class="muted">(secrets masked as ***)</span></h3><pre>' + esc(d.body || '') + '</pre></div>';
  $('#result').innerHTML = html;
}

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
  if (!name) return alert('name required');
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
  alert('saved');
}

async function deleteEnv(id) {
  if (!confirm('Delete environment #' + id + '?')) return;
  await api('/environments/' + id, { method: 'DELETE' });
  renderEnvironments();
}

async function activateEnv(id, slot) {
  const body = slot === 'global' ? { global_env_id: id } : { user_env_id: id };
  await api('/environments/activate', { method: 'POST', body: body });
  alert('active ' + slot + ' environment set');
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
  if (!name || !value) return alert('name and value required');
  await api('/secrets', { method: 'POST', body: { name: name, value: value } });
  renderSecrets();
}

async function updateSecret(name, id) {
  const value = $('#sec-val-' + id).value;
  if (!value) return alert('new value required');
  await api('/secrets/' + encodeURIComponent(name), { method: 'PUT', body: { value: value } });
  renderSecrets();
}

async function deleteSecret(id) {
  if (!confirm('Delete secret #' + id + '?')) return;
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
  if (!confirm('Delete history #' + id + '?')) return;
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
  if (!username || !password) return alert('username and password required');
  await api('/users', { method: 'POST', body: { username: username, password: password, role: role } });
  renderUsers();
}

async function setUserEnabled(id, enabled) {
  await api('/users/' + id + (enabled ? '/enable' : '/disable'), { method: 'POST' });
  renderUsers();
}

async function resetPassword(id) {
  const data = await api('/users/' + id + '/reset-password', { method: 'POST', body: {} });
  prompt('New one-time password for user #' + id + ' (copy it now):', data.password);
  renderUsers();
}

async function deleteUser(id) {
  if (!confirm('Delete user #' + id + '?')) return;
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
    + '<div class="row"><button class="primary" onclick="saveSettings()">Save</button><span id="set-status" class="muted"></span></div>'
    + '</div></div>';
}

async function saveSettings() {
  const body = {
    ssrf_whitelist: $('#set-whitelist').value,
    exec_timeout: $('#set-timeout').value,
    max_history: $('#set-maxhist').value,
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
  $('#login-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    $('#login-err').textContent = '';
    try {
      await api('/auth/login', {
        method: 'POST',
        body: { username: $('#login-user').value, password: $('#login-pass').value },
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
  // Try to resume an existing session.
  api('/auth/me').then(() => startApp()).catch(() => showLogin());
});
