// Temporary UI walkthrough: drives the real SPA in Chrome over the DevTools
// protocol (no dependencies) and asserts what the user would see.
//   ADMIN_PW=... BASE_URL=http://127.0.0.1:5681 node uitest.mjs
const BASE = process.env.BASE_URL || 'http://127.0.0.1:5681';
const CDP = process.env.CDP_URL || 'http://127.0.0.1:9222';
const ADMIN_PW = process.env.ADMIN_PW;
const SECRET_VALUE = 'DEMO-SECRET-9f3a';

if (!ADMIN_PW) {
  console.error('ADMIN_PW is required');
  process.exit(2);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];
let client;
let signedIn = false;

async function connect() {
  const targets = await (await fetch(CDP + '/json/list')).json();
  const page = targets.find((t) => t.type === 'page');
  if (!page) throw new Error('no page target: ' + JSON.stringify(targets));
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  const pending = new Map();
  const events = [];
  let id = 0;
  ws.addEventListener('message', (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && pending.has(msg.id)) {
      const p = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? p.rej(new Error(JSON.stringify(msg.error))) : p.res(msg.result);
      return;
    }
    events.push(msg);
  });
  await new Promise((res, rej) => { ws.addEventListener('open', res); ws.addEventListener('error', rej); });
  const send = (method, params = {}) => new Promise((res, rej) => {
    const i = ++id;
    pending.set(i, { res, rej });
    ws.send(JSON.stringify({ id: i, method, params }));
  });
  return { send, events, close: () => ws.close() };
}

async function evaluate(expr) {
  const r = await client.send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) {
    const d = r.exceptionDetails;
    throw new Error('JS exception: ' + ((d.exception && d.exception.description) || d.text));
  }
  return r.result.value;
}

async function waitFor(label, expr, timeout = 8000) {
  const deadline = Date.now() + timeout;
  let last;
  while (Date.now() < deadline) {
    last = await evaluate(expr);
    if (last) return last;
    await sleep(120);
  }
  throw new Error(`timed out waiting for ${label} (last=${JSON.stringify(last)})`);
}

function expect(name, ok, detail) {
  if (!ok) throw new Error(name + (detail ? ' — ' + detail : ''));
}

async function step(name, fn, needsAuth = true) {
  if (needsAuth && !signedIn) {
    results.push({ name, ok: false, note: 'skipped: not signed in' });
    console.log('SKIP  ' + name + ' (not signed in)');
    return;
  }
  try {
    const note = await fn();
    results.push({ name, ok: true });
    console.log('PASS  ' + name + (note ? '  [' + note + ']' : ''));
  } catch (e) {
    results.push({ name, ok: false, note: e.message });
    console.log('FAIL  ' + name + '\n        ' + e.message);
  }
}

// Simulate a real sign-in through the form and report exactly what the page said.
async function signIn(username, password) {
  await waitFor('login form', `!!document.querySelector('#login-user')`);
  await evaluate(`document.querySelector('#login-user').value = ${JSON.stringify(username)};
    document.querySelector('#login-pass').value = ${JSON.stringify(password)};
    document.querySelector('#login-form button[type=submit]').click(); true`);
  const deadline = Date.now() + 8000;
  while (Date.now() < deadline) {
    const state = await evaluate(`JSON.stringify({
      who: document.querySelector('#who').textContent,
      err: document.querySelector('#login-err').textContent,
      view: (() => { const el = document.querySelector('#app-view');
        return getComputedStyle(el).display !== 'none' ? 'app' : 'login'; })(),
    })`);
    const s = JSON.parse(state);
    if (s.view === 'app' && s.who.includes(username)) { signedIn = true; return s.who.trim(); }
    if (s.err) throw new Error('the page reported: ' + s.err);
    await sleep(150);
  }
  const err = await evaluate(`document.querySelector('#login-err').textContent`);
  throw new Error('still on the login page after 8s' + (err ? ' — ' + err : ' (no message shown)'));
}

const clickNav = (view) => `document.querySelector('nav button[data-view="${view}"]').click(); true`;
const btnByText = (root, text) =>
  `[...document.querySelectorAll(${JSON.stringify(root)} + ' button')].find(b => b.textContent.trim() === ${JSON.stringify(text)})`;
const cssVisible = (sel) =>
  `(() => { const el = document.querySelector(${JSON.stringify(sel)});
     if (!el) return 'missing';
     const cs = getComputedStyle(el);
     if (cs.display === 'none') return 'display:none';
     if (cs.visibility === 'hidden') return 'visibility:hidden';
     const r = el.getBoundingClientRect();
     return (r.width > 0 && r.height > 0) ? 'visible' : 'zero-size'; })()`;

async function main() {
  client = await connect();
  await client.send('Runtime.enable');
  await client.send('Page.enable');
  await client.send('Log.enable');

  client.events.length = 0;
  await client.send('Page.addScriptToEvaluateOnNewDocument', {
    source: `
      window.__errs = [];
      window.__alerts = [];
      window.__prompts = [];
      window.__promptAnswer = 'folder-1';
      window.addEventListener('error', (e) => window.__errs.push('error: ' + e.message));
      window.addEventListener('unhandledrejection', (e) => {
        const r = e.reason;
        const msg = (r && r.message) || r;
        // The app calls preventDefault() for failures it reports in the UI;
        // only unprevented rejections are real crashes.
        setTimeout(() => { if (!e.defaultPrevented) window.__errs.push('unhandledrejection: ' + msg); }, 0);
      });
      // Native dialogs would block the page under CDP; stub them like a user
      // clicking OK (and record what was asked).
      window.prompt = (msg, def) => { window.__prompts.push({ msg: msg, def: def }); return window.__promptAnswer; };
      window.confirm = (msg) => { window.__alerts.push('confirm: ' + msg); return true; };
      window.alert = (msg) => { window.__alerts.push('alert: ' + msg); };
    `,
  });

  await client.send('Page.navigate', { url: BASE + '/' });
  await waitFor('page load', `document.readyState === 'complete' && !!document.querySelector('#login-form')`);

  await step('login page renders and is visible', async () => {
    expect('login view visible', (await evaluate(cssVisible('#login-view'))) === 'visible');
    expect('app view hidden', (await evaluate(cssVisible('#app-view'))) !== 'visible');
    const title = await evaluate('document.title');
    expect('page title', title === 'PostLite', 'title=' + title);
    return 'title=' + title;
  }, false);

  await step('SIGN IN: the app view replaces the login view', async () => signIn('admin', ADMIN_PW), false);

  await step('fresh install: the default view says what to do first', async () => {
    await waitFor('a view rendered', `document.querySelector('#content').textContent.trim().length > 0`);
    const text = await evaluate(`document.querySelector('#content').textContent`);
    expect('no-collections hint', text.includes('No collections yet'), text.slice(0, 120));
    const active = await evaluate(`document.querySelector('nav button[data-view="editor"]').classList.contains('active')`);
    expect('editor nav active', active === true);
    return 'editor shows the no-collections hint';
  });

  await step('SECRETS: store a secret, the UI must never show the value', async () => {
    await evaluate(clickNav('secrets'));
    await waitFor('secrets view', `!!document.querySelector('#new-sec-name')`);
    await evaluate(`document.querySelector('#new-sec-name').value = 'demo_key';
      document.querySelector('#new-sec-value').value = ${JSON.stringify(SECRET_VALUE)};
      ${btnByText('#content', 'Store encrypted')}.click(); true`);
    await waitFor('secret listed', `document.querySelector('#content').textContent.includes('demo_key')`);
    const text = await evaluate('document.body.innerText');
    expect('secret value not rendered', !text.includes(SECRET_VALUE));
    expect('write-only note shown', text.includes('write-only'));
    return 'demo_key stored';
  });

  await step('COLLECTIONS: create collection, folder and request', async () => {
    await evaluate(clickNav('collections'));
    await waitFor('collections view', `!!document.querySelector('#new-coll-name')`);
    await evaluate(`document.querySelector('#new-coll-name').value = 'UI Smoke';
      ${btnByText('#content', 'Create')}.click(); true`);
    await waitFor('collection in tree', `document.querySelector('#tree').textContent.includes('UI Smoke')`);

    await evaluate(`${btnByText('#content', '+ Folder')}.click(); true`);
    await waitFor('folder in tree', `document.querySelector('#tree').textContent.includes('folder-1')`);

    await evaluate(`${btnByText('#content', '+ Request')}.click(); true`);
    await waitFor('editor opened', `!!document.querySelector('#req-url')`);
    return 'collection + folder-1 + request';
  });

  await step('EDITOR: fill, save and send with {{sec.NAME}} + temp vars', async () => {
    await evaluate(`
      document.querySelector('#req-name').value = 'ui smoke request';
      document.querySelector('#req-method').value = 'GET';
      document.querySelector('#req-url').value = ${JSON.stringify(BASE + '/?probe={{sec.demo_key}}')};
      document.querySelector('#req-bodytype').value = 'json';
      document.querySelector('#req-body').value = '{"note":"{{sec.demo_key}}"}';
      true`);
    await evaluate(`${btnByText('#req-headers', '+ row')}.click(); true`);
    await waitFor('header row', `document.querySelectorAll('#req-headers .kvrow').length === 1`);
    await evaluate(`(() => { const r = document.querySelector('#req-headers .kvrow');
      r.querySelector('.k').value = 'X-Demo';
      r.querySelector('.v').value = 'Bearer {{sec.demo_key}}'; })(); true`);
    await evaluate(`${btnByText('#req-vars', '+ row')}.click(); true`);
    await waitFor('temp var row', `document.querySelectorAll('#req-vars .kvrow').length === 1`);
    await evaluate(`(() => { const r = document.querySelector('#req-vars .kvrow');
      r.querySelector('.k').value = 'who';
      r.querySelector('.v').value = 'ui-smoke'; })(); true`);

    await evaluate(`document.querySelector('#btn-save').click(); true`);
    await waitFor('saved', `document.querySelector('#send-status').textContent.startsWith('saved #')`);
    const saved = await evaluate(`document.querySelector('#send-status').textContent`);

    await evaluate(`document.querySelector('#btn-send').click(); true`);
    await waitFor('result panel', `!!document.querySelector('#result .result')`, 10000);
    const result = await evaluate(`document.querySelector('#result').textContent`);
    expect('status 200 rendered', /Response\s*200/.test(result), result.slice(0, 140));
    expect('final url masked', result.includes('key=***'), result.slice(0, 200));
    expect('secret never shown', !result.includes(SECRET_VALUE));
    expect('response headers rendered', result.includes('Content-Type'));
    return saved.trim();
  });

  await step('EDITOR: an unresolved placeholder is reported, not swallowed', async () => {
    await evaluate(`document.querySelector('#req-url').value = ${JSON.stringify(BASE + '/?x={{nope}}')}; true`);
    await evaluate(`document.querySelector('#btn-send').click(); true`);
    await waitFor('final send status', `/^(error|saved)/.test(document.querySelector('#send-status').textContent)`, 8000);
    const status = await evaluate(`document.querySelector('#send-status').textContent`);
    expect('error surfaced in the editor', /error|unresolved|placeholder/i.test(status), status);
    return status.trim();
  });

  await step('HISTORY: lists the execution redacted, with a detail view', async () => {
    await evaluate(clickNav('history'));
    await waitFor('history rows', `document.querySelectorAll('#content tr').length > 1`);
    const text = await evaluate('document.body.innerText');
    expect('secret never in the history view', !text.includes(SECRET_VALUE));
    expect('masked url shown', text.includes('***'));
    await evaluate(`[...document.querySelectorAll('#content button')].find(b => b.textContent.trim() === 'View').click(); true`);
    await waitFor('history detail', `document.querySelector('#hist-detail').textContent.trim().length > 0`);
    const detail = await evaluate(`document.querySelector('#hist-detail').textContent`);
    expect('detail redacted', !detail.includes(SECRET_VALUE) && detail.includes('***'));
    return 'detail rendered';
  });

  await step('SETTINGS: loads, saves, persists and rejects bad input', async () => {
    await evaluate(clickNav('settings'));
    await waitFor('settings form', `!!document.querySelector('#set-whitelist')`);
    const whitelist = await evaluate(`document.querySelector('#set-whitelist').value`);
    expect('whitelist loaded', whitelist.includes('127.0.0.0/8'), whitelist);
    const timeout = await evaluate(`document.querySelector('#set-timeout').value`);
    expect('timeout loaded', timeout.length > 0, timeout);

    await evaluate(`document.querySelector('#set-maxhist').value = '50';
      ${btnByText('#content', 'Save')}.click(); true`);
    await waitFor('saved status', `document.querySelector('#set-status').textContent === 'saved'`);

    await evaluate(clickNav('editor'));
    await waitFor('editor back', `!!document.querySelector('#req-url')`);
    await evaluate(clickNav('settings'));
    await waitFor('settings form again', `!!document.querySelector('#set-maxhist')`);
    const persisted = await evaluate(`document.querySelector('#set-maxhist').value`);
    expect('max_history persisted', persisted === '50', 'value=' + persisted);

    await evaluate(`document.querySelector('#set-timeout').value = 'soon';
      ${btnByText('#content', 'Save')}.click(); true`);
    await waitFor('failure status', `/failed/.test(document.querySelector('#set-status').textContent)`, 8000);
    const msg = await evaluate(`document.querySelector('#set-status').textContent`);

    await evaluate(`document.querySelector('#set-timeout').value = '60s';
      ${btnByText('#content', 'Save')}.click(); true`);
    await waitFor('saved again', `document.querySelector('#set-status').textContent === 'saved'`);
    return 'max_history=50; ' + msg.trim();
  });

  await step('ENVIRONMENTS: create, set vars, activate and use via {{VAR}}', async () => {
    await evaluate(clickNav('environments'));
    await waitFor('environments view', `!!document.querySelector('#new-env-name')`);
    await evaluate(`document.querySelector('#new-env-name').value = 'UI Env';
      document.querySelector('#new-env-scope').value = 'user';
      ${btnByText('#content', 'Create')}.click(); true`);
    await waitFor('env listed', `document.querySelector('#content').textContent.includes('UI Env')`);

    const envId = await evaluate(`(state.envs.find(e => e.name === 'UI Env') || {}).id`);
    expect('env has an id', !!envId, 'envId=' + envId);

    await evaluate(`(() => { const box = document.querySelector('#env-vars-${envId}');
      [...box.querySelectorAll('button')].find(b => b.textContent.includes('+ row')).click(); })(); true`);
    await waitFor('env var row', `document.querySelectorAll('#env-vars-${envId} .kvrow').length > 0`);
    await evaluate(`(() => { const r = document.querySelector('#env-vars-${envId} .kvrow');
      r.querySelector('.k').value = 'host';
      r.querySelector('.v').value = '127.0.0.1:5681'; })(); true`);
    await evaluate(`${btnByText('#content', 'Save vars')}.click(); true`);
    await waitFor('vars saved', `window.__alerts.some(a => a.includes('saved'))`, 6000);

    await evaluate(`${btnByText('#content', 'Set active user')}.click(); true`);
    await waitFor('env activated', `window.__alerts.some(a => a.includes('active'))`, 6000);

    await evaluate(clickNav('editor'));
    await waitFor('editor back', `!!document.querySelector('#req-url')`);
    await evaluate(`document.querySelector('#req-url').value = 'http://{{host}}/';
      document.querySelector('#req-vars').innerHTML = '';
      document.querySelector('#req-headers').innerHTML = '';
      document.querySelector('#req-method').value = 'GET';
      document.querySelector('#req-bodytype').value = 'none';
      document.querySelector('#btn-send').click(); true`);
    await waitFor('result panel', `!!document.querySelector('#result .result')`, 10000);
    const result = await evaluate(`document.querySelector('#result').textContent`);
    expect('{{host}} resolved from the active env', /Response\s*200/.test(result), result.slice(0, 160));
    return 'active user env applied';
  });

  await step('USERS: create, disable, reset password, enable', async () => {
    await evaluate(clickNav('users'));
    await waitFor('users view', `!!document.querySelector('#new-user-name')`);
    await evaluate(`document.querySelector('#new-user-name').value = 'ui-tester';
      document.querySelector('#new-user-pass').value = 'pw123456';
      document.querySelector('#new-user-role').value = 'user';
      ${btnByText('#content', 'Create')}.click(); true`);
    await waitFor('user listed', `document.querySelector('#content').textContent.includes('ui-tester')`);

    const row = `[...document.querySelectorAll('#content tr')].find(tr => tr.textContent.includes('ui-tester'))`;
    await evaluate(`(${row}).querySelector('button.ghost').click(); true`);
    await waitFor('user disabled', `(${row}).textContent.includes('off')`);

    await evaluate(`[...(${row}).querySelectorAll('button')].find(b => b.textContent.trim() === 'Reset password').click(); true`);
    await waitFor('password prompted', `window.__prompts.length > 0`, 6000);
    const prompted = await evaluate(`window.__prompts[window.__prompts.length - 1].def`);
    expect('one-time password handed to the admin', typeof prompted === 'string' && prompted.length >= 8, 'pw=' + prompted);

    await evaluate(`(${row}).querySelector('button.ghost').click(); true`);
    await waitFor('user enabled', `(${row}).textContent.includes('on')`);
    return 'created, disabled, reset, enabled';
  });

  await step('ERROR FEEDBACK: a rejected action is reported, not swallowed', async () => {
    await evaluate(clickNav('users'));
    await waitFor('users view', `document.querySelector('#content').textContent.includes('admin')`);
    // Disabling your own account is refused by the server.
    const ownRow = `[...document.querySelectorAll('#content tr')].find(tr => /(^|\s)admin(\s|$)/.test(tr.cells[1].textContent))`;
    await evaluate(`(${ownRow}).querySelector('button.ghost').click(); true`);
    await waitFor('flash message', `document.querySelector('#flash').textContent.length > 0`, 6000);
    const msg = await evaluate(`document.querySelector('#flash').textContent`);
    expect('failure surfaced in the UI', /failed:/.test(msg), msg);
    return msg.trim();
  });

  await step('RBAC: a plain user gets no admin navigation', async () => {
    await evaluate(`${btnByText('header', 'Log out')}.click(); true`);
    await waitFor('login view back', `${cssVisible('#login-view')} === 'visible'`, 6000);
    signedIn = false;
    const who = await signIn('ui-tester', 'pw123456');
    const displays = await evaluate(`[...document.querySelectorAll('.admin-only')].map(b => getComputedStyle(b).display)`);
    expect('admin-only nav hidden', displays.every((d) => d === 'none'), JSON.stringify(displays));

    await evaluate(clickNav('settings'));
    await waitFor('redirected to editor', `!!document.querySelector('#req-url')`, 6000);
    const active = await evaluate(`document.querySelector('nav button[data-view="editor"]').classList.contains('active')`);
    expect('settings view refused', active === true);
    return who + ' — nav filtered, settings blocked';
  }, false);

  await step('cleanup: admin logs back in and deletes the test user', async () => {
    if (signedIn) {
      await evaluate(`${btnByText('header', 'Log out')}.click(); true`);
      await waitFor('login view back', `${cssVisible('#login-view')} === 'visible'`, 6000);
      signedIn = false;
    }
    await signIn('admin', ADMIN_PW);
    await evaluate(clickNav('users'));
    await waitFor('users view', `document.querySelector('#content').textContent.includes('ui-tester')`);
    const row = `[...document.querySelectorAll('#content tr')].find(tr => tr.textContent.includes('ui-tester'))`;
    await evaluate(`${row}.querySelector('button.danger').click(); true`);
    await waitFor('user gone', `!document.querySelector('#content').textContent.includes('ui-tester')`, 8000);
    return 'ui-tester removed';
  }, false);

  const pageErrs = await evaluate('window.__errs');
  const consoleErrs = client.events
    .filter((e) => e.method === 'Log.entryAdded' && e.params.entry.level === 'error')
    .map((e) => 'console: ' + e.params.entry.text);
  const exceptions = client.events
    .filter((e) => e.method === 'Runtime.exceptionThrown')
    .map((e) => 'exception: ' + e.params.exceptionDetails.text);
  const allErrs = [...new Set([...pageErrs, ...consoleErrs, ...exceptions])].filter(
    (e) => !/status of 401/.test(e), // the expected "no session yet" probe
  );

  console.log('\n================ summary ================');
  const failed = results.filter((r) => !r.ok);
  console.log(`${results.length - failed.length}/${results.length} UI steps passed`);
  failed.forEach((f) => console.log('  FAILED: ' + f.name + ' — ' + f.note));
  console.log(allErrs.length ? `JS errors (${allErrs.length}):\n  ` + allErrs.join('\n  ') : 'JS errors: none');
  client.close();
  process.exit(failed.length || allErrs.length ? 1 : 0);
}

main().catch((e) => {
  console.error('FATAL: ' + e.stack);
  process.exit(2);
});
