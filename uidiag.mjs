// Temporary: diagnose why a login click leaves the SPA on the login page.
const BASE = 'http://127.0.0.1:5681';
const CDP = 'http://127.0.0.1:9222';
const PW = process.env.ADMIN_PW;

if (!PW) {
  console.error('ADMIN_PW is required');
  process.exit(2);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const targets = await (await fetch(CDP + '/json/list')).json();
const page = targets.find((t) => t.type === 'page');
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
  } else events.push(msg);
});
await new Promise((r) => ws.addEventListener('open', r));
const send = (method, params = {}) => new Promise((res, rej) => {
  const i = ++id;
  pending.set(i, { res, rej });
  ws.send(JSON.stringify({ id: i, method, params }));
});

async function evaluate(expr) {
  const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) return 'JS-EXCEPTION: ' + (r.exceptionDetails.exception?.description || r.exceptionDetails.text);
  return r.result.value;
}

await send('Runtime.enable');
await send('Page.enable');
await send('Page.addScriptToEvaluateOnNewDocument', {
  source: `
    window.__calls = [];
    window.__errs = [];
    const _f = window.fetch;
    window.fetch = function () {
      const url = String(arguments[0]);
      return _f.apply(this, arguments).then(
        (res) => { window.__calls.push(url + ' -> ' + res.status); return res; },
        (err) => { window.__calls.push(url + ' -> NETWORK ' + err); throw err; }
      );
    };
    window.addEventListener('error', (e) => window.__errs.push('error: ' + e.message + '\\n' + ((e.error && e.error.stack) || '')));
    window.addEventListener('unhandledrejection', (e) => {
      const r = e.reason;
      window.__errs.push('rejection: ' + ((r && r.message) || r) + '\\n' + ((r && r.stack) || ''));
    });
  `,
});
await send('Page.navigate', { url: BASE + '/' });
await sleep(2500);

console.log('--- before click ---');
console.log('readyState   :', await evaluate('document.readyState'));
console.log('state.user   :', JSON.stringify(await evaluate('state && state.user')));
console.log('state.view   :', JSON.stringify(await evaluate('state && state.view')));
console.log('login-err    :', JSON.stringify(await evaluate(`document.querySelector('#login-err').textContent`)));
console.log('cookie       :', JSON.stringify(await evaluate('document.cookie')));
console.log('login visible:', await evaluate(`getComputedStyle(document.querySelector('#login-view')).display`));
console.log('app visible  :', await evaluate(`getComputedStyle(document.querySelector('#app-view')).display`));
console.log('fetch calls  :', JSON.stringify(await evaluate('window.__calls')));

console.log('\n--- clicking Sign in ---');
console.log(await evaluate(`document.querySelector('#login-user').value = 'admin';
  document.querySelector('#login-pass').value = ${JSON.stringify(PW)};
  document.querySelector('#login-form button[type=submit]').click(); 'clicked'`));

for (let i = 0; i < 12; i++) {
  await sleep(400);
  const line = await evaluate(`JSON.stringify({
    user: state && state.user && state.user.username,
    view: state && state.view,
    err: document.querySelector('#login-err').textContent,
    login: getComputedStyle(document.querySelector('#login-view')).display,
    app: getComputedStyle(document.querySelector('#app-view')).display,
    calls: window.__calls.slice(-4),
    errs: window.__errs.length,
  })`);
  console.log(`t+${((i + 1) * 400) / 1000}s ` + line);
}

console.log('\n--- captured JS errors ---');
console.log(JSON.stringify(await evaluate('window.__errs'), null, 2));
console.log('\n--- all fetch calls ---');
console.log(JSON.stringify(await evaluate('window.__calls'), null, 2));
const exceptions = events.filter((e) => e.method === 'Runtime.exceptionThrown');
console.log('\n--- CDP exceptions ---');
exceptions.forEach((e) => console.log(JSON.stringify(e.params.exceptionDetails.exception?.description || e.params.exceptionDetails.text)));
ws.close();
