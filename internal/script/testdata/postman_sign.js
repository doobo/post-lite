// post-lite example: Ed25519 detached signature, the equivalent of section 4 of
// docs/post-lite-script.md, with no Node.js and no npm install.
//
// It is run by TestExampleScriptProducesAVerifiableSignature, which then checks
// the signature with Go's crypto/ed25519 — so the script has to hand its
// material back through globalThis.result.
const PRIVATE_KEY_BASE64 = 'nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A='; // 32B Ed25519 seed
const APP_KEY = 'demo-app-key';

const uuid = pm.require('npm:uuid@9.0.0');

const timestamp = Math.floor(Date.now() / 1000).toString();
const nonce = uuid.v4();
const method = 'POST';
const url = '/openApi/v1/orders';

const signContent = `${method}\n${url}\n${timestamp}\n${nonce}`;

// Native API: one call, no base64/UTF-8 helpers of our own. The seed is base64
// while the payload is UTF-8, so the seed gets its own encoding.
const signature = pm.crypto.ed25519.sign({
    seed: PRIVATE_KEY_BASE64,
    seedEncoding: 'base64',
    data: signContent,
    inputEncoding: 'utf8',
    outputEncoding: 'base64',
});

// Compatibility layer: the same result the way a migrated Postman script does
// it, plugging tweetnacl's own util codecs in for the helpers it used to carry.
const nacl = pm.require('npm:tweetnacl@1.0.3');
const keyPair = nacl.sign.keyPair.fromSeed(nacl.util.decodeBase64(PRIVATE_KEY_BASE64));
const legacySignature = nacl.util.encodeBase64(
    nacl.sign.detached(nacl.util.decodeUTF8(signContent), keyPair.secretKey),
);

const headers = {
    'bsi-openapi-appkey': APP_KEY,
    'bsi-openapi-sign': signature,
};

console.log('signed %s %s at %s', method, url, timestamp);

globalThis.result = {
    signContent,
    nonce,
    signature,
    legacySignature,
    publicKey: nacl.util.encodeHex(keyPair.publicKey),
    headers,
};
