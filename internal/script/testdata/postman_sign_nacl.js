const nacl = pm.require('npm:tweetnacl@1.0.3');
const APP_KEY = '***';
const PRIVATE_KEY_BASE64 = '***';
const VERSION = "1.0.0";
// timestamp
const timestamp = Math.floor(Date.now() / 1000).toString();
// nonce
const nonce = uuidv4();
// method
const method = pm.request.method.toUpperCase();
// url
const url = pm.request.url.getPathWithQuery().replace('/openApi', '');
// sign content
const signContent =
    `${method}\n` +
    `${url}\n` +
    `${timestamp}\n` +
    `${nonce}`;
console.log(signContent);
// base64 -> Uint8Array
function base64ToUint8Array(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

// Uint8Array -> Base64
function uint8ArrayToBase64(bytes) {

    let binary = "";

    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }

    return btoa(binary);
}

// UTF8
function utf8ToUint8Array(str) {

    return new TextEncoder().encode(str);
}

// seed
const seed = base64ToUint8Array(PRIVATE_KEY_BASE64);

const keyPair = nacl.sign.keyPair.fromSeed(seed);

// sign
const signature = nacl.sign.detached(
    utf8ToUint8Array(signContent),
    keyPair.secretKey
);

const signatureBase64 = uint8ArrayToBase64(signature);

console.log(signatureBase64);

// headers
pm.request.headers.upsert({
    key: "bsi-openapi-appkey",
    value: APP_KEY
});

pm.request.headers.upsert({
    key: "bsi-openapi-sign",
    value: signatureBase64
});

pm.request.headers.upsert({
    key: "bsi-openapi-timestamp",
    value: timestamp
});

pm.request.headers.upsert({
    key: "bsi-openapi-nonce",
    value: nonce
});

pm.request.headers.upsert({
    key: "bsi-openapi-version",
    value: VERSION
});

// uuid
function uuidv4() {

    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
        .replace(/[xy]/g, function(c) {

            const r = Math.random() * 16 | 0;
            const v = c === 'x'
                ? r
                : (r & 0x3 | 0x8);

            return v.toString(16);
        });
}
