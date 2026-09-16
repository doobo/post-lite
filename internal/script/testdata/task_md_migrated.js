// Task.md 的 Postman 前置脚本，迁移到 post-lite 的版本。
//
// 与 testdata/postman_sign_nacl.js（Task.md 原文，两个值被涂成 '***'）的唯一区别：
// APP_KEY / PRIVATE_KEY_BASE64 改成从变量袋读。「Vars」分页里的同名变量、或已激活的
// 环境变量，都会进这个袋子（环境变量先、Vars 分页覆盖之）；密钥仓里的 sec.* 读不到，
// 所以签名用的 seed 只能放这两处，或直接明文写在本文件里。
//
// 由 TestMigratedTaskMdScriptReadsItsKeyFromVariables 执行，并用 Go 的 crypto/ed25519 验签。
const nacl = pm.require('npm:tweetnacl@1.0.3');
const APP_KEY = pm.variables.get('APP_KEY');
const PRIVATE_KEY_BASE64 = pm.variables.get('PRIVATE_KEY_BASE64');
const VERSION = "1.0.0";

// 没设变量时早点炸掉：否则 atob(undefined) 的报错说的是「拿到的不是字符串」，
// 而 header 会变成字面量 "undefined"，比脚本失败更难查。
if (typeof APP_KEY !== 'string' || APP_KEY === '') {
    throw new Error("APP_KEY 没有设置：填在「Vars」分页或环境变量里");
}
if (typeof PRIVATE_KEY_BASE64 !== 'string' || PRIVATE_KEY_BASE64 === '') {
    throw new Error("PRIVATE_KEY_BASE64 没有设置：填在「Vars」分页或环境变量里（32 字节 Ed25519 seed 的 base64）");
}

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
