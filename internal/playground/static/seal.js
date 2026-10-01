/* Patch Log playground: Addendum E cryptography on WebCrypto only.
 *
 * Mirrors internal/seal (and the folding of internal/client/e2e.go):
 *   - JWE compact, alg "dir", enc "A256GCM", protected header
 *     {alg, enc, kid: "{ns}#{e}", pl, zip?: "DEF"}, AAD = the base64url header (§E.2.2)
 *   - K_r = HKDF-SHA256(ikm K_e, salt "patchlog-e2", info ns ‖ 0x0A ‖ name) (§E.2.1)
 *   - HPKE base mode (RFC 9180), DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM,
 *     single shot, empty AAD, wire form enc ‖ ct, info "patchlog-keys-v1\n" ‖ kid [‖ "\n" ‖ resource] (§E.2.3)
 *   - E3 keyring documents and recipient ids text(trunc160(sha256(canonical(jwk)))) (§E.3.2)
 *   - revision ids trunc160(sha256(parent ‖ 0x0A ‖ canonical patches)) (§3.3)
 *   - RFC 6902 JSON Patch, for folding e2e logs client-side
 *   - a small JSON Schema subset, for flagging e2e revisions on read (§E.3.2)
 *   - blob ids (§3.7) and the binary sealed-blob form (§E.2.2, §E.3.1), for viewing and attaching files
 *
 * No dependencies; runs in browsers and in Node >= 20 (globalThis.crypto).
 */
(function (root) {
'use strict';

const subtle = root.crypto.subtle;
const te = new TextEncoder();
const td = new TextDecoder('utf-8', { fatal: true });

const SUITE = 'hpke-base-0x0020-0x0001-0x0002';
const WRAP_INFO_PREFIX = 'patchlog-keys-v1\n';
const RESOURCE_KEY_SALT = 'patchlog-e2';

/* ---------------- bytes ---------------- */
function concat(...parts) {
  let n = 0; for (const p of parts) n += p.length;
  const out = new Uint8Array(n); let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
function utf8(s) { return te.encode(s); }
function b64u(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function unb64u(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) throw new Error('malformed base64url');
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function hex(bytes) { return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(''); }
function unhex(s) { const out = new Uint8Array(s.length / 2); for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16); return out; }
function equalBytes(a, b) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }
function randomBytes(n) { const b = new Uint8Array(n); root.crypto.getRandomValues(b); return b; }

const B32 = 'abcdefghijklmnopqrstuvwxyz234567';
function b32(bytes) {
  let out = '', bits = 0, v = 0;
  for (const x of bytes) { v = (v << 8) | x; bits += 8; while (bits >= 5) { out += B32[(v >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += B32[(v << (5 - bits)) & 31];
  return out;
}
function unb32(s) {
  const out = []; let bits = 0, v = 0;
  for (const c of s) { const i = B32.indexOf(c); if (i < 0) throw new Error('malformed base32'); v = (v << 5) | i; bits += 5; if (bits >= 8) { out.push((v >>> (bits - 8)) & 255); bits -= 8; } }
  return new Uint8Array(out);
}

/* padLen: the padded length of an n-byte plaintext, max(256, padmé(n)) (§E.2.2, seal.PadLen) */
function padLen(n) {
  if (n <= 256) return 256;
  const e = Math.floor(Math.log2(n)), s = Math.floor(Math.log2(e)) + 1, unit = 2 ** (e - s);
  return Math.ceil(n / unit) * unit;
}

/* $nonce: 128 random bits as 26 lowercase base32 characters (§C.7) */
function newNonce() { return b32(randomBytes(16)); }

/* ---------------- canonical JSON and ids ---------------- */
/* Sorted members, no whitespace. Strings and numbers use JSON.stringify, which
 * matches the server's canonical form for the values this page produces. */
function canonical(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  return '{' + Object.keys(v).sort(cmpUTF16).map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
}
function cmpUTF16(a, b) { return a < b ? -1 : a > b ? 1 : 0; }

async function sha256(bytes) { return new Uint8Array(await subtle.digest('SHA-256', bytes)); }
function idText(b20) { return '1' + b32(b20); }
function idBytes(id) {
  if (!/^1[a-z2-7]{32}$/.test(id)) throw new Error('malformed id ' + id);
  return unb32(id.slice(1));
}
/* trunc160(sha256(parent ‖ 0x0A ‖ body)), parent "" for the first entry */
async function chainID(parent, bodyBytes) {
  const p = parent ? idBytes(parent) : new Uint8Array(0);
  return idText((await sha256(concat(p, new Uint8Array([10]), bodyBytes))).slice(0, 20));
}
function revisionID(parent, patches) { return chainID(parent, utf8(canonical(patches))); }
function tombstoneID(parent) { return chainID(parent, utf8('tombstone')); }

/* ---------------- HMAC / HKDF (RFC 5869) ---------------- */
async function hmac(key, data) {
  const k = await subtle.importKey('raw', key.length ? key : new Uint8Array(32), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', k, data));
}
/* An empty HMAC key is zero-padded to the block size, so it equals 32 zero bytes. */
function hkdfExtract(salt, ikm) { return hmac(salt, ikm); }
async function hkdfExpand(prk, info, len) {
  let t = new Uint8Array(0); const out = [];
  let n = 0;
  for (let i = 1; n < len; i++) {
    t = await hmac(prk, concat(t, info, new Uint8Array([i])));
    out.push(t); n += t.length;
  }
  return concat(...out).slice(0, len);
}
async function hkdf(ikm, salt, info, len) { return hkdfExpand(await hkdfExtract(salt, ikm), info, len); }

/* K_r = HKDF-SHA256(K_e, "patchlog-e2", ns ‖ "\n" ‖ name) */
function resourceKey(epochKey, ns, name) {
  if (epochKey.length !== 32) throw new Error('epoch key must be 32 bytes');
  return hkdf(epochKey, utf8(RESOURCE_KEY_SALT), utf8(ns + '\n' + name), 32);
}

/* ---------------- AES-256-GCM ---------------- */
async function gcmKey(raw, usage) {
  if (raw.length !== 32) throw new Error('key must be 32 bytes');
  return subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, [usage]);
}
async function gcmSeal(key, iv, pt, aad) {
  return new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, await gcmKey(key, 'encrypt'), pt));
}
async function gcmOpen(key, iv, ctTag, aad) {
  try {
    return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, await gcmKey(key, 'decrypt'), ctTag));
  } catch (_) { throw new Error('decryption failed (wrong key, or tampered header, IV, ciphertext or tag)'); }
}

/* ---------------- X25519 ---------------- */
const PKCS8_X25519 = unhex('302e020100300506032b656e04220420');
async function importPrivate(raw) {
  return subtle.importKey('pkcs8', concat(PKCS8_X25519, raw), { name: 'X25519' }, true, ['deriveBits']);
}
async function importPublic(raw) { return subtle.importKey('raw', raw, { name: 'X25519' }, true, []); }
async function dh(priv, pubRaw) {
  const bits = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: await importPublic(pubRaw) }, priv, 256));
  if (bits.every((b) => b === 0)) throw new Error('X25519: low-order point');
  return bits;
}
/* An identity: { d, x } base64url (private scalar and public key). */
async function generateIdentity() {
  const kp = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const jwk = await subtle.exportKey('jwk', kp.privateKey);
  return { d: jwk.d, x: jwk.x };
}
async function identityFromPrivate(dB64) {
  const raw = unb64u(dB64);
  if (raw.length !== 32) throw new Error('private key must be 32 bytes');
  const k = await importPrivate(raw);
  const jwk = await subtle.exportKey('jwk', k);
  return { d: jwk.d, x: jwk.x };
}
function recipientJWK(xB64) { return { kty: 'OKP', crv: 'X25519', x: xB64 }; }
async function recipientID(xB64) {
  return idText((await sha256(utf8(canonical(recipientJWK(xB64))))).slice(0, 20));
}
function parseJWK(v) {
  const m = typeof v === 'string' ? JSON.parse(v) : v;
  if (!m || m.kty !== 'OKP' || m.crv !== 'X25519' || typeof m.x !== 'string' || unb64u(m.x).length !== 32) throw new Error('JWK must be {"kty":"OKP","crv":"X25519","x":…}');
  return m.x;
}

/* ---------------- HPKE (RFC 9180) base mode ---------------- */
const KEM_ID = 0x0020, KDF_ID = 0x0001, AEAD_ID = 0x0002;
const i2osp2 = (n) => new Uint8Array([(n >> 8) & 255, n & 255]);
const KEM_SUITE = concat(utf8('KEM'), i2osp2(KEM_ID));
const HPKE_SUITE = concat(utf8('HPKE'), i2osp2(KEM_ID), i2osp2(KDF_ID), i2osp2(AEAD_ID));
const V1 = utf8('HPKE-v1');
function labeledExtract(suite, salt, label, ikm) { return hkdfExtract(salt, concat(V1, suite, utf8(label), ikm)); }
function labeledExpand(suite, prk, label, info, len) { return hkdfExpand(prk, concat(i2osp2(len), V1, suite, utf8(label), info), len); }
async function extractAndExpand(dhBytes, kemContext) {
  const prk = await labeledExtract(KEM_SUITE, new Uint8Array(0), 'eae_prk', dhBytes);
  return labeledExpand(KEM_SUITE, prk, 'shared_secret', kemContext, 32);
}
async function keySchedule(shared, info) {
  const empty = new Uint8Array(0);
  const pskIDHash = await labeledExtract(HPKE_SUITE, empty, 'psk_id_hash', empty);
  const infoHash = await labeledExtract(HPKE_SUITE, empty, 'info_hash', info);
  const ctx = concat(new Uint8Array([0]), pskIDHash, infoHash);
  const secret = await labeledExtract(HPKE_SUITE, shared, 'secret', empty);
  return { key: await labeledExpand(HPKE_SUITE, secret, 'key', ctx, 32), nonce: await labeledExpand(HPKE_SUITE, secret, 'base_nonce', ctx, 12) };
}
/* hpkeSeal(pkR raw, info, pt) -> enc ‖ ct */
async function hpkeSeal(pkR, info, pt) {
  const skE = (await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits'])).privateKey;
  const enc = unb64u((await subtle.exportKey('jwk', skE)).x);
  const shared = await extractAndExpand(await dh(skE, pkR), concat(enc, pkR));
  const ks = await keySchedule(shared, info);
  return concat(enc, await gcmSeal(ks.key, ks.nonce, pt, new Uint8Array(0)));
}
async function hpkeOpen(identity, info, wrapped) {
  if (wrapped.length < 32 + 16) throw new Error('wrapped key too short');
  const enc = wrapped.slice(0, 32), ct = wrapped.slice(32);
  const skR = await importPrivate(unb64u(identity.d));
  const pkR = unb64u(identity.x);
  const shared = await extractAndExpand(await dh(skR, enc), concat(enc, pkR));
  const ks = await keySchedule(shared, info);
  return gcmOpen(ks.key, ks.nonce, ct, new Uint8Array(0));
}
function wrapContext(kid, resource) { return utf8(WRAP_INFO_PREFIX + kid + (resource ? '\n' + resource : '')); }
async function wrapKey(recipientX, kid, resource, key) {
  if (key.length !== 32) throw new Error('key must be 32 bytes');
  return hpkeSeal(unb64u(recipientX), wrapContext(kid, resource), key);
}
async function unwrapKey(identity, kid, resource, wrapped) {
  const k = await hpkeOpen(identity, wrapContext(kid, resource), wrapped);
  if (k.length !== 32) throw new Error('unwrapped key is not 32 bytes');
  return k;
}

/* ---------------- kids ---------------- */
function kid(ns, epoch) { return ns + '#' + epoch; }
function parseKid(k) {
  const i = typeof k === 'string' ? k.lastIndexOf('#') : -1;
  const e = i > 0 ? k.slice(i + 1) : '';
  if (!/^(0|[1-9][0-9]*)$/.test(e)) throw new Error('malformed kid ' + k);
  return { ns: k.slice(0, i), epoch: Number(e) };
}

/* ---------------- JWE ---------------- */
function parseJWE(jwe) {
  const parts = typeof jwe === 'string' ? jwe.trim().split('.') : [];
  if (parts.length !== 5) throw new Error('not a compact JWE');
  const raw = td.decode(unb64u(parts[0]));
  const hdr = JSON.parse(raw);
  if (!hdr || hdr.alg !== 'dir' || hdr.enc !== 'A256GCM') throw new Error('unsupported alg/enc');
  if (!hdr.kid) throw new Error('missing kid');
  if ('crit' in hdr) throw new Error('unsupported crit');
  if ('zip' in hdr && hdr.zip !== 'DEF') throw new Error('unsupported zip');
  if (!hdr.pl || typeof hdr.pl !== 'object' || Array.isArray(hdr.pl)) throw new Error('missing pl');
  return { header: hdr, raw, parts };
}
async function inflateRaw(bytes) {
  if (typeof DecompressionStream === 'undefined') throw new Error('this browser cannot inflate zip "DEF" content');
  const s = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
  return new Uint8Array(await new Response(s).arrayBuffer());
}
/* openJWE -> { header, plaintext (Uint8Array), text } */
async function openJWE(jwe, key) {
  const { header, parts } = parseJWE(jwe);
  if (parts[1] !== '') throw new Error('dir JWE must have an empty encrypted key');
  const iv = unb64u(parts[2]), ct = unb64u(parts[3]), tag = unb64u(parts[4]);
  if (iv.length !== 12 || tag.length !== 16) throw new Error('malformed IV or tag');
  let pt = await gcmOpen(key, iv, concat(ct, tag), utf8(parts[0]));
  if (header.zip === 'DEF') pt = await inflateRaw(pt);
  return { header, plaintext: pt, text: td.decode(pt) };
}
async function sealJWE(key, kidStr, pl, plaintext, iv) {
  const protectedB64 = b64u(utf8(canonical({ alg: 'dir', enc: 'A256GCM', kid: kidStr, pl })));
  iv = iv || randomBytes(12);
  const out = await gcmSeal(key, iv, typeof plaintext === 'string' ? utf8(plaintext) : plaintext, utf8(protectedB64));
  return protectedB64 + '..' + b64u(iv) + '.' + b64u(out.slice(0, out.length - 16)) + '.' + b64u(out.slice(out.length - 16));
}
/* plDiff lists the members where got differs from want (compared canonically) */
function plDiff(got, want) {
  const out = [];
  const keys = new Set([...Object.keys(got || {}), ...Object.keys(want || {})]);
  for (const k of keys) if (canonical(got ? got[k] : undefined) !== canonical(want ? want[k] : undefined)) out.push(k);
  return out;
}

/* E3 sealed patch sets (§E.3.1): [{"op":"sealed","value":"<JWE>","blobs":[…]?}] with pl {ns, name, parent};
 * pad (a namespace with encryption.pad) pads the plaintext to its bucket with spaces (§E.2.2).
 * blobs is the declared list of the blob ids the resulting document references (blobIDs), left out when empty. */
async function sealPatchSet(key, kidStr, ns, name, parent, patches, pad, blobs) {
  let pt = utf8(canonical(patches));
  if (pad) { const out = new Uint8Array(padLen(pt.length)).fill(0x20); out.set(pt); pt = out; }
  const jwe = await sealJWE(key, kidStr, { ns, name, parent: parent || '' }, pt);
  const op = { op: 'sealed', value: jwe };
  if (blobs && blobs.length) op.blobs = blobs;
  return [op];
}
function sealedOp(ps) {
  if (!Array.isArray(ps) || ps.length !== 1 || !ps[0] || ps[0].op !== 'sealed') return null;
  const op = ps[0], n = Object.keys(op).length;
  if (typeof op.value !== 'string' || !op.value) return null;
  if (n === 3 && Array.isArray(op.blobs) && op.blobs.every((b) => typeof b === 'string')) return op;
  return n === 2 ? op : null;
}
function sealedJWE(ps) { const op = sealedOp(ps); return op ? op.value : ''; }
/* sealedBlobs is the declared blob list of a sealed patch set ([] when it has none) */
function sealedBlobs(ps) { const op = sealedOp(ps); return op && op.blobs ? op.blobs : []; }

/* ---------------- blobs (§3.7, §7.8, §E.2.2, §E.3.1) ---------------- */
const BLOB_TYPE = 'application/vnd.patchlog.sealed-blob';
const BLOB_MAGIC = utf8('PLB1');
const MAX_BLOB_HEADER = 64 << 10;

/* blobType: a media type lowercased, without parameters (client.blobType) */
function blobType(ct) { return String(ct || '').split(';')[0].trim().toLowerCase(); }
/* blobID = trunc160(sha256("patchlog-blob-v1" ‖ 0x0A ‖ type ‖ 0x0A ‖ nonce ‖ 0x0A ‖ bytes)), nonce "" for none (ids.Blob) */
async function blobID(type, nonce, bytes) {
  return idText((await sha256(concat(utf8('patchlog-blob-v1\n' + blobType(type) + '\n' + (nonce || '') + '\n'), bytes))).slice(0, 20));
}

/* blobIDs lists the distinct ids a document references: objects whose $blob member is a string, at any depth,
 * not looking inside them; schema documents have none (client.BlobIDs). Sorted by the ids' binary form (§3.2, §E.3.1):
 * the base32 alphabet puts the digits after the letters, so text order isn't it. */
function blobIDs(doc) {
  if (doc && typeof doc === 'object' && !Array.isArray(doc) && doc.$schema === 'https://json-schema.org/draft/2020-12/schema') return [];
  const seen = new Set();
  const walk = (v) => {
    if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === 'object') {
      if (typeof v.$blob === 'string') seen.add(v.$blob);
      else Object.values(v).forEach(walk);
    }
  };
  walk(doc);
  const key = (s) => s.replace(/[a-z2-7]/g, (c) => String.fromCharCode(65 + 'abcdefghijklmnopqrstuvwxyz234567'.indexOf(c)));
  return [...seen].sort((a, b) => { const x = key(a), y = key(b); return x < y ? -1 : x > y ? 1 : 0; });
}
function sameBlobs(a, b) { const x = new Set(a), y = new Set(b); return x.size === y.size && [...x].every((i) => y.has(i)); }

/* parseBlob splits "PLB1" ‖ len ‖ header ‖ iv ‖ ciphertext ‖ tag and checks the header (seal.ParseBlobHeader).
 * kid and pl come together (E2) or not at all (E3). The header is unauthenticated until openBlob succeeds. */
function parseBlob(bytes) {
  const bad = (w) => { throw new Error('malformed sealed blob: ' + w); };
  if (bytes.length < 8 || !equalBytes(bytes.slice(0, 4), BLOB_MAGIC)) bad('not a sealed blob');
  const l = new DataView(bytes.buffer, bytes.byteOffset, bytes.length).getUint32(4);
  if (l > MAX_BLOB_HEADER || l > bytes.length - 8) bad('header length');
  let header;
  try { header = JSON.parse(td.decode(bytes.slice(8, 8 + l))); } catch (e) { bad('header: ' + e.message); }
  if (!header || typeof header !== 'object' || Array.isArray(header)) bad('header is not an object');
  if (header.enc !== 'A256GCM') bad('unsupported enc');
  for (const k of Object.keys(header)) if (k !== 'enc' && k !== 'kid' && k !== 'pl') bad('header member ' + JSON.stringify(k));
  if ('kid' in header && (typeof header.kid !== 'string' || !header.kid)) bad('kid');
  if ('pl' in header && (!header.pl || typeof header.pl !== 'object' || Array.isArray(header.pl))) bad('pl');
  if (('kid' in header) !== ('pl' in header)) bad('a sealed blob has both kid and pl or neither');
  return { header, off: 8 + l };
}
/* openBlob decrypts a sealed blob under key (seal.OpenBlob): the AAD is everything before the IV, the
 * plaintext is size (8 bytes, big-endian) ‖ bytes ‖ zero padding. Callers check the header. */
async function openBlob(bytes, key) {
  const { header, off } = parseBlob(bytes);
  if (bytes.length < off + 12 + 16) throw new Error('malformed sealed blob: too short');
  const plain = await gcmOpen(key, bytes.slice(off, off + 12), bytes.slice(off + 12), bytes.slice(0, off));
  if (plain.length < 8) throw new Error('malformed sealed blob: plaintext too short');
  const size = new DataView(plain.buffer, plain.byteOffset, plain.length).getBigUint64(0);
  if (size > BigInt(plain.length - 8)) throw new Error('malformed sealed blob: size exceeds its plaintext');
  const n = Number(size);
  if (plain.slice(8 + n).some((b) => b !== 0)) throw new Error('malformed sealed blob: padding is not zeros');
  return { header, data: plain.slice(8, 8 + n) };
}
/* sealBlob seals data in the binary form; kid and pl give the E2 header, both left out the E3 one {enc}.
 * pad zero-pads the plaintext to its padmé bucket (seal.SealBlob). */
async function sealBlob(key, kidStr, pl, data, pad) {
  const hdr = utf8(canonical(kidStr || pl ? { enc: 'A256GCM', kid: kidStr, pl } : { enc: 'A256GCM' }));
  const plain = new Uint8Array(pad ? padLen(8 + data.length) : 8 + data.length);
  new DataView(plain.buffer).setBigUint64(0, BigInt(data.length));
  plain.set(data, 8);
  const head = new Uint8Array(8 + hdr.length);
  head.set(BLOB_MAGIC); new DataView(head.buffer).setUint32(4, hdr.length); head.set(hdr, 8);
  const iv = randomBytes(12);
  return concat(head, iv, await gcmSeal(key, iv, plain, head));
}
/* encryptBlob prepares a file for an e2e namespace (§E.3.1, client.EncryptBlob): a fresh key, the sealed form, and
 * the reference that carries the key. Upload sealed with Content-Type BLOB_TYPE and no nonce. */
async function encryptBlob(type, data, pad) {
  const key = randomBytes(32);
  const sealed = await sealBlob(key, '', null, data, pad);
  const ref = { $blob: await blobID(BLOB_TYPE, '', sealed), type: BLOB_TYPE, size: sealed.length, sealed: { key: b64u(key), type: blobType(type), size: data.length } };
  return { sealed, ref };
}
/* decryptBlob opens an e2e blob against its reference (client.DecryptBlob): id, size, the key of the reference,
 * a header without kid, and the plaintext size it declares. */
async function decryptBlob(ref, sealed) {
  const s = ref && ref.sealed;
  if (!s || typeof s.key !== 'string') throw new Error('the reference carries no key (§E.3.1)');
  const key = unb64u(s.key);
  if (key.length !== 32) throw new Error('malformed sealed blob reference: the key is not 32 bytes');
  if (await blobID(ref.type, ref.nonce || '', sealed) !== ref.$blob || sealed.length !== ref.size) throw new Error('the blob does not match its id or size');
  const o = await openBlob(sealed, key);
  if (o.header.kid) throw new Error('an e2e blob\'s header has no kid');
  if (o.data.length !== s.size) throw new Error(`the blob has ${o.data.length} bytes, the reference says ${s.size}`);
  return { type: s.type, data: o.data };
}

/* ---------------- keyring (§E.3.2, seal.Keyring) ---------------- */
function parseKeyring(doc) {
  const bad = (w) => { throw new Error('keyring: ' + w); };
  if (!doc || typeof doc !== 'object' || doc.keyring !== 1) bad('version');
  if ('suite' in doc && doc.suite !== SUITE) bad('suite');
  if (typeof doc.ns !== 'string' || !doc.ns) bad('ns');
  if (!Number.isInteger(doc.current) || doc.current < 0) bad('current');
  if (!doc.recipients || typeof doc.recipients !== 'object') bad('recipients');
  if (!doc.epochs || typeof doc.epochs !== 'object') bad('epochs');
  return doc;
}
function buildKeyring(ns, current) { return { keyring: 1, suite: SUITE, ns, current, recipients: {}, epochs: {} }; }
async function keyringAdd(kr, recipientX, epoch, epochKey) {
  const rid = await recipientID(recipientX);
  const w = await wrapKey(recipientX, kid(kr.ns, epoch), '', epochKey);
  kr.recipients[rid] = recipientJWK(recipientX);
  (kr.epochs[String(epoch)] = kr.epochs[String(epoch)] || {})[rid] = b64u(w);
  if (epoch > kr.current) kr.current = epoch;
  return rid;
}
async function keyringEpochKey(kr, identity, epoch) {
  const rid = await recipientID(identity.x);
  const w = (kr.epochs[String(epoch)] || {})[rid];
  if (!w) throw new Error(`the keyring has no key for this identity in epoch ${epoch}`);
  return unwrapKey(identity, kid(kr.ns, epoch), '', unb64u(w));
}

/* ---------------- JSON Patch (RFC 6902) ---------------- */
function clone(v) { return v === undefined ? undefined : JSON.parse(JSON.stringify(v)); }
function ptr(p) {
  if (p === '') return [];
  if (typeof p !== 'string' || p[0] !== '/') throw new Error('malformed pointer ' + JSON.stringify(p));
  return p.slice(1).split('/').map((s) => s.replace(/~1/g, '/').replace(/~0/g, '~'));
}
function deepEqual(a, b) { return canonical(a) === canonical(b); }
function arrIndex(arr, tok, forAdd) {
  if (forAdd && tok === '-') return arr.length;
  if (!/^(0|[1-9][0-9]*)$/.test(tok)) throw new Error('bad array index ' + tok);
  const i = Number(tok);
  if (i > arr.length || (!forAdd && i === arr.length)) throw new Error('array index out of range ' + tok);
  return i;
}
function getAt(doc, toks) {
  let cur = doc;
  for (const t of toks) {
    if (Array.isArray(cur)) cur = cur[arrIndex(cur, t, false)];
    else if (cur && typeof cur === 'object' && Object.prototype.hasOwnProperty.call(cur, t)) cur = cur[t];
    else throw new Error('path not found /' + toks.join('/'));
  }
  return cur;
}
function applyPatch(doc, exists, ops) {
  let d = clone(doc), ex = exists;
  const parentOf = (toks) => getAt(d, toks.slice(0, -1));
  const put = (toks, v) => {
    if (!toks.length) { d = v; ex = true; return; }
    if (!ex) throw new Error('document does not exist');
    const p = parentOf(toks), last = toks[toks.length - 1];
    if (Array.isArray(p)) p.splice(arrIndex(p, last, true), 0, v);
    else if (p && typeof p === 'object') p[last] = v;
    else throw new Error('parent is not a container');
  };
  const del = (toks) => {
    if (!toks.length) throw new Error('cannot remove the root');
    const p = parentOf(toks), last = toks[toks.length - 1];
    if (Array.isArray(p)) p.splice(arrIndex(p, last, false), 1);
    else if (p && typeof p === 'object' && Object.prototype.hasOwnProperty.call(p, last)) delete p[last];
    else throw new Error('path not found /' + toks.join('/'));
  };
  if (!Array.isArray(ops)) throw new Error('a patch set is an array');
  for (const o of ops) {
    if (!o || typeof o !== 'object') throw new Error('an operation is an object');
    const path = ptr(o.path);
    switch (o.op) {
      case 'add': if (!('value' in o)) throw new Error('add needs value'); put(path, clone(o.value)); break;
      case 'remove': del(path); break;
      case 'replace':
        if (!('value' in o)) throw new Error('replace needs value');
        if (!path.length) { if (!ex) throw new Error('document does not exist'); d = clone(o.value); break; }
        getAt(d, path); del(path); put(path, clone(o.value)); break;
      case 'move': {
        const from = ptr(o.from);
        if (o.path.startsWith(o.from + '/')) throw new Error('cannot move into a child');
        const v = getAt(d, from); if (o.from !== o.path) { del(from); put(path, v); } break;
      }
      case 'copy': put(path, clone(getAt(d, ptr(o.from)))); break;
      case 'test': if (!deepEqual(getAt(d, path), o.value)) throw new Error('test failed at ' + o.path); break;
      default: throw new Error('unknown op ' + JSON.stringify(o.op));
    }
  }
  return { doc: d, exists: ex };
}

/* ---------------- JSON Schema (a subset) ----------------
 * Enough to flag the usual mistakes in e2e documents on read (§E.3.2). Keywords outside the
 * subset are reported as unchecked rather than guessed at. */
const CHECKED = new Set(['$schema', '$id', 'title', 'description', 'default', 'examples', '$comment', 'format', 'x-index', 'deprecated', 'readOnly', 'writeOnly',
  'type', 'enum', 'const', 'required', 'properties', 'additionalProperties', 'patternProperties', 'items', 'minItems', 'maxItems', 'uniqueItems',
  'minLength', 'maxLength', 'pattern', 'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'multipleOf', 'minProperties', 'maxProperties',
  'allOf', 'anyOf', 'oneOf', 'not']);
function typeOf(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  if (typeof v === 'number') return Number.isInteger(v) ? 'integer' : 'number';
  return typeof v;
}
function validate(schema, doc) {
  const errors = [], unchecked = new Set();
  const walk = (s, v, at) => {
    if (s === true || s === undefined) return;
    if (s === false) { errors.push({ pointer: at, message: 'no value allowed' }); return; }
    if (typeof s !== 'object') return;
    for (const k of Object.keys(s)) if (!CHECKED.has(k) && !k.startsWith('x-')) unchecked.add(k);
    const err = (m) => errors.push({ pointer: at || '', message: m });
    const t = typeOf(v);
    if (s.type !== undefined) {
      const ts = [].concat(s.type);
      if (!ts.some((x) => x === t || (x === 'number' && t === 'integer'))) err(`type ${t}, want ${ts.join('|')}`);
    }
    if (s.enum && !s.enum.some((x) => deepEqual(x, v))) err('not one of the enum values');
    if ('const' in s && !deepEqual(s.const, v)) err('not the const value');
    if (t === 'string') {
      const n = [...v].length;
      if (s.minLength !== undefined && n < s.minLength) err(`shorter than ${s.minLength}`);
      if (s.maxLength !== undefined && n > s.maxLength) err(`longer than ${s.maxLength}`);
      if (s.pattern !== undefined) { try { if (!new RegExp(s.pattern, 'u').test(v)) err(`does not match ${s.pattern}`); } catch (_) { unchecked.add('pattern'); } }
    }
    if (t === 'number' || t === 'integer') {
      if (s.minimum !== undefined && v < s.minimum) err(`below ${s.minimum}`);
      if (s.maximum !== undefined && v > s.maximum) err(`above ${s.maximum}`);
      if (s.exclusiveMinimum !== undefined && v <= s.exclusiveMinimum) err(`not above ${s.exclusiveMinimum}`);
      if (s.exclusiveMaximum !== undefined && v >= s.exclusiveMaximum) err(`not below ${s.exclusiveMaximum}`);
      if (s.multipleOf !== undefined && Math.abs(v / s.multipleOf - Math.round(v / s.multipleOf)) > 1e-9) err(`not a multiple of ${s.multipleOf}`);
    }
    if (t === 'array') {
      if (s.minItems !== undefined && v.length < s.minItems) err(`fewer than ${s.minItems} items`);
      if (s.maxItems !== undefined && v.length > s.maxItems) err(`more than ${s.maxItems} items`);
      if (s.uniqueItems && new Set(v.map(canonical)).size !== v.length) err('items are not unique');
      if (s.items !== undefined && !Array.isArray(s.items)) v.forEach((x, i) => walk(s.items, x, at + '/' + i));
    }
    if (t === 'object') {
      const keys = Object.keys(v);
      if (s.minProperties !== undefined && keys.length < s.minProperties) err(`fewer than ${s.minProperties} members`);
      if (s.maxProperties !== undefined && keys.length > s.maxProperties) err(`more than ${s.maxProperties} members`);
      for (const r of s.required || []) if (!(r in v)) err(`missing required member ${r}`);
      const props = s.properties || {}, pats = Object.entries(s.patternProperties || {});
      for (const k of keys) {
        const p = at + '/' + k.replace(/~/g, '~0').replace(/\//g, '~1');
        let matched = false;
        if (k in props) { matched = true; walk(props[k], v[k], p); }
        for (const [re, ps] of pats) { try { if (new RegExp(re, 'u').test(k)) { matched = true; walk(ps, v[k], p); } } catch (_) { unchecked.add('patternProperties'); } }
        if (!matched && s.additionalProperties !== undefined) walk(s.additionalProperties, v[k], p);
      }
    }
    for (const sub of s.allOf || []) walk(sub, v, at);
    const count = (list) => list.filter((sub) => { const r = validate(sub, v); r.unchecked.forEach((u) => unchecked.add(u)); return !r.errors.length; }).length;
    if (s.anyOf && !count(s.anyOf)) err('matches none of anyOf');
    if (s.oneOf && count(s.oneOf) !== 1) err('does not match exactly one of oneOf');
    if (s.not !== undefined && !validate(s.not, v).errors.length) err('matches not');
  };
  walk(schema, doc, '');
  return { errors, unchecked: [...unchecked] };
}

/* ---------------- self-test against a Go-generated fixture ---------------- */
/* selftest.json is written by internal/playground's tests with internal/seal. */
async function selfTest(fx) {
  const results = [];
  const check = async (name, fn) => {
    try { const r = await fn(); results.push({ name, ok: r === true, detail: r === true ? '' : String(r) }); }
    catch (e) { results.push({ name, ok: false, detail: e.message }); }
  };
  const id = await identityFromPrivate(fx.recipient.d);
  await check('X25519 public key from private', () => id.x === fx.recipient.x || `got ${id.x}`);
  await check('recipient id', async () => (await recipientID(id.x)) === fx.recipient.rid || 'mismatch');
  await check('HPKE unwrap of a Go-wrapped epoch key', async () => {
    const k = await unwrapKey(id, fx.wrapped.kid, fx.wrapped.resource || '', unb64u(fx.wrapped.wrapped));
    return b64u(k) === fx.epochKey || 'wrong key';
  });
  await check('HPKE wrap is refused under another context', async () => {
    try { await unwrapKey(id, fx.wrapped.kid + '0', '', unb64u(fx.wrapped.wrapped)); return 'opened under the wrong kid'; } catch (_) { return true; }
  });
  await check('HPKE unwrap of a Go-wrapped per-resource key', async () => {
    const k = await unwrapKey(id, fx.wrappedResource.kid, fx.wrappedResource.resource, unb64u(fx.wrappedResource.wrapped));
    return b64u(k) === fx.resourceKey.key || 'wrong key';
  });
  await check('HPKE round trip (wrap here, unwrap here)', async () => {
    const k = randomBytes(32);
    const w = await wrapKey(id.x, 'x#2', 'res', k);
    return equalBytes(await unwrapKey(id, 'x#2', 'res', w), k) || 'mismatch';
  });
  await check('K_r derivation (HKDF-SHA256)', async () => b64u(await resourceKey(unb64u(fx.epochKey), fx.resourceKey.ns, fx.resourceKey.name)) === fx.resourceKey.key || 'mismatch');
  await check('open a Go-sealed JWE and check kid/pl', async () => {
    const o = await openJWE(fx.jwe.jwe, unb64u(fx.jwe.key));
    const d = plDiff(o.header.pl, fx.jwe.pl);
    return (o.text === fx.jwe.plaintext && o.header.kid === fx.jwe.kid && !d.length) || 'mismatch ' + d.join(',');
  });
  await check('open a Go-sealed compressed (zip DEF) JWE', async () => {
    const o = await openJWE(fx.jweZip.jwe, unb64u(fx.jweZip.key));
    return (o.header.zip === 'DEF' && o.text === fx.jweZip.plaintext) || 'mismatch';
  });
  await check('tampered JWE is refused', async () => {
    const p = fx.jwe.jwe.split('.'); p[3] = (p[3][0] === 'A' ? 'B' : 'A') + p[3].slice(1);
    try { await openJWE(p.join('.'), unb64u(fx.jwe.key)); return 'opened'; } catch (_) { return true; }
  });
  await check('JWE round trip', async () => {
    const k = randomBytes(32);
    const j = await sealJWE(k, 'x#1', { ns: 'x', name: 'y', parent: '' }, '{"a":1}');
    return (await openJWE(j, k)).text === '{"a":1}' || 'mismatch';
  });
  await check('keyring: unwrap this identity\'s epoch key', async () => b64u(await keyringEpochKey(parseKeyring(fx.keyring), id, fx.keyring.current)) === fx.epochKey || 'wrong key');
  await check('E3 sealed patch set id and plaintext', async () => {
    const ps = fx.patchSet.patchSet;
    if ((await revisionID(fx.patchSet.parent, ps)) !== fx.patchSet.id) return 'revision id differs';
    const o = await openJWE(sealedJWE(ps), unb64u(fx.epochKey));
    return (canonical(JSON.parse(o.text)) === canonical(fx.patchSet.patches) && !plDiff(o.header.pl, { ns: fx.patchSet.ns, name: fx.patchSet.name, parent: fx.patchSet.parent }).length) || 'mismatch';
  });
  await check('tombstone id', async () => (await tombstoneID(fx.patchSet.id)) === fx.patchSet.tombstone || 'mismatch');
  await check('padding buckets (padmé)', () => { const bad = (fx.padLen || []).filter(([n, want]) => padLen(n) !== want); return (fx.padLen && fx.padLen.length && !bad.length) || 'mismatch ' + JSON.stringify(bad.slice(0, 3)); });
  await check('open a Go-sealed padded JWE', async () => {
    const o = await openJWE(fx.jwePadded.jwe, unb64u(fx.jwePadded.key));
    const bare = o.text.replace(/ +$/, '');
    return (!o.header.zip && o.plaintext.length === padLen(utf8(bare).length) && canonical(JSON.parse(o.text)) === canonical(JSON.parse(fx.jwePadded.plaintext))) || 'mismatch';
  });
  if (fx.blobIDs) {
    await check('blob ids (§3.7)', async () => {
      for (const b of fx.blobIDs) if ((await blobID(b.type, b.nonce, unb64u(b.data))) !== b.id) return 'mismatch for ' + b.type;
      return fx.blobIDs.length > 0 || 'no vectors';
    });
    await check('open Go-sealed E3 blobs against their references, plain and padded', async () => {
      for (const b of [fx.blobE3, fx.blobE3Padded]) {
        const o = await decryptBlob(b.ref, unb64u(b.sealed));
        if (o.type !== 'image/png' || !equalBytes(o.data, unb64u(b.data))) return 'mismatch';
      }
      return true;
    });
    await check('open a Go-sealed E2 blob and check its header', async () => {
      const b = fx.blobE2, sealed = unb64u(b.sealed);
      const o = await openBlob(sealed, unb64u(b.key));
      return (o.header.kid === b.kid && !plDiff(o.header.pl, b.pl).length && equalBytes(o.data, unb64u(b.data))) || 'mismatch';
    });
    await check('tampered or mis-keyed blob is refused', async () => {
      const b = unb64u(fx.blobE3.sealed); b[b.length - 20] ^= 1;
      try { await openBlob(b, unb64u(fx.blobE3.key)); return 'opened'; } catch (_) { /* expected */ }
      try { await openBlob(unb64u(fx.blobE3.sealed), unb64u(fx.blobE2.key)); return 'opened under another key'; } catch (_) { return true; }
    });
    await check('sealed op with a declared blob list', async () => {
      const p = fx.patchSetBlobs;
      if ((await revisionID(p.parent, p.patchSet)) !== p.id) return 'revision id differs';
      return (canonical(sealedBlobs(p.patchSet)) === canonical(p.blobs) && canonical(blobIDs(p.patches[0].value)) === canonical(p.blobs)) || 'blob list differs';
    });
  }
  return results;
}

root.PLSeal = {
  SUITE, b64u, unb64u, b32, hex, unhex, utf8, equalBytes, randomBytes, newNonce, canonical, padLen,
  sha256, chainID, revisionID, tombstoneID, idBytes,
  hkdf, resourceKey, generateIdentity, identityFromPrivate, recipientJWK, recipientID, parseJWK,
  hpkeSeal, hpkeOpen, wrapKey, unwrapKey, kid, parseKid, parseJWE, openJWE, sealJWE, plDiff,
  sealPatchSet, sealedJWE, sealedBlobs, BLOB_TYPE, blobType, blobID, blobIDs, sameBlobs, parseBlob, openBlob, sealBlob, encryptBlob, decryptBlob,
  parseKeyring, buildKeyring, keyringAdd, keyringEpochKey,
  applyPatch, validate, selfTest,
};
})(typeof window !== 'undefined' ? window : globalThis);
