// Independent byte encoding and signature verification for bounded test payments.
// Arguments: pinned patched Noble module, public payment/signature manifest.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
const { gen, SHA256_SIMPLE } = await import(pathToFileURL(resolve(process.argv[2])));
const record = JSON.parse(readFileSync(process.argv[3], 'utf8'));
const p = record.payment, body = Buffer.from(p.body_hex, 'hex');
for (const name of ['network', 'amount', 'expires', 'sequence', 'epoch'])
  if (!Number.isSafeInteger(p[name])) throw new Error('checker requires safe JSON integers');
const message = Buffer.alloc(100 + body.length);
message.write('PQS1', 0, 'ascii'); message.writeInt32BE(p.network, 4);
for (const [name, offset] of [['wallet', 8], ['recipient', 41]]) {
  const [wc, hash] = p[name].split(':');
  if (Number(wc) !== 0 || !/^[0-9a-f]{64}$/.test(hash)) throw new Error('raw basechain address required');
  message.writeInt8(Number(wc), offset); Buffer.from(hash, 'hex').copy(message, offset + 1);
}
message.writeBigUInt64BE(BigInt(p.amount), 74); message.writeUInt32BE(p.expires, 82);
message.writeBigUInt64BE(BigInt(p.sequence), 86); message.writeUInt32BE(p.epoch, 94);
message.writeUInt16BE(body.length, 98); body.copy(message, 100);
if (message.toString('hex') !== record.canonical_hex) throw new Error('canonical encoding mismatch');
const scheme = gen({ N: 16, W: 4, H: 22, D: 1, K: 6, A: 24, securityLevel: 128 }, SHA256_SIMPLE);
if (!scheme.verify(Buffer.from(record.signature, 'hex'), message, Buffer.from(record.public_key, 'hex')))
  throw new Error('signature rejected');
console.log(JSON.stringify({ canonical_bytes: message.length, independent_encoding_matches: true,
  noble_signature_valid: true, sequence: p.sequence, wallet: p.wallet }));
