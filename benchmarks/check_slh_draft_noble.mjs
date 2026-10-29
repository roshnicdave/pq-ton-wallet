// Independent implementation check. Argument: patched pinned Noble module path.
// Public fixtures only. The six upstream parameter/address patches need review.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
const { gen, SHA256_SIMPLE } = await import(pathToFileURL(resolve(process.argv[2])));
const scheme = gen({ N: 16, W: 4, H: 22, D: 1, K: 6, A: 24, securityLevel: 128 }, SHA256_SIMPLE);
const bytes = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));
for (const name of ['gpu', 'cpu']) {
  const fixture = JSON.parse(readFileSync(`tests/fixtures/slh-draft/${name}.json`, 'utf8'));
  const pk = bytes(fixture.public_key), msg = bytes(fixture.message), sig = bytes(fixture.signature);
  if (!scheme.verify(sig, msg, pk)) throw new Error(`${name}: valid signature rejected`);
  const bad = sig.slice(); bad[1700] ^= 1;
  if (scheme.verify(bad, msg, pk)) throw new Error(`${name}: forged path accepted`);
  const wrong = msg.slice(); wrong[0] ^= 1;
  if (scheme.verify(sig, wrong, pk)) throw new Error(`${name}: wrong message accepted`);
  console.log(JSON.stringify({ name, implementation: 'patched @noble/post-quantum@0.6.1',
    valid: true, forged_path_rejected: true, wrong_message_rejected: true }));
}
