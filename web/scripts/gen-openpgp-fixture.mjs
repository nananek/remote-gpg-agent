// OpenPGP.js が生成した curve25519Legacy 鍵と detached 署名を fixture として書き出す。
// 目的: 「ブラウザ側の実装が本物の gpg で通るか」を Go のテストで固定する。
//
//   cd web && node ../scripts/gen-openpgp-fixture.mjs ../internal/e2e/testdata
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import * as openpgp from 'openpgp';

const outDir = process.argv[2] ?? 'internal/e2e/testdata';
mkdirSync(outDir, { recursive: true });

const { privateKey, publicKey } = await openpgp.generateKey({
  type: 'ecc',
  curve: 'curve25519Legacy',
  userIDs: [{ name: 'Fixture User', email: 'fixture@example.com' }],
  format: 'armored',
});

const data = new TextEncoder().encode('tree 0000000000000000000000000000000000000000\n\nfixture\n');
const signature = await openpgp.sign({
  message: await openpgp.createMessage({ binary: data }),
  signingKeys: await openpgp.readPrivateKey({ armoredKey: privateKey }),
  detached: true,
  format: 'armored',
});

const fingerprint = (await openpgp.readPrivateKey({ armoredKey: privateKey })).getFingerprint().toUpperCase();

writeFileSync(join(outDir, 'openpgpjs-private.asc'), privateKey);
writeFileSync(join(outDir, 'openpgpjs-public.asc'), publicKey);
writeFileSync(join(outDir, 'openpgpjs-data.bin'), data);
writeFileSync(join(outDir, 'openpgpjs-data.asc'), signature);
writeFileSync(join(outDir, 'openpgpjs-fingerprint.txt'), fingerprint + '\n');

console.log(`${outDir}: ${fingerprint}`);
