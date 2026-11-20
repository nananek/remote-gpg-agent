import { describe, expect, it } from 'vitest';
import * as openpgp from 'openpgp';
import { generateKey, signDetached, selfTest, exportBackup, importBackup, describe as describeKey, signDigest, openpgpDigest } from '../src/pgp';

describe('pgp', () => {
  it('generates a v4 ed25519 key that signs and verifies', async () => {
    const generated = await generateKey('personal', 'Test User', 'test@example.com');
    expect(generated.fingerprint).toMatch(/^[0-9A-F]{40}$/);
    expect(generated.armoredSecret).toContain('BEGIN PGP PRIVATE KEY BLOCK');

    await expect(selfTest(generated.armoredSecret)).resolves.toBeUndefined();

    const data = new TextEncoder().encode('tree 0000000000000000000000000000000000000000\n\nmsg\n');
    const sig = await signDetached(generated.armoredSecret, data);

    const verified = await openpgp.verify({
      message: await openpgp.createMessage({ binary: data }),
      signature: await openpgp.readSignature({ armoredSignature: sig }),
      verificationKeys: await openpgp.readKey({ armoredKey: generated.armoredPublic }),
    });
    await expect(verified.signatures[0].verified).resolves.toBeTruthy();
  });

  it('computes the OpenPGP digest over data + signature metadata + trailer', async () => {
    const data = new TextEncoder().encode('hello');
    const meta = new Uint8Array([4, 0, 22, 8, 0, 0]);
    const digest = await openpgpDigest(data, meta);
    expect(Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('')).toBe(
      '7a500204e5a14015100a09929b9f28d422b17b21a748a046f238d811330b9901',
    );
  });

  it('signs a 32-byte digest with Ed25519 and verifies with the public key', async () => {
    const generated = await generateKey('p', 'A', 'a@example.com');
    const key = await openpgp.readPrivateKey({ armoredKey: generated.armoredSecret });
    const Q = (key.keyPacket as any).publicParams.Q as Uint8Array;
    const digest = crypto.getRandomValues(new Uint8Array(32));
    const signature = await signDigest(generated.armoredSecret, digest);
    expect(signature).toHaveLength(64);

    const publicKey = await crypto.subtle.importKey(
      'jwk',
      { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(Q.slice(1)).toString('base64url') },
      'Ed25519',
      false,
      ['verify'],
    );
    await expect(crypto.subtle.verify('Ed25519', publicKey, signature, digest)).resolves.toBe(true);
  });

  it('describes the key with a matching fingerprint', async () => {
    const generated = await generateKey('p', 'A', 'a@example.com');
    const info = await describeKey(generated.armoredSecret);
    expect(info.fingerprint).toBe(generated.fingerprint);
    expect(info.armoredPublic).toContain('BEGIN PGP PUBLIC KEY BLOCK');
  });

  it('round-trips a passphrase protected backup', async () => {
    const generated = await generateKey('p', 'A', 'a@example.com');
    const backup = await exportBackup(generated.armoredSecret, 'correct horse battery');
    expect(backup).toContain('BEGIN PGP PRIVATE KEY BLOCK');

    const restored = await importBackup(backup, 'correct horse battery');
    const info = await describeKey(restored);
    expect(info.fingerprint).toBe(generated.fingerprint);

    await expect(importBackup(backup, 'wrong passphrase')).rejects.toThrow();
  });
});
