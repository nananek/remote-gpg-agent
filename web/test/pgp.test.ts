import { describe, expect, it } from 'vitest';
import * as openpgp from 'openpgp';
import { generateKey, signDetached, selfTest, exportBackup, importBackup, describe as describeKey } from '../src/pgp';

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
