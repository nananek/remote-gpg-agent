import { describe, expect, it } from 'vitest';
import { deriveWrapKey, open, seal } from '../src/vault';

const prf = new Uint8Array(32).fill(7);
const fingerprint = 'A'.repeat(40);

describe('vault', () => {
  it('round-trips the sealed payload', async () => {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const key = await deriveWrapKey(prf, salt);
    const env = await seal('secret', key, fingerprint, salt);
    expect(await open(env, key, fingerprint)).toBe('secret');
  });

  it('rejects a different PRF output', async () => {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const key = await deriveWrapKey(prf, salt);
    const other = await deriveWrapKey(new Uint8Array(32).fill(8), salt);
    const env = await seal('secret', key, fingerprint, salt);
    await expect(open(env, other, fingerprint)).rejects.toThrow();
  });

  it('binds the ciphertext to the fingerprint', async () => {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const key = await deriveWrapKey(prf, salt);
    const env = await seal('secret', key, fingerprint, salt);
    await expect(open(env, key, 'B'.repeat(40))).rejects.toThrow();
  });

  it('uses a fresh IV per seal', async () => {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const key = await deriveWrapKey(prf, salt);
    const a = await seal('same', key, fingerprint, salt);
    const b = await seal('same', key, fingerprint, salt);
    expect(a.ivB64).not.toBe(b.ivB64);
    expect(a.ciphertextB64).not.toBe(b.ciphertextB64);
  });
});
