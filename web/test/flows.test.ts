import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/api', () => ({
  api: {
    me: vi.fn(),
    registerOptions: vi.fn(),
    registerVerify: vi.fn(),
    loginOptions: vi.fn(),
    loginVerify: vi.fn(),
    state: vi.fn(),
    sealKey: vi.fn(),
  },
}));

vi.mock('../src/ceremonies', () => ({
  createPasskey: vi.fn(),
  assertWithPrf: vi.fn(),
}));

vi.mock('../src/pgp', () => ({
  generateKey: vi.fn(),
  selfTest: vi.fn(),
  signDetached: vi.fn(),
  describe: vi.fn(),
  exportBackup: vi.fn(),
  importBackup: vi.fn(),
}));

import { api } from '../src/api';
import { assertWithPrf, createPasskey } from '../src/ceremonies';
import { generateKey, selfTest, signDetached } from '../src/pgp';
import { b64, unb64 } from '../src/b64';
import { state, type UnlockedKey } from '../src/state';
import { deriveWrapKey, open, seal } from '../src/vault';
import { addKey, addPasskey, unlock } from '../src/flows';

const apiMock = api as any;

const FP1 = 'A'.repeat(40);
const FP2 = 'B'.repeat(40);
const KEY_ID_1 = FP1.slice(-16);
const KEY_ID_2 = FP2.slice(-16);
const PRF_OLD = new Uint8Array(32).fill(1);
const PRF_NEW = new Uint8Array(32).fill(2);

function key1(): UnlockedKey {
  return { fingerprint: FP1, label: 'personal', armoredSecret: 'SECRET-1', revocation: 'REV-1' };
}

beforeEach(() => {
  vi.resetAllMocks();
  state.clear();
  apiMock.me.mockResolvedValue({ authenticated: true, credentialId: 'cred-old', credentialCount: 1 });
  apiMock.registerVerify.mockResolvedValue({ credentialId: 'cred-new' });
  apiMock.sealKey.mockResolvedValue({ keyId: KEY_ID_2 });
  (selfTest as any).mockResolvedValue(undefined);
  (signDetached as any).mockResolvedValue('PROOF');
});

describe('addPasskey', () => {
  it('新 credential の PRF で全鍵を再封印し、サーバには平文を送らない', async () => {
    state.set('cred-old', [key1()], PRF_OLD);
    apiMock.registerOptions.mockResolvedValue({ ceremonyId: 'c1', options: {} });
    (createPasskey as any).mockResolvedValue({
      credentialId: 'cred-new',
      prfEnabled: true,
      prfOutput: PRF_NEW,
      response: { id: 'cred-new' },
    });

    await addPasskey('backup');

    const envelopes = apiMock.registerVerify.mock.calls[0][3];
    expect(envelopes).toHaveLength(1);
    expect(envelopes[0].keyId).toBe(KEY_ID_1);
    // 送るのは ciphertext だけで、armored 秘密鍵は含まれない。
    expect(JSON.stringify(envelopes)).not.toContain('SECRET-1');

    // 所持証明は「新しい credential × この envelope」に束縛される。
    expect(envelopes[0].proof).toBe('PROOF');
    const proofMessage = new TextDecoder().decode((signDetached as any).mock.calls[0][1]);
    expect(proofMessage).toBe([
      'rga-envelope:v1',
      'cred-new',
      KEY_ID_1,
      envelopes[0].hkdfSaltB64,
      envelopes[0].ivB64,
      envelopes[0].ciphertextB64,
    ].join('\n'));

    const withNew = await deriveWrapKey(PRF_NEW, unb64(envelopes[0].hkdfSaltB64));
    expect(JSON.parse(await open(envelopes[0], withNew, FP1)).secret).toBe('SECRET-1');

    const withOld = await deriveWrapKey(PRF_OLD, unb64(envelopes[0].hkdfSaltB64));
    await expect(open(envelopes[0], withOld, FP1)).rejects.toThrow();
  });

  it('成功後に state を新 credential へ追随させる', async () => {
    state.set('cred-old', [key1()], PRF_OLD);
    apiMock.registerOptions.mockResolvedValue({ ceremonyId: 'c1', options: {} });
    (createPasskey as any).mockResolvedValue({
      credentialId: 'cred-new',
      prfEnabled: true,
      prfOutput: PRF_NEW,
      response: {},
    });

    await addPasskey('backup');

    expect(state.credentialId).toBe('cred-new');
    expect(state.prfOutput).toEqual(PRF_NEW);
    expect(state.keys.map((k) => k.label)).toEqual(['personal']);
  });

  it('解錠していなければ典礼を始めない', async () => {
    await expect(addPasskey('backup')).rejects.toThrow(/解錠/);
    expect(apiMock.registerOptions).not.toHaveBeenCalled();
  });
});

describe('addKey after addPasskey', () => {
  it('新しい PRF で封印する（旧実装では古い PRF のまま壊れた）', async () => {
    state.set('cred-old', [key1()], PRF_OLD);
    apiMock.registerOptions.mockResolvedValue({ ceremonyId: 'c1', options: {} });
    (createPasskey as any).mockResolvedValue({
      credentialId: 'cred-new',
      prfEnabled: true,
      prfOutput: PRF_NEW,
      response: {},
    });
    await addPasskey('backup');

    apiMock.me.mockResolvedValue({ authenticated: true, credentialId: 'cred-new', credentialCount: 2 });
    (generateKey as any).mockResolvedValue({
      fingerprint: FP2,
      armoredSecret: 'SECRET-2',
      armoredPublic: 'PUB-2',
      revocationCertificate: 'REV-2',
    });

    let sealed: any;
    apiMock.sealKey.mockImplementation(async (body: any) => {
      sealed = body;
      return { keyId: KEY_ID_2 };
    });

    await addKey({ label: 'second', name: 'n', email: 'e' });

    // 封印先の credential を明示し、その credential 用の所持証明を付ける。
    expect(sealed.credentialId).toBe('cred-new');
    expect(sealed.proof).toBe('PROOF');

    const withNew = await deriveWrapKey(PRF_NEW, unb64(sealed.hkdfSaltB64));
    expect(JSON.parse(await open(sealed, withNew, FP2)).secret).toBe('SECRET-2');

    const withOld = await deriveWrapKey(PRF_OLD, unb64(sealed.hkdfSaltB64));
    await expect(open(sealed, withOld, FP2)).rejects.toThrow();
  });

  it('セッションの credential と解錠状態がずれていたら封印しない', async () => {
    state.set('cred-old', [key1()], PRF_OLD);
    apiMock.me.mockResolvedValue({ authenticated: true, credentialId: 'cred-other', credentialCount: 2 });

    await expect(addKey({ label: 'second', name: 'n', email: 'e' })).rejects.toThrow(/解錠/);
    expect(generateKey as any).not.toHaveBeenCalled();
    expect(apiMock.sealKey).not.toHaveBeenCalled();
  });
});

describe('unlock', () => {
  async function stubLogin(vaultState: unknown): Promise<void> {
    apiMock.loginOptions.mockResolvedValue({ ceremonyId: 'c', options: {} });
    (assertWithPrf as any).mockResolvedValue({
      credentialId: 'cred-new',
      prfEnabled: true,
      prfOutput: PRF_NEW,
      response: {},
    });
    apiMock.loginVerify.mockResolvedValue({ credentialId: 'cred-new' });
    apiMock.state.mockResolvedValue(vaultState);
  }

  async function goodEnvelope(): Promise<any> {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const wrapKey = await deriveWrapKey(PRF_NEW, salt);
    const env = await seal(JSON.stringify({ secret: 'SECRET-1', revocation: 'REV-1' }), wrapKey, FP1, salt);
    return { credentialId: 'cred-new', keyId: KEY_ID_1, ...env };
  }

  const brokenEnvelope = (): any => ({
    credentialId: 'cred-new',
    keyId: KEY_ID_2,
    hkdfSaltB64: b64(new Uint8Array(32).fill(9)),
    ivB64: b64(new Uint8Array(12)),
    ciphertextB64: b64(new Uint8Array(48)),
  });

  it('壊れた envelope をスキップし、残りの鍵は解錠する', async () => {
    await stubLogin({
      credentialId: 'cred-new',
      credentials: [{ credentialId: 'cred-new', label: 'backup' }],
      keys: [
        { keyId: KEY_ID_1, fingerprint: FP1, label: 'personal' },
        { keyId: KEY_ID_2, fingerprint: FP2, label: 'broken' },
      ],
      envelopes: [await goodEnvelope(), brokenEnvelope()],
    });

    const failed = await unlock();

    expect(failed).toEqual(['broken']);
    expect(state.credentialId).toBe('cred-new');
    expect(state.keys.map((k) => k.label)).toEqual(['personal']);
  });

  it('全滅なら鍵のラベルを含めて失敗する', async () => {
    await stubLogin({
      credentialId: 'cred-new',
      credentials: [],
      keys: [{ keyId: KEY_ID_2, fingerprint: FP2, label: 'broken' }],
      envelopes: [brokenEnvelope()],
    });

    await expect(unlock()).rejects.toThrow(/broken/);
    expect(state.keys).toHaveLength(0);
  });
});
