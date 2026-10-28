import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createPasskey, assertWithPrf } from '../src/ceremonies';

/** WebAuthn の JSON 形（サーバが返す {publicKey: ...}）を受けてセレモニーを回せることを固定する。 */

let captured: any = null;

function fakeCredential(kind: 'create' | 'get') {
  const bytes = (n: number) => new Uint8Array(n).fill(7).buffer;
  const ext = { prf: { enabled: true, results: kind === 'create' ? { first: bytes(32) } : { first: bytes(32) } } };
  if (kind === 'create') {
    return {
      id: 'cred-1',
      rawId: bytes(16),
      type: 'public-key',
      authenticatorAttachment: 'platform',
      getClientExtensionResults: () => ext,
      response: { clientDataJSON: bytes(4), attestationObject: bytes(8), getTransports: () => ['internal'] },
    };
  }
  return {
    id: 'cred-1',
    rawId: bytes(16),
    type: 'public-key',
    getClientExtensionResults: () => ext,
    response: { clientDataJSON: bytes(4), authenticatorData: bytes(8), signature: bytes(8), userHandle: bytes(4) },
  };
}

beforeEach(() => {
  captured = null;
  vi.stubGlobal('navigator', {
    credentials: {
      create: vi.fn(async (arg: any) => {
        captured = arg.publicKey;
        return fakeCredential('create');
      }),
      get: vi.fn(async (arg: any) => {
        captured = arg.publicKey;
        return fakeCredential('get');
      }),
    },
  });
});

const serverOptions = {
  publicKey: {
    rp: { name: 'remote-gpg-agent', id: 'localhost' },
    user: { name: 'rga-user', displayName: 'remote-gpg-agent', id: 'cmdhLXVzZXI' },
    challenge: 'wKAfPtDD1BuW2hZMgxoSgHMIzai0aUmHeb0Vgaj31dg',
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    timeout: 300000,
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    attestation: 'none',
    extensions: { prf: {} },
  },
};

describe('createPasskey', () => {
  it('サーバの {publicKey: ...} をそのまま渡せる', async () => {
    const res = await createPasskey(serverOptions as any);
    expect(captured).not.toBeNull();
    expect(captured.challenge).toBeInstanceOf(Uint8Array);
    expect(captured.user.id).toBeInstanceOf(Uint8Array);
    expect(res.credentialId).toBe('cred-1');
    expect(res.prfEnabled).toBe(true);
    expect(res.prfOutput).toBeInstanceOf(Uint8Array);
    expect(res.prfOutput?.length).toBe(32);
  });

  it('内側の publicKey を直接渡しても動く', async () => {
    const res = await createPasskey(serverOptions.publicKey as any);
    expect(captured.challenge).toBeInstanceOf(Uint8Array);
    expect(res.credentialId).toBe('cred-1');
  });

  it('extensions.prf.eval.first を BufferSource に直す', async () => {
    const withEval = {
      publicKey: {
        ...serverOptions.publicKey,
        extensions: { prf: { eval: { first: 'AAAAAA' } } },
      },
    };
    await createPasskey(withEval as any);
    expect(captured.extensions.prf.eval.first).toBeInstanceOf(Uint8Array);
  });
  it('PRF 出力はサーバへ送らない（enabled だけを載せる）', async () => {
    const res: any = await createPasskey(serverOptions as any);
    const ext = res.response.clientExtensionResults;
    expect(ext.prf.enabled).toBe(true);
    expect(ext.prf.results).toBeUndefined();
  });
  it('assertion でも clientExtensionResults に PRF 出力を載せない', async () => {
    const res: any = await assertWithPrf({
      publicKey: {
        challenge: 'wKAfPtDD1BuW2hZMgxoSgHMIzai0aUmHeb0Vgaj31dg',
        rpId: 'localhost',
        allowCredentials: [{ type: 'public-key', id: 'Y3JlZC0x' }],
        userVerification: 'required',
        extensions: { prf: { eval: { first: 'AAAAAA' } } },
      },
    } as any);
    // ローカルでは PRF 出力が取れている
    expect(res.prfOutput?.length).toBe(32);
    // しかしサーバへ送る JSON には含まれない
    expect(res.response.clientExtensionResults.prf.results).toBeUndefined();
  });
});

describe('assertWithPrf', () => {
  it('サーバの {publicKey: ...} をそのまま渡せる', async () => {
    const res = await assertWithPrf({
      publicKey: {
        challenge: 'wKAfPtDD1BuW2hZMgxoSgHMIzai0aUmHeb0Vgaj31dg',
        rpId: 'localhost',
        allowCredentials: [{ type: 'public-key', id: 'Y3JlZC0x' }],
        userVerification: 'required',
        extensions: { prf: { eval: { first: 'AAAAAA' } } },
      },
    } as any);
    expect(captured.challenge).toBeInstanceOf(Uint8Array);
    expect(captured.allowCredentials[0].id).toBeInstanceOf(Uint8Array);
    expect(captured.extensions.prf.eval.first).toBeInstanceOf(Uint8Array);
    expect(res.prfOutput?.length).toBe(32);
  });
});
