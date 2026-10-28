import { b64url, unb64url } from './b64';

export interface CeremonyResult {
  credentialId: string;
  prfEnabled: boolean;
  prfOutput?: Uint8Array;
  response: unknown;
}

function toB64(buf?: ArrayBuffer | null): string | undefined {
  return buf ? b64url(new Uint8Array(buf)) : undefined;
}

/**
 * getClientExtensionResults() は ArrayBuffer を返すが、JSON にすると `{}` に潰れて
 * サーバ（go-webauthn）が assertion をパースできない。base64url に直して送る。
 */
function serializeExtensions(ext: any): any {
  const out: any = {};
  if (ext?.prf) {
    out.prf = { enabled: Boolean(ext.prf.enabled) };
    const first = toB64(ext.prf.results?.first);
    const second = toB64(ext.prf.results?.second);
    if (first || second) {
      out.prf.results = { ...(first ? { first } : {}), ...(second ? { second } : {}) };
    }
  }
  return out;
}

/**
 * サーバは WebAuthn の JSON 形（`{publicKey: {...}}`）で返す。内側の
 * publicKey を直接渡された場合も動くようにしておく。
 */
function toPublicKeyOptions(options: any): any {
  const o = options && typeof options === 'object' && options.publicKey ? options.publicKey : options;
  if (!o || typeof o !== 'object') throw new Error('WebAuthn の options が空です');
  return o;
}

/**
 * サーバが返す options.extensions.prf.eval.first は base64url 文字列なので、
 * navigator.credentials が要求する BufferSource に直す。
 */
function convertExtensions(ext: any): any {
  if (!ext || !ext.prf) return undefined;
  const prf: any = {};
  if (ext.prf.eval?.first) prf.eval = { first: unb64url(ext.prf.eval.first) };
  return { prf };
}

export async function createPasskey(options: any): Promise<CeremonyResult> {
  const o = toPublicKeyOptions(options);
  const publicKey: PublicKeyCredentialCreationOptions = {
    ...o,
    challenge: unb64url(o.challenge) as BufferSource,
    user: { ...o.user, id: unb64url(o.user.id) as BufferSource },
    excludeCredentials: (o.excludeCredentials ?? []).map((c: any) => ({
      ...c,
      id: unb64url(c.id) as BufferSource,
    })),
    extensions: convertExtensions(o.extensions),
  };

  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new Error('パスキーの作成がキャンセルされました');

  const res = cred.response as AuthenticatorAttestationResponse;
  const ext: any = cred.getClientExtensionResults();
  return {
    credentialId: cred.id,
    prfEnabled: Boolean(ext?.prf?.enabled),
    prfOutput: ext?.prf?.results?.first ? new Uint8Array(ext.prf.results.first) : undefined,
    response: {
      id: cred.id,
      rawId: b64url(new Uint8Array(cred.rawId)),
      type: cred.type,
      clientExtensionResults: serializeExtensions(ext),
      authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
      response: {
        clientDataJSON: b64url(new Uint8Array(res.clientDataJSON)),
        attestationObject: b64url(new Uint8Array(res.attestationObject)),
        transports: res.getTransports?.() ?? [],
      },
    },
  };
}

export async function assertWithPrf(options: any): Promise<CeremonyResult> {
  const o = toPublicKeyOptions(options);
  const publicKey: PublicKeyCredentialRequestOptions = {
    ...o,
    challenge: unb64url(o.challenge) as BufferSource,
    allowCredentials: (o.allowCredentials ?? []).map((c: any) => ({
      ...c,
      id: unb64url(c.id) as BufferSource,
    })),
    extensions: convertExtensions(o.extensions),
  };

  const cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new Error('認証がキャンセルされました');

  const res = cred.response as AuthenticatorAssertionResponse;
  const ext: any = cred.getClientExtensionResults();
  return {
    credentialId: cred.id,
    prfEnabled: Boolean(ext?.prf?.results?.first ?? ext?.prf?.enabled),
    prfOutput: ext?.prf?.results?.first ? new Uint8Array(ext.prf.results.first) : undefined,
    response: {
      id: cred.id,
      rawId: b64url(new Uint8Array(cred.rawId)),
      type: cred.type,
      clientExtensionResults: serializeExtensions(ext),
      authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
      response: {
        clientDataJSON: b64url(new Uint8Array(res.clientDataJSON)),
        authenticatorData: b64url(new Uint8Array(res.authenticatorData)),
        signature: b64url(new Uint8Array(res.signature)),
        userHandle: res.userHandle ? b64url(new Uint8Array(res.userHandle)) : undefined,
      },
    },
  };
}
