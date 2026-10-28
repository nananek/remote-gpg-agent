import { b64url, unb64url } from './b64';

export interface CeremonyResult {
  credentialId: string;
  prfEnabled: boolean;
  prfOutput?: Uint8Array;
  response: unknown;
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
  const publicKey: PublicKeyCredentialCreationOptions = {
    ...options,
    challenge: unb64url(options.challenge) as BufferSource,
    user: { ...options.user, id: unb64url(options.user.id) as BufferSource },
    excludeCredentials: (options.excludeCredentials ?? []).map((c: any) => ({
      ...c,
      id: unb64url(c.id) as BufferSource,
    })),
    extensions: convertExtensions(options.extensions),
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
      clientExtensionResults: ext,
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
  const publicKey: PublicKeyCredentialRequestOptions = {
    ...options,
    challenge: unb64url(options.challenge) as BufferSource,
    allowCredentials: (options.allowCredentials ?? []).map((c: any) => ({
      ...c,
      id: unb64url(c.id) as BufferSource,
    })),
    extensions: convertExtensions(options.extensions),
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
      clientExtensionResults: ext,
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
