import type { Envelope } from './vault';

export interface Me {
  authenticated: boolean;
  credentialCount: number;
  credentialId?: string;
  hasVault?: boolean;
}

export interface KeyMeta {
  keyId: string;
  fingerprint: string;
  label: string;
  publicKeyArmored?: string;
}

export interface EnvelopeMeta extends Envelope {
  credentialId: string;
  keyId: string;
}

export interface VaultState {
  credentialId: string;
  credentials: { credentialId: string; label: string }[];
  keys: KeyMeta[];
  envelopes: EnvelopeMeta[];
}

export interface PushStatus {
  webpush: boolean;
  discord: boolean;
}

/** 端末追加（ペアリング）の状態。 */
export interface PairingStatus {
  state: 'created' | 'joined' | 'delivered' | 'aborted' | string;
  creatorCredentialId: string;
  joinerCredentialId?: string;
  joinerLabel?: string;
  receipt?: string;
  expiresAt: string;
}

export interface PairingSignal {
  seq: number;
  from: 'creator' | 'joiner' | string;
  kind: string;
  blob: string;
  at: string;
}

export interface PendingRequest {
  id: string;
  purpose: string;
  description: string;
  clientName: string;
  keyFingerprint: string;
  mode: 'digest' | 'data';
  dataSha256: string;
  dataSize: number;
  /** 一覧表示用の先頭部分。本体は承認時に requestData() で取得する。 */
  dataPreviewB64?: string;
  dataAvailable: boolean;
  textMode: boolean;
  digestB64?: string;
  sigMetaB64?: string;
  /** データ本体を送らないときの人間向け説明。 */
  preview?: string;
  createdAt: string;
  expiresAt: string;
}

export interface PendingResponse {
  requests: PendingRequest[];
  /** サーバの現在時刻。端末の時計ずれを補正してカウントダウンを出すのに使う。 */
  serverNow: string;
}

async function call<T>(method: string, path: string, body?: unknown, headers?: Record<string, string>): Promise<T> {
  const res = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: {
      'content-type': 'application/json',
      'x-rga-client': 'pwa',
      ...(headers ?? {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) {
    let msg = text;
    try {
      msg = (JSON.parse(text) as { error?: string }).error ?? text;
    } catch {
      /* そのまま */
    }
    throw new Error(msg || `HTTP ${res.status}`);
  }
  return (text ? JSON.parse(text) : {}) as T;
}

export const api = {
  me: () => call<Me>('GET', '/api/v1/auth/me'),

  registerOptions: (bootstrap?: string) =>
    call<{ ceremonyId: string; options: any }>(
      'POST',
      '/api/v1/auth/register/options',
      {},
      bootstrap ? { 'x-rga-bootstrap': bootstrap } : undefined,
    ),

  registerVerify: (
    ceremonyId: string,
    response: unknown,
    label: string,
    envelopes: unknown[],
    bootstrap?: string,
    pairingId?: string,
  ) =>
    call<{ credentialId: string }>(
      'POST',
      '/api/v1/auth/register/verify',
      { ceremonyId, response, label, envelopes, ...(pairingId ? { pairingId } : {}) },
      bootstrap ? { 'x-rga-bootstrap': bootstrap } : undefined,
    ),

  loginOptions: () => call<{ ceremonyId: string; options: any }>('POST', '/api/v1/auth/login/options', {}),

  loginVerify: (ceremonyId: string, response: unknown) =>
    call<{ credentialId: string }>('POST', '/api/v1/auth/login/verify', { ceremonyId, response }),

  logout: () => call('POST', '/api/v1/auth/logout', {}),

  state: () => call<VaultState>('GET', '/api/v1/state'),

  pairCreate: (body: { pairingId: string; joinProof: string }) =>
    call<{ pairingId: string; expiresAt: string }>('POST', '/api/v1/pair/create', body),

  pairJoin: (body: { pairingId: string; joinProof: string }) =>
    call<{ ceremonyId: string; options: any }>('POST', '/api/v1/pair/join', body),

  pairStatus: (pairingId: string) => call<PairingStatus>('GET', `/api/v1/pair/${pairingId}`),

  pairSignal: (pairingId: string, body: { kind: string; blob: string }) =>
    call<{ seq: number }>('POST', `/api/v1/pair/${pairingId}/signal`, body),

  pairSignals: (pairingId: string, after: number) =>
    call<{ signals: PairingSignal[] }>('GET', `/api/v1/pair/${pairingId}/signal?after=${after}`),

  pairNonce: (pairingId: string, nonce: string) =>
    call<{ ok: boolean }>('POST', `/api/v1/pair/${pairingId}/nonce`, { nonce }),

  pairComplete: (pairingId: string, body: { receipt: string; nonce: string }) =>
    call<{ state: string }>('POST', `/api/v1/pair/${pairingId}/complete`, body),

  pairAbort: (pairingId: string) =>
    call<{ ok: boolean }>('POST', `/api/v1/pair/${pairingId}/abort`, {}),

  sealKey: (body: {
    credentialId: string;
    fingerprint: string;
    label: string;
    publicKeyArmored: string;
    hkdfSaltB64: string;
    ivB64: string;
    ciphertextB64: string;
    proof: string;
  }) => call<{ keyId: string }>('POST', '/api/v1/keys', body),

  pending: () => call<PendingResponse>('GET', '/api/v1/requests?status=pending'),

  sign: (id: string, body: { signatureB64?: string; signatureArmored?: string }) =>
    call('POST', `/api/v1/requests/${id}/sign`, body),

  requestData: async (id: string): Promise<Uint8Array> => {
    const res = await fetch(`/api/v1/requests/${id}/data`, {
      credentials: 'same-origin',
      headers: { 'x-rga-client': 'pwa' },
    });
    if (!res.ok) {
      const text = await res.text();
      let msg = text;
      try {
        msg = (JSON.parse(text) as { error?: string }).error ?? text;
      } catch {
        /* そのまま */
      }
      throw new Error(msg || `HTTP ${res.status}`);
    }
    return new Uint8Array(await res.arrayBuffer());
  },

  deny: (id: string, reason: string) => call('POST', `/api/v1/requests/${id}/deny`, { reason }),

  vapidPublicKey: () => call<{ publicKey: string }>('GET', '/api/v1/push/vapid-public-key'),

  subscribe: (body: { endpoint: string; p256dh: string; auth: string }) =>
    call('POST', '/api/v1/push/subscribe', body),

  unsubscribe: () => call<{ ok: boolean }>('DELETE', '/api/v1/push/subscribe'),

  pushStatus: () => call<PushStatus>('GET', '/api/v1/push/status'),

  testNotify: (channel: 'webpush' | 'discord') =>
    call<{ sent?: number; ok?: boolean }>('POST', '/api/v1/push/test', { channel }),
};
