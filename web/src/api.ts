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

export interface PendingRequest {
  id: string;
  purpose: string;
  description: string;
  clientName: string;
  keyFingerprint: string;
  dataSha256: string;
  dataSize: number;
  dataB64: string;
  textMode: boolean;
  createdAt: string;
  expiresAt: string;
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

  registerVerify: (ceremonyId: string, response: unknown, label: string, envelopes: unknown[], bootstrap?: string) =>
    call<{ credentialId: string }>(
      'POST',
      '/api/v1/auth/register/verify',
      { ceremonyId, response, label, envelopes },
      bootstrap ? { 'x-rga-bootstrap': bootstrap } : undefined,
    ),

  loginOptions: () => call<{ ceremonyId: string; options: any }>('POST', '/api/v1/auth/login/options', {}),

  loginVerify: (ceremonyId: string, response: unknown) =>
    call<{ credentialId: string }>('POST', '/api/v1/auth/login/verify', { ceremonyId, response }),

  logout: () => call('POST', '/api/v1/auth/logout', {}),

  state: () => call<VaultState>('GET', '/api/v1/state'),

  sealKey: (body: {
    fingerprint: string;
    label: string;
    publicKeyArmored: string;
    hkdfSaltB64: string;
    ivB64: string;
    ciphertextB64: string;
  }) => call<{ keyId: string }>('POST', '/api/v1/keys', body),

  pending: () => call<{ requests: PendingRequest[] }>('GET', '/api/v1/requests?status=pending'),

  sign: (id: string, signatureArmored: string) =>
    call('POST', `/api/v1/requests/${id}/sign`, { signatureArmored }),

  deny: (id: string, reason: string) => call('POST', `/api/v1/requests/${id}/deny`, { reason }),

  vapidPublicKey: () => call<{ publicKey: string }>('GET', '/api/v1/push/vapid-public-key'),

  subscribe: (body: { endpoint: string; p256dh: string; auth: string }) =>
    call('POST', '/api/v1/push/subscribe', body),
};
