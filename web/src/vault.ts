import { b64, unb64 } from './b64';

const INFO = 'remote-gpg-agent:v1:vault-wrap';

export interface Envelope {
  hkdfSaltB64: string;
  ivB64: string;
  ciphertextB64: string;
}

/** PRF 出力（32B）→ HKDF-SHA256 → AES-256-GCM 鍵。 */
export async function deriveWrapKey(prfOutput: Uint8Array, hkdfSalt: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', prfOutput as BufferSource, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: hkdfSalt as BufferSource, info: new TextEncoder().encode(INFO) },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** 平文（armored 秘密鍵 + 失効証明書の JSON）を封印する。 */
export async function seal(
  plaintext: string,
  key: CryptoKey,
  fingerprint: string,
  hkdfSalt: Uint8Array,
): Promise<Envelope> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv as BufferSource,
      additionalData: new TextEncoder().encode(fingerprint) as BufferSource,
    },
    key,
    new TextEncoder().encode(plaintext),
  );
  return { hkdfSaltB64: b64(hkdfSalt), ivB64: b64(iv), ciphertextB64: b64(new Uint8Array(ct)) };
}

/** 封印を開ける。AAD は fingerprint なので、別の鍵の envelope には使えない。 */
export async function open(env: Envelope, key: CryptoKey, fingerprint: string): Promise<string> {
  const pt = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: unb64(env.ivB64) as BufferSource,
      additionalData: new TextEncoder().encode(fingerprint) as BufferSource,
    },
    key,
    unb64(env.ciphertextB64) as BufferSource,
  );
  return new TextDecoder().decode(pt);
}
