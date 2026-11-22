import { b64url } from '../b64';

const enc = new TextEncoder();

export const PAIR_JOIN_LABEL = 'rga-pair-join:v1';
export const PAIR_FRAME_MAGIC = 'RGP1';
export const PAIR_FRAME_VERSION = 1;
/** 1 フレームの平文上限。SDP や鍵束を DataChannel に載せても詰まらない大きさ。 */
export const PAIR_CHUNK_BYTES = 16 << 10;

export const PAIR_FRAME_KEYS = 1;
export const PAIR_FRAME_RECEIPT = 2;
export type PairFrameType = typeof PAIR_FRAME_KEYS | typeof PAIR_FRAME_RECEIPT;

export type PairRole = 'creator' | 'joiner';

const HEADER_BYTES = 28;
const MAX_CHUNKS = 64;

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function normalizeFingerprint(fp: string): string {
  return fp.replace(/\s+/g, '').toUpperCase();
}

/** 表示用の 6 桁コード。QR の秘密から導き、両端末で同じ値になる。 */
export async function pairingCode(
  secret: Uint8Array,
  pairingId: string,
  credentialIds: string[],
): Promise<string> {
  const creds = [...credentialIds].sort();
  const digest = await crypto.subtle.digest(
    'SHA-256',
    concat([
      enc.encode('rga-pair-code:v1|'),
      secret,
      enc.encode(`|${pairingId}|${creds.join('|')}`),
    ]) as BufferSource,
  );
  const n = new DataView(digest).getUint32(0);
  return String(n % 1_000_000).padStart(6, '0');
}

/** サーバに預ける join 証明。秘密そのものは送らない。 */
export async function pairJoinProof(secret: Uint8Array, pairingId: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    concat([enc.encode(`${PAIR_JOIN_LABEL}|`), secret, enc.encode(`|${pairingId}`)]) as BufferSource,
  );
  return b64url(new Uint8Array(digest));
}

export interface PairCipher {
  send: CryptoKey;
  recv: CryptoKey;
  transcript: Uint8Array;
}

/**
 * 方向別の AES-GCM 鍵を導く。AAD に入れる transcript は両端末の
 * credential と DTLS fingerprint を正規化したもので、シグナリングを
 * 差し替えられると値が食い違い、復号が失敗する。
 */
export async function derivePairCipher(params: {
  secret: Uint8Array;
  pairingId: string;
  creatorCredentialId: string;
  joinerCredentialId: string;
  role: PairRole;
  localFingerprint: string;
  remoteFingerprint: string;
}): Promise<PairCipher> {
  const creds = [params.creatorCredentialId, params.joinerCredentialId].sort();
  const fps = [normalizeFingerprint(params.localFingerprint), normalizeFingerprint(params.remoteFingerprint)].sort();
  const transcript = new Uint8Array(
    await crypto.subtle.digest(
      'SHA-256',
      enc.encode(`rga-pair-transcript:v1|${params.pairingId}|${creds.join('|')}|${fps.join('|')}`) as BufferSource,
    ),
  );
  const base = await crypto.subtle.importKey('raw', params.secret as BufferSource, 'HKDF', false, ['deriveKey']);
  const derive = (dir: string): Promise<CryptoKey> =>
    crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: enc.encode(params.pairingId) as BufferSource,
        info: enc.encode(`rga-pair:v1|${dir}|${creds.join('|')}`) as BufferSource,
      },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  return {
    send: await derive(params.role === 'creator' ? 'c2j' : 'j2c'),
    recv: await derive(params.role === 'creator' ? 'j2c' : 'c2j'),
    transcript,
  };
}

/** SDP から DTLS の証明書 fingerprint を取り出す。 */
export function dtlsFingerprint(sdp: string): string {
  for (const line of sdp.split(/\r?\n/)) {
    const m = /^a=fingerprint:\s*sha-256\s+([0-9A-Fa-f:]+)\s*$/.exec(line.trim());
    if (m) return normalizeFingerprint(m[1]);
  }
  throw new Error('SDP に DTLS fingerprint が含まれていません');
}

function header(
  type: number,
  seq: number,
  msgId: number,
  idx: number,
  total: number,
  plainLen: number,
  ctLen: number,
): Uint8Array {
  const h = new Uint8Array(HEADER_BYTES);
  h.set([...PAIR_FRAME_MAGIC].map((c) => c.charCodeAt(0)), 0);
  h[4] = type;
  h[5] = PAIR_FRAME_VERSION;
  const view = new DataView(h.buffer);
  view.setUint32(8, seq);
  view.setUint32(12, msgId);
  view.setUint16(16, idx);
  view.setUint16(18, total);
  view.setUint32(20, plainLen);
  view.setUint32(24, ctLen);
  return h;
}

function nonce(seq: number): Uint8Array {
  const n = new Uint8Array(12);
  new DataView(n.buffer).setUint32(4, seq);
  return n;
}

async function sealFrame(
  cipher: PairCipher,
  type: number,
  seq: number,
  msgId: number,
  idx: number,
  total: number,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const h = header(type, seq, msgId, idx, total, plaintext.length, plaintext.length + 16);
  const aad = concat([h, cipher.transcript]);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce(seq) as BufferSource, additionalData: aad as BufferSource },
      cipher.send,
      plaintext as BufferSource,
    ),
  );
  if (ct.length !== plaintext.length + 16) throw new Error('暗号文の長さが不正です');
  return concat([h, ct]);
}

export interface OpenedFrame {
  type: number;
  seq: number;
  msgId: number;
  idx: number;
  total: number;
  plaintext: Uint8Array;
}

export async function openFrame(cipher: PairCipher, frame: Uint8Array): Promise<OpenedFrame> {
  if (frame.length < HEADER_BYTES) throw new Error('フレームが短すぎます');
  if (String.fromCharCode(...frame.subarray(0, 4)) !== PAIR_FRAME_MAGIC) {
    throw new Error('フレームの形式が違います');
  }
  if (frame[5] !== PAIR_FRAME_VERSION) throw new Error('フレームのバージョンが違います');
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  const seq = view.getUint32(8);
  const msgId = view.getUint32(12);
  const idx = view.getUint16(16);
  const total = view.getUint16(18);
  const plainLen = view.getUint32(20);
  const ctLen = view.getUint32(24);
  if (ctLen + HEADER_BYTES !== frame.length || total === 0 || idx >= total) {
    throw new Error('フレームの分割情報が壊れています');
  }
  const h = frame.subarray(0, HEADER_BYTES);
  const ct = frame.subarray(HEADER_BYTES);
  const aad = concat([h, cipher.transcript]);
  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce(seq) as BufferSource, additionalData: aad as BufferSource },
      cipher.recv,
      ct as BufferSource,
    ),
  );
  if (plaintext.length !== plainLen) throw new Error('平文の長さが一致しません');
  return { type: frame[4], seq, msgId, idx, total, plaintext };
}

/**
 * 1 つの論理メッセージを分割して送受信する。各断片を個別に AEAD するので、
 * 欠落・重複・順序の入れ替えはその場で落ちる。
 */
export class PairChannel {
  private seq = 0;
  private nextMsgId = 1;
  private lastSeq = 0;
  private pending = new Map<number, { type: number; total: number; chunks: (Uint8Array | undefined)[]; got: number }>();
  private completed = new Set<number>();

  constructor(private readonly cipher: PairCipher) {}

  async encode(type: PairFrameType, payload: Uint8Array): Promise<Uint8Array[]> {
    const total = Math.max(1, Math.ceil(payload.length / PAIR_CHUNK_BYTES));
    if (total > MAX_CHUNKS) throw new Error('送信するメッセージが大きすぎます');
    const msgId = this.nextMsgId++;
    const frames: Uint8Array[] = [];
    for (let idx = 0; idx < total; idx++) {
      const chunk = payload.subarray(idx * PAIR_CHUNK_BYTES, Math.min(payload.length, (idx + 1) * PAIR_CHUNK_BYTES));
      frames.push(await sealFrame(this.cipher, type, ++this.seq, msgId, idx, total, chunk));
    }
    return frames;
  }

  async accept(frame: Uint8Array): Promise<{ type: number; payload: Uint8Array } | null> {
    const f = await openFrame(this.cipher, frame);
    if (f.seq !== this.lastSeq + 1) {
      throw new Error('フレームの順序が不正です（再生された可能性があります）');
    }
    this.lastSeq = f.seq;
    let slot = this.pending.get(f.msgId);
    if (!slot) {
      if (this.completed.has(f.msgId)) throw new Error('完了したメッセージが再送されました');
      if (f.total > MAX_CHUNKS) throw new Error('分割数が多すぎます');
      slot = { type: f.type, total: f.total, chunks: new Array(f.total), got: 0 };
      this.pending.set(f.msgId, slot);
    }
    if (slot.total !== f.total || slot.type !== f.type) throw new Error('メッセージの分割情報が食い違っています');
    if (slot.chunks[f.idx]) throw new Error('メッセージの断片が重複しています');
    slot.chunks[f.idx] = f.plaintext;
    slot.got++;
    if (slot.got < slot.total) return null;

    this.pending.delete(f.msgId);
    this.completed.add(f.msgId);
    const size = slot.chunks.reduce((n, c) => n + (c?.length ?? 0), 0);
    const payload = new Uint8Array(size);
    let offset = 0;
    for (const c of slot.chunks) {
      payload.set(c as Uint8Array, offset);
      offset += (c as Uint8Array).length;
    }
    return { type: slot.type, payload };
  }
}
