import { api, type PairingStatus } from '../api';
import { assertWithPrf, createPasskey } from '../ceremonies';
import { b64url, sha256Hex, unb64, unb64url } from '../b64';
import { importFromPairing, type PairingKeyPayload } from '../flows';
import { state, type UnlockedKey } from '../state';
import {
  PAIR_FRAME_KEYS,
  PAIR_FRAME_RECEIPT,
  PairChannel,
  derivePairCipher,
  pairJoinProof,
  pairingCode,
  type PairRole,
} from './psk';
import { P2PConnection, startSignalPump } from './webrtc';

const enc = new TextEncoder();
const dec = new TextDecoder();

const PRF_ANDROID =
  'この端末のパスキーが PRF に対応していません。Chrome（Google パスワード マネージャー）で開き直してください。';

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** QR は `#pair=<16B>.<32B>`。フラグメントなのでサーバのログには残らない。 */
export function parsePairHash(hash: string): { pairingId: string; secret: Uint8Array } | null {
  const m = /^#pair=([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})$/.exec(hash);
  if (!m) return null;
  return { pairingId: m[1], secret: unb64url(m[2]) };
}

export function buildPairUrl(origin: string, pairingId: string, secret: Uint8Array): string {
  return `${origin}/#pair=${pairingId}.${b64url(secret)}`;
}

/** 転送の直前に、いま解錠しているパスキーでもう一度 Face ID を取る。 */
async function reauthenticate(expectedCredentialId: string): Promise<void> {
  const login = await api.loginOptions();
  const assertion = await assertWithPrf(login.options);
  if (!assertion.prfOutput) throw new Error('この端末のパスキーで解錠できませんでした');
  if (assertion.credentialId !== expectedCredentialId) {
    throw new Error('解錠に使っているパスキーを選んでください');
  }
  await api.loginVerify(login.ceremonyId, assertion.response);
}

async function waitForJoiner(
  pairingId: string,
  expiresAt: string,
  signal: AbortSignal,
): Promise<PairingStatus> {
  const deadline = Date.parse(expiresAt);
  for (;;) {
    if (signal.aborted) throw new Error('中止しました');
    const status = await api.pairStatus(pairingId);
    if (status.state === 'joined' && status.joinerCredentialId) return status;
    if (status.state === 'aborted') throw new Error('相手側で中止されました');
    if (Number.isFinite(deadline) && Date.now() > deadline) {
      throw new Error('有効期限が切れました。もう一度 QR を表示してください');
    }
    await sleep(1000);
  }
}

interface Opened {
  peer: P2PConnection;
  channel: PairChannel;
  pump: { stop: () => void };
}

async function openChannel(params: {
  role: PairRole;
  pairingId: string;
  secret: Uint8Array;
  creatorCredentialId: string;
  joinerCredentialId: string;
  signal: AbortSignal;
}): Promise<Opened> {
  const peer = new P2PConnection(params.role, async (kind, blob) => {
    await api.pairSignal(params.pairingId, { kind, blob });
  });
  const pump = startSignalPump(
    peer,
    async (after) => (await api.pairSignals(params.pairingId, after)).signals,
  );
  const onAbort = (): void => peer.close();
  params.signal.addEventListener('abort', onAbort, { once: true });
  try {
    if (params.role === 'creator') await peer.start();
    await peer.waitOpen();
    const cipher = await derivePairCipher({
      secret: params.secret,
      pairingId: params.pairingId,
      creatorCredentialId: params.creatorCredentialId,
      joinerCredentialId: params.joinerCredentialId,
      role: params.role,
      localFingerprint: peer.localFingerprint,
      remoteFingerprint: peer.remoteFingerprint,
    });
    return { peer, channel: new PairChannel(cipher), pump };
  } catch (err) {
    pump.stop();
    peer.close();
    if (params.signal.aborted) throw new Error('中止しました');
    throw err;
  } finally {
    params.signal.removeEventListener('abort', onAbort);
  }
}

async function waitForMessage(
  peer: P2PConnection,
  channel: PairChannel,
  type: number,
  timeoutMs: number,
  signal: AbortSignal,
): Promise<Uint8Array> {
  return await new Promise<Uint8Array>((resolve, reject) => {
    if (signal.aborted) {
      reject(new Error('中止しました'));
      return;
    }
    const timer = setTimeout(
      () => reject(new Error('相手からの応答がありません（同じ Wi-Fi か確認してください）')),
      timeoutMs,
    );
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(new Error('中止しました'));
    };
    signal.addEventListener('abort', onAbort, { once: true });
    peer.onFrame((frame) => {
      void channel
        .accept(frame)
        .then((msg) => {
          if (!msg || msg.type !== type) return;
          clearTimeout(timer);
          signal.removeEventListener('abort', onAbort);
          resolve(msg.payload);
        })
        .catch((err) => {
          clearTimeout(timer);
          reject(err as Error);
        });
    });
  });
}

export interface SendHooks {
  onQr: (url: string, expiresAt: string, keys: UnlockedKey[]) => void;
  onJoined: (label: string, code: string) => Promise<boolean>;
  onStatus: (message: string) => void;
  onDone: (keys: UnlockedKey[]) => void;
}

/**
 * 解錠済みの端末から新しい端末へ、鍵素材を DataChannel で直接渡す。
 * 平文も暗号文もサーバは通らない（サーバが見るのは SDP / ICE だけ）。
 */
export async function sendToNewDevice(hooks: SendHooks, signal: AbortSignal): Promise<void> {
  if (!state.unlocked) throw new Error('先に解錠してください');
  const creatorCredentials = state.credentialId;
  const keys = [...state.keys];
  if (keys.length === 0) throw new Error('渡せる鍵がありません');

  const pairingId = b64url(crypto.getRandomValues(new Uint8Array(16)));
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const joinProof = await pairJoinProof(secret, pairingId);

  await reauthenticate(creatorCredentials);
  const created = await api.pairCreate({ pairingId, joinProof });
  hooks.onQr(buildPairUrl(location.origin, pairingId, secret), created.expiresAt, keys);

  const joined = await waitForJoiner(pairingId, created.expiresAt, signal);
  const joinerCredentialId = joined.joinerCredentialId;
  if (!joinerCredentialId) throw new Error('相手の credential が確定していません');

  const code = await pairingCode(secret, pairingId, [joined.creatorCredentialId, joinerCredentialId]);
  const approved = await hooks.onJoined(joined.joinerLabel || '新しい端末', code);
  if (!approved) {
    await api.pairAbort(pairingId).catch(() => {});
    throw new Error('転送を中止しました');
  }

  hooks.onStatus('接続しています（同じ Wi-Fi か確認してください）');
  const { peer, channel, pump } = await openChannel({
    role: 'creator',
    pairingId,
    secret,
    creatorCredentialId: joined.creatorCredentialId,
    joinerCredentialId,
    signal,
  });

  try {
    const payload: { v: number; keys: PairingKeyPayload[] } = {
      v: 1,
      keys: keys.map((k) => ({
        fingerprint: k.fingerprint,
        label: k.label,
        secret: k.armoredSecret,
        revocation: k.revocation,
      })),
    };
    for (const frame of await channel.encode(PAIR_FRAME_KEYS, enc.encode(JSON.stringify(payload)))) {
      await peer.send(frame);
    }

    hooks.onStatus('相手が鍵を封印しています');
    let receipt: string;
    try {
      receipt = dec.decode(await waitForMessage(peer, channel, PAIR_FRAME_RECEIPT, 60_000, signal));
    } catch (err) {
      // 転送は終わっているのに受領書だけ届かなかった場合に備え、
      // サーバに預けられた控えへフォールバックする。
      const stored = await waitForStoredReceipt(pairingId);
      if (!stored) throw err;
      receipt = stored;
    }
    verifyReceipt(receipt, keys);
    hooks.onDone(keys);
  } finally {
    pump.stop();
    peer.close();
  }
}

async function waitForStoredReceipt(pairingId: string): Promise<string | null> {
  for (let i = 0; i < 30; i++) {
    const status = await api.pairStatus(pairingId);
    if (status.receipt) return dec.decode(unb64url(status.receipt));
    await sleep(1000);
  }
  return null;
}

function verifyReceipt(receipt: string, keys: UnlockedKey[]): void {
  let parsed: { v?: number; keys?: { keyId?: string }[] };
  try {
    parsed = JSON.parse(receipt) as { v?: number; keys?: { keyId?: string }[] };
  } catch {
    throw new Error('受領書を読めませんでした');
  }
  if (parsed.v !== 1 || !Array.isArray(parsed.keys)) throw new Error('受領書の形式が不正です');
  const want = keys.map((k) => k.fingerprint.slice(-16).toUpperCase()).sort();
  const got = parsed.keys.map((k) => String(k.keyId ?? '').toUpperCase()).sort();
  if (want.length !== got.length || want.some((id, i) => id !== got[i])) {
    throw new Error('受領した鍵の一覧が、送った内容と一致しません');
  }
}

export interface ReceiveHooks {
  onStatus: (message: string) => void;
  onCode: (code: string) => void;
  onDone: (keys: UnlockedKey[]) => void;
}

function deviceLabel(): string {
  return /Android/i.test(navigator.userAgent) ? 'Android 端末' : '新しい端末';
}

/**
 * QR を読んだ端末側。先にパスキーを作ってセッションを得てから、
 * DataChannel で鍵素材を受け取り、自分の PRF で封印し直してアップロードする。
 */
export async function receiveFromNewDevice(
  pairingId: string,
  secret: Uint8Array,
  hooks: ReceiveHooks,
  signal: AbortSignal,
): Promise<void> {
  hooks.onStatus('この端末のパスキーを作成しています（生体認証）');
  const joinProof = await pairJoinProof(secret, pairingId);

  let joined: { ceremonyId: string; options: unknown };
  try {
    joined = await api.pairJoin({ pairingId, joinProof });
  } catch {
    throw new Error('この QR は使えません（期限切れか、すでに使われています）');
  }
  const created = await createPasskey(joined.options);
  if (!created.prfEnabled || !created.prfOutput) throw new Error(PRF_ANDROID);
  const prfOutput = created.prfOutput;
  await api.registerVerify(joined.ceremonyId, created.response, deviceLabel(), [], undefined, pairingId);
  state.set(created.credentialId, [], prfOutput);

  const status = await api.pairStatus(pairingId);
  const code = await pairingCode(secret, pairingId, [status.creatorCredentialId, created.credentialId]);
  hooks.onCode(code);
  hooks.onStatus('解錠中の端末に出ているコードと同じか確認してください');

  const { peer, channel, pump } = await openChannel({
    role: 'joiner',
    pairingId,
    secret,
    creatorCredentialId: status.creatorCredentialId,
    joinerCredentialId: created.credentialId,
    signal,
  });

  try {
    const raw = await waitForMessage(peer, channel, PAIR_FRAME_KEYS, 60_000, signal);
    const payload = JSON.parse(dec.decode(raw)) as { v?: number; keys?: PairingKeyPayload[] };
    if (payload.v !== 1 || !Array.isArray(payload.keys) || payload.keys.length === 0) {
      throw new Error('受信した鍵の形式が不正です');
    }
    hooks.onStatus('鍵をこの端末のパスキーで封印しています');
    const result = await importFromPairing(payload.keys);

    const receiptKeys = [];
    for (const sealed of result.sealed) {
      receiptKeys.push({ keyId: sealed.keyId, sha256: await sha256Hex(unb64(sealed.ciphertextB64)) });
    }
    const receipt = JSON.stringify({ v: 1, keys: receiptKeys });
    const encodedReceipt = b64url(enc.encode(receipt));

    // 先にサーバへ控えを置く。チャネルが切れても解錠側が完了を確認できる。
    await api.pairComplete(pairingId, { receipt: encodedReceipt });
    for (const frame of await channel.encode(PAIR_FRAME_RECEIPT, enc.encode(receipt))) {
      await peer.send(frame);
    }
    state.set(created.credentialId, result.keys, prfOutput);
    hooks.onDone(result.keys);
  } finally {
    pump.stop();
    peer.close();
  }
}
