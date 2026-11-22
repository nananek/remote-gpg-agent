import './styles.css';
import { api, type PendingRequest } from './api';
import { state } from './state';
import * as flows from './flows';
import {
  busy,
  clearError,
  renderApprove,
  renderPairingConfirm,
  renderPairingDone,
  renderPairingError,
  renderPairingQR,
  renderPairingWait,
  renderSettings,
  renderSetup,
  renderUnlock,
  root,
  setError,
} from './views';
import { parsePairHash, receiveFromNewDevice, sendToNewDevice } from './pairing/flow';
import { renderQrSvg } from './pairing/qr';
import { pushPermission, subscribePush, testPush, unsubscribePush } from './push';
import { playRequestChime, primeSound, setSoundEnabled, soundEnabled } from './sound';

let polling = 0;
let renderedKey = '';

/** 直前に描画した要求 ID。解錠直後の一覧（null）では鳴らさない。 */
let knownRequestIds: Set<string> | null = null;

function announceArrivals(requests: PendingRequest[]): void {
  const previous = knownRequestIds;
  knownRequestIds = new Set(requests.map((r) => r.id));
  if (previous && requests.some((r) => !previous.has(r.id))) playRequestChime();
}

function stopPolling(): void {
  if (polling) {
    clearInterval(polling);
    polling = 0;
  }
}

function startPolling(): void {
  stopPolling();
  polling = window.setInterval(() => {
    if (!document.hidden && state.unlocked) void refresh(false);
  }, 3000);
}

/** 同じ内容の再描画でカウントダウンやスクロールを壊さないための比較キー。 */
function requestsKey(requests: PendingRequest[]): string {
  return JSON.stringify({
    requests: requests.map((r) => [r.id, r.expiresAt, r.dataSha256]),
    keys: state.keys.map((k) => [k.fingerprint, k.label]),
  });
}

async function refresh(force = true): Promise<void> {
  if (!state.unlocked) return;
  try {
    const { requests, serverNow } = await api.pending();
    announceArrivals(requests);
    const key = requestsKey(requests);
    if (!force && key === renderedKey) return;
    renderedKey = key;
    renderApprove({
      requests,
      serverNow,
      keys: state.keys,
      onSign: (r) => void sign(r),
      onDeny: (r) => void deny(r),
      onSettings: () => void showSettings(),
    });
  } catch (err) {
    setError((err as Error).message);
  }
}

async function sign(request: PendingRequest): Promise<void> {
  busy('署名しています（Face ID）');
  try {
    await flows.approve(request, request.keyFingerprint);
    await refresh();
  } catch (err) {
    await refresh();
    setError((err as Error).message);
  }
}

async function deny(request: PendingRequest): Promise<void> {
  try {
    await flows.deny(request.id);
    await refresh();
  } catch (err) {
    setError((err as Error).message);
  }
}

async function showSettings(): Promise<void> {
  stopPolling();
  let status = { webpush: false, discord: false };
  try {
    status = await api.pushStatus();
  } catch {
    /* 通知 API が落ちていても設定画面自体は開く */
  }
  renderSettings({
    keys: state.keys,
    pushSubscribed: status.webpush,
    pushPermission: pushPermission(),
    discordEnabled: status.discord,
    onBack: () => void refresh().then(startPolling),
    onAddPasskey: (label) => {
      busy('パスキーを追加しています（Face ID）');
      flows
        .addPasskey(label)
        .then(() => showSettings())
        .catch((err) => {
          void showSettings();
          setError((err as Error).message);
        });
    },
    onAddDevice: () => void startPairing(),
    onAddKey: (v) => {
      busy('鍵を生成しています');
      flows
        .addKey(v)
        .then(() => showSettings())
        .catch((err) => {
          void showSettings();
          setError((err as Error).message);
        });
    },
    onCopyPublicKey: (fingerprint) => {
      flows
        .publicKey(fingerprint)
        .then(async (armored) => {
          try {
            await navigator.clipboard.writeText(armored);
            setError('公開鍵をコピーしました');
          } catch {
            // クリップボードが使えない環境（iOS の standalone など）では共有シートに落とす。
            await deliver(`${fingerprint.slice(-16)}-public.asc`, armored);
          }
        })
        .catch((err) => setError((err as Error).message));
    },
    onBackup: (fingerprint, passphrase) => {
      if (passphrase.length < 8) {
        setError('パスフレーズは 8 文字以上にしてください');
        return;
      }
      flows
        .backup(fingerprint, passphrase)
        .then((armored) => deliver(`${fingerprint.slice(-16)}.asc`, armored))
        .catch((err) => setError((err as Error).message));
    },
    onRestore: (armored, passphrase, label) => {
      busy('復元しています');
      flows
        .restore(armored, passphrase, label)
        .then(() => showSettings())
        .catch((err) => {
          void showSettings();
          setError((err as Error).message);
        });
    },
    onSubscribePush: () => {
      subscribePush()
        .then(() => showSettings())
        .catch((err: unknown) => setError((err as Error).message));
    },
    onUnsubscribePush: () => {
      unsubscribePush()
        .then(() => showSettings())
        .catch((err: unknown) => setError((err as Error).message));
    },
    onTestPush: () => {
      testPush('webpush')
        .then((msg) => setError(msg))
        .catch((err: unknown) => setError((err as Error).message));
    },
    onTestDiscord: () => {
      testPush('discord')
        .then((msg) => setError(msg))
        .catch((err: unknown) => setError((err as Error).message));
    },
    soundEnabled: soundEnabled(),
    onToggleSound: () => {
      const next = !soundEnabled();
      setSoundEnabled(next);
      // 有効にしたときは、その場で確認できるよう 1 回鳴らす。
      if (next) playRequestChime();
      void showSettings();
    },
    onLogout: () => {
      void api.logout().finally(() => {
        state.clear();
        stopPolling();
        location.reload();
      });
    },
  });
}

/** iOS の standalone PWA では a[download] が不安定なので、share を優先する。 */
async function deliver(filename: string, text: string): Promise<void> {
  const file = new File([text], filename, { type: 'application/pgp-keys' });
  const nav = navigator as Navigator & {
    canShare?: (d: unknown) => boolean;
    share?: (d: unknown) => Promise<void>;
  };
  // 共有シートが使えるなら優先する。ただしキャンセルや失敗で何も残らないのは困るので、
  // 失敗したらダウンロードに落とす。
  if (nav.canShare?.({ files: [file] }) && typeof nav.share === 'function') {
    try {
      await nav.share({ files: [file], title: filename });
      return;
    } catch {
      /* ダウンロードへ */
    }
  }
  const url = URL.createObjectURL(file);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/**
 * 端末追加の送信側。QR を出し、相手が接続してきたらコードを突き合わせてから
 * DataChannel で鍵を渡す。サーバは SDP / ICE しか見ない。
 */
async function startPairing(): Promise<void> {
  stopPolling();
  const controller = new AbortController();
  try {
    await sendToNewDevice(
      {
        onQr: (url, expiresAt, keys) =>
          renderPairingQR({
            qrSvg: renderQrSvg(url),
            keys,
            expiresAt,
            onCancel: () => controller.abort(),
          }),
        onJoined: (label, code) =>
          new Promise<boolean>((resolve) => {
            renderPairingConfirm({
              label,
              code,
              keys: state.keys,
              onConfirm: () => resolve(true),
              onCancel: () => resolve(false),
            });
          }),
        onStatus: (lead) => renderPairingWait({ title: '端末を追加', lead }),
        onDone: (keys) =>
          renderPairingDone({ keys, onClose: () => void refresh().then(startPolling) }),
      },
      controller.signal,
    );
  } catch (err) {
    const message = (err as Error).message;
    if (message === '中止しました' || message === '転送を中止しました') {
      void refresh().then(startPolling);
      return;
    }
    renderPairingError({
      message,
      onRetry: () => void startPairing(),
      onClose: () => void refresh().then(startPolling),
    });
  }
}

/** 端末追加の受信側。QR の秘密は URL のフラグメントからだけ読む。 */
async function joinPairing(pair: { pairingId: string; secret: Uint8Array }): Promise<void> {
  let code = '';
  const render = (lead: string): void => renderPairingWait({ title: '端末を追加', lead, code });
  render('この端末を登録しています');
  const close = (): void => {
    if (state.unlocked) void refresh().then(startPolling);
    else location.replace(location.pathname);
  };
  try {
    await receiveFromNewDevice(
      pair.pairingId,
      pair.secret,
      {
        onStatus: render,
        onCode: (c) => {
          code = c;
          render('解錠中の端末と同じコードか確認してください');
        },
        onDone: (keys) => renderPairingDone({ keys, onClose: close }),
      },
      new AbortController().signal,
    );
  } catch (err) {
    renderPairingError({ message: (err as Error).message, onClose: close });
  }
}

async function boot(): Promise<void> {
  const pair = parsePairHash(location.hash);
  if (pair) {
    // QR の秘密を URL 履歴に残さない（サーバには元から送られない）。
    history.replaceState(null, '', location.pathname + location.search);
    void joinPairing(pair);
    return;
  }
  try {
    const me = await api.me();
    if (me.credentialCount === 0) {
      renderSetup({
        needsBootstrap: true,
        onSubmit: (v) => {
          busy('パスキーを作成しています（Face ID）');
          flows
            .bootstrap({ bootstrapToken: v.token, label: v.label, name: v.name, email: v.email })
            .then(() => void refresh().then(startPolling))
            .catch((err) => {
              renderSetup({ needsBootstrap: true, onSubmit: () => location.reload() });
              setError((err as Error).message);
            });
        },
      });
      return;
    }
    renderUnlock({ credentialCount: me.credentialCount, onUnlock: () => unlockNow() });
  } catch (err) {
    root().innerHTML = `<p class="error">${(err as Error).message}</p>`;
  }
}

async function unlockNow(): Promise<void> {
  busy('解錠しています（Face ID）');
  try {
    const failed = await flows.unlock();
    await refresh();
    startPolling();
    if (failed.length > 0) {
      setError(
        `復号できなかった鍵があります（envelope が壊れている可能性）: ${failed.join('、')}。` +
          'バックアップから復元してください。',
      );
    }
  } catch (err) {
    const me = await api.me().catch(() => null);
    renderUnlock({ credentialCount: me?.credentialCount ?? 0, onUnlock: () => unlockNow() });
    setError((err as Error).message);
  }
}

// AudioContext はユーザー操作の中でしか開始できない（iOS）。最初の操作で用意しておく。
document.addEventListener('pointerdown', primeSound, { capture: true, passive: true, once: true });
document.addEventListener('keydown', primeSound, { capture: true, once: true });

document.addEventListener('visibilitychange', () => {
  if (!document.hidden && state.unlocked) void refresh();
});

void boot();
