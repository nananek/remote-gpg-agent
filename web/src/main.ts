import './styles.css';
import { api, type PendingRequest } from './api';
import { state } from './state';
import * as flows from './flows';
import {
  busy,
  clearError,
  renderApprove,
  renderSettings,
  renderSetup,
  renderUnlock,
  root,
  setError,
} from './views';
import { subscribePush } from './push';

let polling = 0;

function stopPolling(): void {
  if (polling) {
    clearInterval(polling);
    polling = 0;
  }
}

function startPolling(): void {
  stopPolling();
  polling = window.setInterval(() => {
    if (!document.hidden && state.unlocked) void refresh();
  }, 3000);
}

async function refresh(): Promise<void> {
  if (!state.unlocked) return;
  try {
    const { requests } = await api.pending();
    renderApprove({
      requests,
      keys: state.keys,
      onSign: (r) => void sign(r),
      onDeny: (r) => void deny(r),
      onSettings: () => showSettings(),
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

function showSettings(): void {
  stopPolling();
  renderSettings({
    keys: state.keys,
    onBack: () => void refresh().then(startPolling),
    onAddPasskey: (label) => {
      busy('パスキーを追加しています（Face ID）');
      flows
        .addPasskey(label)
        .then(() => showSettings())
        .catch((err) => {
          showSettings();
          setError((err as Error).message);
        });
    },
    onAddKey: (v) => {
      busy('鍵を生成しています');
      flows
        .addKey(v)
        .then(() => showSettings())
        .catch((err) => {
          showSettings();
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
          showSettings();
          setError((err as Error).message);
        });
    },
    onSubscribePush: () => {
      subscribePush()
        .then(() => setError('通知を有効にしました'))
        .catch((err: unknown) => setError((err as Error).message));
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

async function boot(): Promise<void> {
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

document.addEventListener('visibilitychange', () => {
  if (!document.hidden && state.unlocked) void refresh();
});

void boot();
