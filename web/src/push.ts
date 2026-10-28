import { api } from './api';
import { unb64url } from './b64';

export function pushSupported(): boolean {
  return 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
}

export function pushPermission(): NotificationPermission | 'unsupported' {
  if (!('Notification' in window)) return 'unsupported';
  return Notification.permission;
}

async function ensurePermission(): Promise<void> {
  if (!pushSupported()) {
    throw new Error('この環境では通知を使えません（ホーム画面に追加した PWA で開いてください）');
  }
  if (Notification.permission === 'granted') return;
  if ((await Notification.requestPermission()) !== 'granted') {
    throw new Error('通知が許可されていません（iOS は 設定 → 通知 → remote-gpg-agent を確認）');
  }
}

/** Web Push を購読する。iOS では「ホーム画面に追加」した PWA でのみ動く。 */
export async function subscribePush(): Promise<void> {
  await ensurePermission();
  const reg = await navigator.serviceWorker.ready;
  const { publicKey } = await api.vapidPublicKey();
  const sub = await reg.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: unb64url(publicKey) as BufferSource,
  });
  const json = sub.toJSON() as { endpoint?: string; keys?: { p256dh?: string; auth?: string } };
  if (!json.endpoint || !json.keys?.p256dh || !json.keys?.auth) {
    throw new Error('購読情報が不完全です');
  }
  await api.subscribe({ endpoint: json.endpoint, p256dh: json.keys.p256dh, auth: json.keys.auth });
}

/**
 * 通知を無効にする。ブラウザ側の購読を先に解除してからサーバの購読を消す。
 * もう一度「有効にする」を押すと新しい endpoint で再登録される
 * (= 端末側とサーバ側の購読がずれた時のリセット操作を兼ねる)。
 */
export async function unsubscribePush(): Promise<void> {
  if ('serviceWorker' in navigator) {
    const reg = await navigator.serviceWorker.getRegistration();
    const sub = await reg?.pushManager.getSubscription();
    if (sub) await sub.unsubscribe();
  }
  await api.unsubscribe();
}

export async function testPush(channel: 'webpush' | 'discord'): Promise<string> {
  const res = await api.testNotify(channel);
  if (channel === 'discord') {
    return res.ok ? 'Discord にテスト通知を送信しました' : 'Discord への送信に失敗しました';
  }
  return `Web Push を ${res.sent ?? 0} 件送信しました`;
}
