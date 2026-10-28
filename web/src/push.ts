import { api } from './api';
import { unb64url } from './b64';

/** Web Push を購読する。iOS では「ホーム画面に追加」した PWA でのみ動く。 */
export async function subscribePush(): Promise<void> {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
    throw new Error('この環境では通知を使えません（ホーム画面に追加した PWA で開いてください）');
  }
  const reg = await navigator.serviceWorker.ready;
  if ((await Notification.requestPermission()) !== 'granted') {
    throw new Error('通知が許可されていません');
  }
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
