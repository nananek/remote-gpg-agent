import type { PendingRequest } from './api';
import type { UnlockedKey } from './state';

export function root(): HTMLElement {
  const el = document.querySelector('#app');
  if (!el) throw new Error('#app がありません');
  return el as HTMLElement;
}

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] as string));
}

function header(title: string, lead?: string): string {
  return `<header><h1>${escapeHtml(title)}</h1>${lead ? `<p class="lead">${escapeHtml(lead)}</p>` : ''}</header>`;
}

export function setError(msg: string): void {
  const el = document.querySelector('#err');
  if (el) el.textContent = msg;
}

export function clearError(): void {
  setError('');
}

export function busy(label: string): void {
  root().innerHTML = `${header('処理中')}<p class="lead">${escapeHtml(label)}</p>`;
}

export function renderSetup(params: {
  needsBootstrap: boolean;
  onSubmit: (v: { token: string; label: string; name: string; email: string }) => void;
}): void {
  root().innerHTML = `
    ${header('remote-gpg-agent', 'この iPhone を署名端末として登録します。')}
    <form class="card" id="setup">
      ${params.needsBootstrap ? `
        <label for="token">セットアップ用トークン</label>
        <input id="token" autocomplete="off" autocapitalize="off" spellcheck="false" />` : ''}
      <label for="label">鍵のラベル</label>
      <input id="label" value="personal" autocomplete="off" />
      <label for="name">名前</label>
      <input id="name" value="氏名" autocomplete="off" />
      <label for="email">メールアドレス</label>
      <input id="email" value="you@example.com" inputmode="email" autocomplete="off" />
      <button class="primary" type="submit">パスキーを作って鍵を生成</button>
      <p class="error" id="err"></p>
    </form>`;

  root().querySelector<HTMLFormElement>('#setup')!.addEventListener('submit', (e) => {
    e.preventDefault();
    params.onSubmit({
      token: (document.querySelector('#token') as HTMLInputElement | null)?.value.trim() ?? '',
      label: (document.querySelector('#label') as HTMLInputElement).value.trim() || 'personal',
      name: (document.querySelector('#name') as HTMLInputElement).value.trim(),
      email: (document.querySelector('#email') as HTMLInputElement).value.trim(),
    });
  });
}

export function renderUnlock(params: { onUnlock: () => void; credentialCount: number }): void {
  root().innerHTML = `
    ${header('ロック中', 'Face ID で解錠すると、承認待ちの要求が表示されます。')}
    <div class="card">
      <button class="primary" id="unlock">Face ID で解錠</button>
      <p class="meta">登録済みパスキー: ${params.credentialCount} 個</p>
      <p class="error" id="err"></p>
    </div>`;
  root().querySelector<HTMLButtonElement>('#unlock')!.addEventListener('click', params.onUnlock);
}

function previewOf(r: PendingRequest): string {
  try {
    const text = atob(r.dataB64).slice(0, 600);
    return text.replace(/[^\t\n\x20-\x7e]/g, '.');
  } catch {
    return '(preview unavailable)';
  }
}

export function renderApprove(params: {
  requests: PendingRequest[];
  keys: UnlockedKey[];
  onSign: (request: PendingRequest) => void;
  onDeny: (request: PendingRequest) => void;
  onSettings: () => void;
}): void {
  const cards = params.requests
    .map((r) => {
      const key = params.keys.find((k) => k.fingerprint === r.keyFingerprint.toUpperCase());
      const keyLabel = key ? key.label : 'この端末では未解錠';
      return `
      <article class="card">
        <h2>${escapeHtml(r.purpose)} · ${escapeHtml(r.clientName)}</h2>
        <p class="meta">${escapeHtml(keyLabel)} · ${r.dataSize} バイト · sha256 ${r.dataSha256.slice(0, 16)}…</p>
        <p class="meta">${escapeHtml(r.description)}</p>
        <pre class="preview">${escapeHtml(previewOf(r))}</pre>
        <div class="row">
          <button class="primary" data-sign="${r.id}" ${key ? '' : 'disabled'}>署名する</button>
          <button class="quiet" data-deny="${r.id}">拒否</button>
        </div>
      </article>`;
    })
    .join('');

  root().innerHTML = `
    ${header(params.requests.length ? `承認待ち ${params.requests.length} 件` : '承認待ちはありません')}
    ${cards || '<p class="lead">端末でコミットすると、ここに署名要求が出ます。</p>'}
    <p class="error" id="err"></p>
    <div class="card">
      <button id="settings">設定</button>
    </div>`;

  root().querySelectorAll<HTMLButtonElement>('[data-sign]').forEach((b) =>
    b.addEventListener('click', () => {
      const r = params.requests.find((x) => x.id === b.dataset.sign);
      if (r) params.onSign(r);
    }));
  root().querySelectorAll<HTMLButtonElement>('[data-deny]').forEach((b) =>
    b.addEventListener('click', () => {
      const r = params.requests.find((x) => x.id === b.dataset.deny);
      if (r) params.onDeny(r);
    }));
  root().querySelector<HTMLButtonElement>('#settings')!.addEventListener('click', params.onSettings);
}

export function renderSettings(params: {
  keys: UnlockedKey[];
  onBack: () => void;
  onAddPasskey: (label: string) => void;
  onAddKey: (v: { label: string; name: string; email: string }) => void;
  onBackup: (fingerprint: string, passphrase: string) => void;
  onRestore: (armored: string, passphrase: string, label: string) => void;
  onSubscribePush: () => void;
  onLogout: () => void;
}): void {
  const keyRows = params.keys
    .map(
      (k) => `
      <div class="card">
        <h2>${escapeHtml(k.label)}</h2>
        <p class="meta">${escapeHtml(k.fingerprint)}</p>
        <label for="pass-${k.fingerprint}">バックアップのパスフレーズ</label>
        <input id="pass-${k.fingerprint}" type="password" autocomplete="new-password" />
        <button data-backup="${k.fingerprint}">パスフレーズ付き鍵を書き出す</button>
      </div>`,
    )
    .join('');

  root().innerHTML = `
    ${header('設定')}
    <div class="card">
      <h2>通知</h2>
      <p class="meta">署名要求が来たら通知で知らせます。</p>
      <button id="push">通知を有効にする</button>
    </div>
    <div class="card">
      <h2>パスキーを追加</h2>
      <p class="meta">いま解錠中の鍵を、新しいパスキーでも開けるようにします。</p>
      <label for="passkey-label">ラベル</label>
      <input id="passkey-label" value="予備のパスキー" />
      <button id="add-passkey">パスキーを追加</button>
    </div>
    <div class="card">
      <h2>鍵を追加</h2>
      <label for="key-label">ラベル</label>
      <input id="key-label" value="arch-pkg" />
      <label for="key-name">名前</label>
      <input id="key-name" value="氏名" />
      <label for="key-email">メールアドレス</label>
      <input id="key-email" value="you@example.com" />
      <button id="add-key">新しい鍵を作る</button>
    </div>
    ${keyRows}
    <div class="card">
      <h2>バックアップから復元</h2>
      <p class="meta">他の端末で作った鍵をこの端末でも使えるようにします。</p>
      <label for="restore-armored">armored 秘密鍵</label>
      <textarea id="restore-armored" spellcheck="false"></textarea>
      <label for="restore-pass">パスフレーズ</label>
      <input id="restore-pass" type="password" autocomplete="off" />
      <label for="restore-label">ラベル</label>
      <input id="restore-label" value="restored" />
      <button id="restore">復元する</button>
    </div>
    <p class="error" id="err"></p>
    <div class="card">
      <button id="back">戻る</button>
      <button class="quiet" id="logout">ログアウト</button>
    </div>`;

  const val = (id: string): string => (document.querySelector('#' + id) as HTMLInputElement | null)?.value ?? '';
  const btn = (id: string): HTMLButtonElement => document.querySelector('#' + id) as HTMLButtonElement;

  btn('push').addEventListener('click', params.onSubscribePush);
  btn('add-passkey').addEventListener('click', () => params.onAddPasskey(val('passkey-label') || '予備のパスキー'));
  btn('add-key').addEventListener('click', () =>
    params.onAddKey({ label: val('key-label') || 'key2', name: val('key-name'), email: val('key-email') }));
  btn('restore').addEventListener('click', () =>
    params.onRestore(val('restore-armored'), val('restore-pass'), val('restore-label') || 'restored'));
  btn('back').addEventListener('click', params.onBack);
  btn('logout').addEventListener('click', params.onLogout);
  root().querySelectorAll<HTMLButtonElement>('[data-backup]').forEach((b) =>
    b.addEventListener('click', () => params.onBackup(b.dataset.backup!, val('pass-' + b.dataset.backup))));
}
