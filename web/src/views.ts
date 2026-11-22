import type { PendingRequest } from './api';
import { countdownState, donutOffset, DONUT_CIRCUMFERENCE } from './countdown';
import {
  decodePrefix,
  hexPreview,
  isPackagePurpose,
  parseCommitObject,
  purposeTitle,
  sanitizeText,
  type CommitIdentity,
} from './preview';
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
      <input id="name" placeholder="氏名" autocomplete="off" />
      <label for="email">メールアドレス</label>
      <input id="email" placeholder="you@example.com" inputmode="email" autocomplete="off" />
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

function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 1024) return `${n || 0} バイト`;
  const units = ['KB', 'MB', 'GB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 10 ? 0 : 1)} ${units[i]}`;
}

function sameIdentity(a?: CommitIdentity, b?: CommitIdentity): boolean {
  return !!a && !!b && a.name === b.name && a.email === b.email && a.date === b.date;
}

function renderCommit(r: PendingRequest): string | null {
  const { text, truncated } = decodePrefix(r.dataPreviewB64 ?? '', 128 * 1024);
  const c = parseCommitObject(text);
  if (!c) return null;

  const ids = [`tree ${escapeHtml(c.tree.slice(0, 8))}`];
  if (c.parents.length > 0) {
    ids.push(`parent ${c.parents.map((p) => escapeHtml(p.slice(0, 8))).join(', ')}`);
  }
  const author = c.author
    ? `<div><dt>作成者</dt><dd>${escapeHtml(c.author.name)} &lt;${escapeHtml(c.author.email)}&gt; · ${escapeHtml(c.author.date)}</dd></div>`
    : '';
  // 作成者とコミッターが同じ（rebase / amend していない普通のコミット）なら繰り返さない。
  const committer = c.committer && !sameIdentity(c.author, c.committer)
    ? `<div><dt>コミット</dt><dd>${escapeHtml(c.committer.name)} &lt;${escapeHtml(c.committer.email)}&gt; · ${escapeHtml(c.committer.date)}</dd></div>`
    : '';

  return `
    <div class="commit">
      <p class="commit-subject">${escapeHtml(c.subject || '(メッセージなし)')}</p>
      ${c.body ? `<pre class="commit-message">${escapeHtml(c.body)}</pre>` : ''}
      <dl class="commit-meta">
        ${author}
        ${committer}
        <div><dt>オブジェクト</dt><dd>${ids.join(' · ')}</dd></div>
      </dl>
      ${truncated ? '<p class="meta">（長いコミットのため先頭のみ表示）</p>' : ''}
    </div>`;
}

function renderPackage(r: PendingRequest): string {
  const hex = hexPreview(r.dataPreviewB64 ?? '', 32);
  return `
    <div class="archive">
      <p class="archive-file">${escapeHtml(r.description)}</p>
      <p class="meta">${formatBytes(r.dataSize)} のバイナリ全体に分離署名を付けます。</p>
      ${r.preview ? `<p class="meta">${escapeHtml(r.preview)}</p>` : ''}
      ${hex ? `<pre class="preview hex">${escapeHtml(hex)} …</pre>` : ''}
    </div>`;
}

function renderBody(r: PendingRequest): string {
  if (r.purpose === 'git-commit') {
    const commit = renderCommit(r);
    if (commit) return commit;
  }
  if (isPackagePurpose(r.purpose)) return renderPackage(r);

  const { text, truncated } = decodePrefix(r.dataPreviewB64 ?? '', 4096);
  return `<pre class="preview">${escapeHtml(sanitizeText(text))}${truncated ? '\n…（以下省略）' : ''}</pre>`;
}

let clockOffsetMs = 0;
let countdownTimer: number | undefined;

function updateCountdowns(): void {
  const now = Date.now() + clockOffsetMs;
  document.querySelectorAll<HTMLElement>('[data-expires]').forEach((el) => {
    const state = countdownState(el.dataset.created ?? '', el.dataset.expires ?? '', now);
    const label = el.querySelector<HTMLElement>('.countdown-label');
    if (label) label.textContent = state.label;
    const ring = el.querySelector<SVGCircleElement>('.donut-value');
    if (ring) {
      ring.style.strokeDasharray = `${DONUT_CIRCUMFERENCE} ${DONUT_CIRCUMFERENCE}`;
      ring.style.strokeDashoffset = String(donutOffset(state.fraction));
      ring.style.stroke = state.color;
    }
    el.classList.toggle('is-expired', state.expired);

    const button = el.closest('article')?.querySelector<HTMLButtonElement>('[data-sign]');
    if (state.expired && button && !button.disabled) {
      button.disabled = true;
      button.textContent = '期限切れ';
    }
  });
}

function startCountdowns(): void {
  if (typeof window === 'undefined' || countdownTimer !== undefined) return;
  countdownTimer = window.setInterval(updateCountdowns, 1000);
}

function countdownHtml(r: PendingRequest): string {
  return `
    <div class="countdown" data-created="${escapeHtml(r.createdAt)}" data-expires="${escapeHtml(r.expiresAt)}" role="timer">
      <svg class="donut" viewBox="0 0 44 44" width="44" height="44" aria-hidden="true">
        <circle class="donut-track" cx="22" cy="22" r="18"></circle>
        <circle class="donut-value" cx="22" cy="22" r="18"></circle>
      </svg>
      <span class="countdown-label">残り --:--</span>
    </div>`;
}

export function renderApprove(params: {
  requests: PendingRequest[];
  serverNow?: string;
  keys: UnlockedKey[];
  onSign: (request: PendingRequest) => void;
  onDeny: (request: PendingRequest) => void;
  onSettings: () => void;
}): void {
  const serverTime = params.serverNow ? Date.parse(params.serverNow) : NaN;
  clockOffsetMs = Number.isFinite(serverTime) ? serverTime - Date.now() : 0;
  const now = Date.now() + clockOffsetMs;

  const cards = params.requests
    .map((r) => {
      const key = params.keys.find((k) => k.fingerprint === r.keyFingerprint.toUpperCase());
      const keyLabel = key ? key.label : 'この端末では未解錠';
      const remaining = countdownState(r.createdAt, r.expiresAt, now);
      const disabled = !key || remaining.expired;
      return `
      <article class="card request">
        <div class="request-head">
          <div class="request-title">
            <h2>${escapeHtml(purposeTitle(r.purpose))}</h2>
            <p class="meta">${escapeHtml(r.clientName)}</p>
          </div>
          ${countdownHtml(r)}
        </div>
        <p class="meta">${escapeHtml(keyLabel)} · ${formatBytes(r.dataSize)} · sha256 ${escapeHtml(r.dataSha256.slice(0, 16))}…</p>
        <p class="meta request-desc">${escapeHtml(r.description)}</p>
        ${r.mode === 'digest' && !(r.dataAvailable && r.dataSize <= 1 << 20)
          ? '<p class="meta warn">内容はこの端末に送られていません。ファイル名・サイズ・SHA-256 を確認して承認してください。</p>'
          : ''}
        ${renderBody(r)}
        <div class="row">
          <button class="primary" data-sign="${r.id}" ${disabled ? 'disabled' : ''}>${remaining.expired ? '期限切れ' : '署名する'}</button>
          <button class="quiet" data-deny="${r.id}">拒否</button>
        </div>
      </article>`;
    })
    .join('');

  root().innerHTML = `
    ${header(params.requests.length ? `承認待ち ${params.requests.length} 件` : '承認待ちはありません')}
    ${cards || '<p class="lead">端末で git commit -S や makepkg --sign を実行すると、ここに署名要求が出ます。</p>'}
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

  updateCountdowns();
  startCountdowns();
}

function permissionLabel(p: NotificationPermission | 'unsupported'): string {
  switch (p) {
    case 'granted':
      return '許可済み';
    case 'denied':
      return '拒否（設定 → 通知 で変更）';
    case 'default':
      return '未許可';
    default:
      return '非対応';
  }
}

export function renderSettings(params: {
  keys: UnlockedKey[];
  onBack: () => void;
  onAddPasskey: (label: string) => void;
  onAddDevice: () => void;
  onAddKey: (v: { label: string; name: string; email: string }) => void;
  onCopyPublicKey: (fingerprint: string) => void;
  onBackup: (fingerprint: string, passphrase: string) => void;
  onRestore: (armored: string, passphrase: string, label: string) => void;
  onSubscribePush: () => void;
  onUnsubscribePush: () => void;
  onTestPush: () => void;
  onTestDiscord: () => void;
  pushSubscribed: boolean;
  pushPermission: NotificationPermission | 'unsupported';
  discordEnabled: boolean;
  soundEnabled: boolean;
  onToggleSound: () => void;
  onLogout: () => void;
}): void {
  const keyRows = params.keys
    .map(
      (k) => `
      <div class="card">
        <h2>${escapeHtml(k.label)}</h2>
        <p class="meta">${escapeHtml(k.fingerprint)}</p>
        <button data-public="${k.fingerprint}">公開鍵をコピー</button>
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
      <p class="meta">Web Push: ${params.pushSubscribed ? '有効' : '無効'} / ブラウザの許可: ${permissionLabel(params.pushPermission)}</p>
      ${params.pushSubscribed
        ? `<button class="quiet" id="push-off">通知を無効にする</button>
           <button id="push-test">テスト通知を送る</button>`
        : `<button id="push">通知を有効にする</button>`}
      <p class="meta">Discord: ${params.discordEnabled ? '有効' : '未設定（サーバの RGA_DISCORD_WEBHOOK）'}</p>
      ${params.discordEnabled ? '<button id="discord-test">Discord にテスト送信</button>' : ''}
    </div>
    <div class="card">
      <h2>効果音</h2>
      <p class="meta">署名要求が来たときに短いチャイムを鳴らします。</p>
      <button id="sound-toggle">${params.soundEnabled ? '効果音を無効にする' : '効果音を有効にする'}</button>
    </div>
    <div class="card">
      <h2>パスキーを追加</h2>
      <p class="meta">いま解錠中の鍵を、新しいパスキーでも開けるようにします。</p>
      <label for="passkey-label">ラベル</label>
      <input id="passkey-label" value="予備のパスキー" />
      <button id="add-passkey">パスキーを追加</button>
    </div>
    <div class="card">
      <h2>端末を追加</h2>
      <p class="meta">Android など別のプラットフォームの端末に、いま解錠中の鍵を直接渡します。同じ Wi-Fi に接続した 2 台で行ってください。</p>
      <button id="add-device">QR を表示して追加</button>
    </div>
    <div class="card">
      <h2>鍵を追加</h2>
      <label for="key-label">ラベル</label>
      <input id="key-label" value="arch-pkg" />
      <label for="key-name">名前</label>
      <input id="key-name" placeholder="氏名" />
      <label for="key-email">メールアドレス</label>
      <input id="key-email" placeholder="you@example.com" />
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

  document.querySelector<HTMLButtonElement>('#push')?.addEventListener('click', params.onSubscribePush);
  document.querySelector<HTMLButtonElement>('#push-off')?.addEventListener('click', params.onUnsubscribePush);
  document.querySelector<HTMLButtonElement>('#push-test')?.addEventListener('click', params.onTestPush);
  document.querySelector<HTMLButtonElement>('#discord-test')?.addEventListener('click', params.onTestDiscord);
  document.querySelector<HTMLButtonElement>('#sound-toggle')?.addEventListener('click', params.onToggleSound);
  btn('add-passkey').addEventListener('click', () => params.onAddPasskey(val('passkey-label') || '予備のパスキー'));
  btn('add-device').addEventListener('click', params.onAddDevice);
  btn('add-key').addEventListener('click', () =>
    params.onAddKey({ label: val('key-label') || 'key2', name: val('key-name'), email: val('key-email') }));
  btn('restore').addEventListener('click', () =>
    params.onRestore(val('restore-armored'), val('restore-pass'), val('restore-label') || 'restored'));
  btn('back').addEventListener('click', params.onBack);
  btn('logout').addEventListener('click', params.onLogout);
  root().querySelectorAll<HTMLButtonElement>('[data-backup]').forEach((b) =>
    b.addEventListener('click', () => params.onBackup(b.dataset.backup!, val('pass-' + b.dataset.backup))));
  root().querySelectorAll<HTMLButtonElement>('[data-public]').forEach((b) =>
    b.addEventListener('click', () => params.onCopyPublicKey(b.dataset.public!)));
}

function pairKeyList(keys: UnlockedKey[]): string {
  const rows = keys
    .map(
      (k) => `<li><span>${escapeHtml(k.label)}</span><code>${escapeHtml(k.fingerprint.slice(-16))}</code></li>`,
    )
    .join('');
  return `<ul class="pair-keys">${rows}</ul>`;
}

function pairExpiry(iso: string): string {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return iso;
  return new Date(t).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' });
}

/** 送信側: QR を表示して相手の接続を待つ。 */
export function renderPairingQR(params: {
  qrSvg: string;
  keys: UnlockedKey[];
  expiresAt: string;
  onCancel: () => void;
}): void {
  root().innerHTML = `
    ${header('端末を追加', '新しい端末のカメラでこの QR を読み取ってください。')}
    <div class="card pair">
      <div class="qr">${params.qrSvg}</div>
      <p class="meta">有効期限: ${escapeHtml(pairExpiry(params.expiresAt))}。この画面を閉じると中断します。</p>
      <p class="meta">渡す鍵: ${params.keys.length} 個</p>
      ${pairKeyList(params.keys)}
      <p class="meta warn">同じ Wi-Fi に接続した 2 台で行ってください。モバイル回線では接続できません。</p>
      <button class="quiet" id="pair-cancel">中止する</button>
      <p class="error" id="err"></p>
    </div>`;
  root().querySelector<HTMLButtonElement>('#pair-cancel')!.addEventListener('click', params.onCancel);
}

/** 送信側: 接続してきた端末を確認し、鍵を渡す最終承認を取る。 */
export function renderPairingConfirm(params: {
  label: string;
  code: string;
  keys: UnlockedKey[];
  onConfirm: () => void;
  onCancel: () => void;
}): void {
  root().innerHTML = `
    ${header('接続を確認', '新しい端末に同じ 6 桁のコードが出ていることを確かめてください。')}
    <div class="card">
      <p class="pair-code">${escapeHtml(params.code)}</p>
      <p class="meta">${escapeHtml(params.label)} が接続しました。</p>
      <p class="meta">この端末の署名鍵（秘密鍵）を渡します。</p>
      ${pairKeyList(params.keys)}
      <p class="meta warn">このコードは QR を見た相手にも計算できます。認証の代わりにはなりません。心当たりのない接続は中止してください。</p>
      <p class="meta warn">渡した鍵は、相手端末のパスキーで開ける形で保存されます。取り消すには GPG 鍵のローテーションが必要です。</p>
      <button class="primary" id="pair-send">鍵を渡す</button>
      <button class="quiet" id="pair-cancel">中止する</button>
      <p class="error" id="err"></p>
    </div>`;
  root().querySelector<HTMLButtonElement>('#pair-send')!.addEventListener('click', params.onConfirm);
  root().querySelector<HTMLButtonElement>('#pair-cancel')!.addEventListener('click', params.onCancel);
}

/** 受信側: パスキー作成中・接続中の待機画面。コードが出たら大きく見せる。 */
export function renderPairingWait(params: { title: string; lead: string; code?: string }): void {
  root().innerHTML = `
    ${header(params.title, params.lead)}
    <div class="card">
      ${params.code ? `<p class="pair-code">${escapeHtml(params.code)}</p><p class="meta">解錠中の端末と同じコードか確認してください。</p>` : ''}
      <p class="meta">両方の画面を開いたままにしてください。</p>
      <p class="error" id="err"></p>
    </div>`;
}

export function renderPairingDone(params: { keys: UnlockedKey[]; onClose: () => void }): void {
  root().innerHTML = `
    ${header('追加しました', `${params.keys.length} 個の鍵をこの端末でも使えるようにしました。`)}
    <div class="card">
      ${pairKeyList(params.keys)}
      <p class="meta">次回からは、この端末のパスキーで解錠できます。</p>
      <button class="primary" id="pair-close">閉じる</button>
    </div>`;
  root().querySelector<HTMLButtonElement>('#pair-close')!.addEventListener('click', params.onClose);
}

export function renderPairingError(params: {
  message: string;
  onRetry?: () => void;
  onClose: () => void;
}): void {
  root().innerHTML = `
    ${header('追加できませんでした')}
    <div class="card">
      <p class="error">${escapeHtml(params.message)}</p>
      <p class="meta">同じ Wi-Fi に接続し、両方の画面を開いたまま、もう一度 QR からやり直してください。</p>
      ${params.onRetry ? '<button class="primary" id="pair-retry">もう一度</button>' : ''}
      <button class="quiet" id="pair-close">閉じる</button>
    </div>`;
  root().querySelector<HTMLButtonElement>('#pair-retry')?.addEventListener('click', params.onRetry!);
  root().querySelector<HTMLButtonElement>('#pair-close')!.addEventListener('click', params.onClose);
}
