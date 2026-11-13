export interface CommitIdentity {
  name: string;
  email: string;
  /** コミットに記録されたタイムゾーンでの表示。例: 2026/11/13 18:00 +0900 */
  date: string;
}

export interface CommitInfo {
  tree: string;
  parents: string[];
  author?: CommitIdentity;
  committer?: CommitIdentity;
  subject: string;
  body: string;
}

export interface DecodedPrefix {
  text: string;
  bytes: Uint8Array;
  truncated: boolean;
}

/** purpose を PWA の見出しにする。未知の値はそのまま出す。 */
export function purposeTitle(purpose: string): string {
  switch (purpose) {
    case 'git-commit':
      return 'Git コミット署名';
    case 'makepkg':
      return 'Arch パッケージ署名';
    case 'repo-db':
      return 'Arch リポジトリ DB 署名';
    case 'file':
      return 'ファイル署名';
    case 'sign':
      return 'データ署名';
    default:
      return purpose || '署名';
  }
}

export function isPackagePurpose(purpose: string): boolean {
  return purpose === 'makepkg' || purpose === 'repo-db';
}

/**
 * base64 の先頭だけをデコードする。makepkg のパッケージは数十 MB に
 * なるので、全部を atob しない。
 */
export function decodePrefix(dataB64: string, maxBytes = 64 * 1024): DecodedPrefix {
  const needed = Math.min(dataB64.length, Math.ceil(maxBytes / 3) * 4);
  const chunk = dataB64.slice(0, needed);
  const aligned = chunk.slice(0, chunk.length - (chunk.length % 4));
  let bin = '';
  try {
    bin = atob(aligned);
  } catch {
    return { text: '', bytes: new Uint8Array(), truncated: false };
  }
  const bytes = new Uint8Array(Math.min(bin.length, maxBytes));
  for (let i = 0; i < bytes.length; i++) bytes[i] = bin.charCodeAt(i);
  return {
    text: new TextDecoder('utf-8').decode(bytes),
    bytes,
    truncated: dataB64.length > aligned.length,
  };
}

/** 制御文字だけを '.' にする（改行とタブは残す）。 */
export function sanitizeText(s: string): string {
  return s.replace(/[^\P{Cc}\t\n]/gu, '.');
}

/** バイナリの識別用に先頭の数バイトを hex で出す。 */
export function hexPreview(dataB64: string, maxBytes = 32): string {
  const { bytes } = decodePrefix(dataB64, maxBytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(' ');
}

const HASH_RE = /^[0-9a-f]{40,64}$/i;

function formatTimestamp(unix: number, tz: string): string {
  if (!Number.isFinite(unix) || !/^[+-]\d{4}$/.test(tz)) return '';
  const sign = tz.startsWith('-') ? -1 : 1;
  const offset = sign * (Number(tz.slice(1, 3)) * 3600 + Number(tz.slice(3, 5)) * 60);
  const d = new Date((unix + offset) * 1000);
  const p = (n: number): string => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}/${p(d.getUTCMonth() + 1)}/${p(d.getUTCDate())} ` +
    `${p(d.getUTCHours())}:${p(d.getUTCMinutes())} ${tz}`;
}

function parseIdentity(value: string): CommitIdentity {
  const m = /^(.*) <([^>]*)> (\d+) ([+-]\d{4})$/.exec(value);
  if (!m) return { name: value, email: '', date: '' };
  return { name: m[1], email: m[2], date: formatTimestamp(Number(m[3]), m[4]) };
}

/**
 * git のコミットオブジェクト（`tree ...\n作者...\n\nメッセージ`）を読む。
 * 生のバイト列をそのまま見せるより、コミットとして読める形にするためのもの。
 */
export function parseCommitObject(raw: string): CommitInfo | null {
  const sep = raw.indexOf('\n\n');
  const headerText = sep === -1 ? raw : raw.slice(0, sep);
  const message = sep === -1 ? '' : raw.slice(sep + 2);

  const headers = new Map<string, string[]>();
  let lastKey = '';
  for (const line of headerText.split('\n')) {
    if (line.startsWith(' ')) {
      // 折り返されたヘッダ（gpgsig / mergetag など）。表示には使わない。
      const values = headers.get(lastKey);
      if (values && values.length > 0) values[values.length - 1] += '\n' + line.slice(1);
      continue;
    }
    const sp = line.indexOf(' ');
    if (sp === -1) {
      lastKey = '';
      continue;
    }
    const key = line.slice(0, sp);
    const list = headers.get(key) ?? [];
    list.push(line.slice(sp + 1));
    headers.set(key, list);
    lastKey = key;
  }

  const tree = headers.get('tree')?.[0] ?? '';
  if (!HASH_RE.test(tree)) return null;

  const parents = (headers.get('parent') ?? []).filter((p) => HASH_RE.test(p));
  const authorRaw = headers.get('author')?.[0];
  const committerRaw = headers.get('committer')?.[0];
  const [first, ...rest] = sanitizeText(message).split('\n');
  // 件名と本文の間の空行は本文には含めない。
  if (rest[0] === '') rest.shift();

  return {
    tree,
    parents,
    author: authorRaw ? parseIdentity(authorRaw) : undefined,
    committer: committerRaw ? parseIdentity(committerRaw) : undefined,
    subject: first ?? '',
    body: rest.join('\n').replace(/\s+$/, ''),
  };
}
