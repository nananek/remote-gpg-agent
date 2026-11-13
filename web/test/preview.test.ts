import { describe, expect, it } from 'vitest';
import { b64 } from '../src/b64';
import {
  decodePrefix,
  hexPreview,
  isPackagePurpose,
  parseCommitObject,
  purposeTitle,
} from '../src/preview';

const encode = (s: string): string => b64(new TextEncoder().encode(s));

describe('parseCommitObject', () => {
  it('tree / parent / author / committer / message を読む', () => {
    const raw = [
      'tree 0123456789abcdef0123456789abcdef01234567',
      'parent abcdef0123456789abcdef0123456789abcdef01',
      'author Alice <alice@example.com> 1700000000 +0900',
      'committer Bob <bob@example.com> 1700000060 -0500',
      '',
      '件名',
      '',
      '本文の 1 行目',
      '本文の 2 行目',
    ].join('\n');

    const c = parseCommitObject(raw);
    expect(c).not.toBeNull();
    expect(c!.tree).toBe('0123456789abcdef0123456789abcdef01234567');
    expect(c!.parents).toEqual(['abcdef0123456789abcdef0123456789abcdef01']);
    expect(c!.author).toEqual({
      name: 'Alice',
      email: 'alice@example.com',
      date: '2023/11/15 07:13 +0900',
    });
    expect(c!.committer).toEqual({
      name: 'Bob',
      email: 'bob@example.com',
      date: '2023/11/14 17:14 -0500',
    });
    expect(c!.subject).toBe('件名');
    expect(c!.body).toBe('本文の 1 行目\n本文の 2 行目');
  });

  it('折り返しヘッダ（gpgsig など）を読み飛ばす', () => {
    const raw = [
      'tree 0123456789abcdef0123456789abcdef01234567',
      'author Alice <alice@example.com> 1700000000 +0000',
      'gpgsig -----BEGIN PGP SIGNATURE-----',
      ' AAAA',
      ' -----END PGP SIGNATURE-----',
      'committer Alice <alice@example.com> 1700000000 +0000',
      '',
      'signed commit',
    ].join('\n');

    const c = parseCommitObject(raw);
    expect(c!.subject).toBe('signed commit');
    expect(c!.author!.name).toBe('Alice');
  });

  it('コミットオブジェクトでなければ null', () => {
    expect(parseCommitObject('hello\nworld')).toBeNull();
    expect(parseCommitObject('')).toBeNull();
    expect(parseCommitObject('tree not-a-hash\n\nmsg')).toBeNull();
  });
});

describe('purposeTitle', () => {
  it('署名の種類を人間向けの見出しにする', () => {
    expect(purposeTitle('git-commit')).toBe('Git コミット署名');
    expect(purposeTitle('makepkg')).toBe('Arch パッケージ署名');
    expect(purposeTitle('repo-db')).toBe('Arch リポジトリ DB 署名');
    expect(purposeTitle('file')).toBe('ファイル署名');
    expect(purposeTitle('sign')).toBe('データ署名');
    expect(purposeTitle('custom')).toBe('custom');
  });

  it('パッケージ系だけバイナリ扱いにする', () => {
    expect(isPackagePurpose('makepkg')).toBe(true);
    expect(isPackagePurpose('repo-db')).toBe(true);
    expect(isPackagePurpose('git-commit')).toBe(false);
  });
});

describe('decodePrefix', () => {
  it('base64 の先頭だけを UTF-8 でデコードする', () => {
    const data = 'こんにちは世界';
    const { text, truncated } = decodePrefix(encode(data), 1024);
    expect(text).toBe(data);
    expect(truncated).toBe(false);
  });

  it('上限を超えたら truncated を立てる', () => {
    const { text, truncated } = decodePrefix(encode('abcdefghij'), 4);
    expect(text).toBe('abcd');
    expect(truncated).toBe(true);
  });

  it('hexPreview は先頭バイトを hex で出す', () => {
    expect(hexPreview(btoa('\x28\xb5\x2f\xfd'), 4)).toBe('28 b5 2f fd');
  });
});
