import * as openpgp from 'openpgp';
import { b64url } from './b64';

export interface GeneratedKey {
  armoredSecret: string;
  armoredPublic: string;
  revocationCertificate: string;
  fingerprint: string;
}

/**
 * 新しい署名鍵を作る。curve25519Legacy（v4 ed25519）に固定する:
 * v6 鍵は GnuPG 2.4 との相互運用が割れるため使わない。
 */
export async function generateKey(label: string, name: string, email: string): Promise<GeneratedKey> {
  if (!name.trim() || !email.trim()) {
    throw new Error('名前とメールアドレスを入れてください（鍵の uid になります）');
  }
  const { privateKey, publicKey, revocationCertificate } = await openpgp.generateKey({
    type: 'ecc',
    curve: 'curve25519Legacy',
    userIDs: [label ? { name, email, comment: label } : { name, email }],
    format: 'armored',
  });
  const key = await openpgp.readPrivateKey({ armoredKey: privateKey });
  return {
    armoredSecret: privateKey,
    armoredPublic: publicKey,
    revocationCertificate,
    fingerprint: key.getFingerprint().toUpperCase(),
  };
}

/** detached 署名（binary）。gpg --detach-sign と同じバイト列を対象にする。 */
export async function signDetached(armoredSecret: string, data: Uint8Array): Promise<string> {
  const started = performance.now();
  const key = await openpgp.readPrivateKey({ armoredKey: armoredSecret });
  const message = await openpgp.createMessage({ binary: data });
  const sig = await openpgp.sign({ message, signingKeys: key, detached: true, format: 'armored' });
  console.info(`rga: signed ${data.length}B in ${Math.round(performance.now() - started)}ms`);
  return sig as string;
}

/** インポート直後に自分で署名→検証する。未対応曲線や壊れた鍵はここで落とす。 */
export async function selfTest(armoredSecret: string): Promise<void> {
  const probe = new TextEncoder().encode('remote-gpg-agent selftest');
  const sig = await signDetached(armoredSecret, probe);
  const key = await openpgp.readPrivateKey({ armoredKey: armoredSecret });
  const res = await openpgp.verify({
    message: await openpgp.createMessage({ binary: probe }),
    signature: await openpgp.readSignature({ armoredSignature: sig }),
    verificationKeys: key.toPublic(),
  });
  await res.signatures[0].verified;
}

export async function describe(armoredSecret: string): Promise<{ fingerprint: string; armoredPublic: string }> {
  const key = await openpgp.readPrivateKey({ armoredKey: armoredSecret });
  return { fingerprint: key.getFingerprint().toUpperCase(), armoredPublic: key.toPublic().armor() };
}

/** バックアップ: パスフレーズで保護した armored 秘密鍵を返す。 */
export async function exportBackup(armoredSecret: string, passphrase: string): Promise<string> {
  const key = await openpgp.readPrivateKey({ armoredKey: armoredSecret });
  const locked = await openpgp.encryptKey({ privateKey: key, passphrase });
  return locked.armor();
}

/** 復元: パスフレーズ付き armored 鍵を平文の armored 鍵に戻す。 */
export async function importBackup(armored: string, passphrase: string): Promise<string> {
  const key = await openpgp.readPrivateKey({ armoredKey: armored.trim() });
  const unlocked = key.isDecrypted() ? key : await openpgp.decryptKey({ privateKey: key, passphrase });
  return unlocked.armor();
}


/**
 * OpenPGP の署名対象 digest を計算する。
 *
 * EdDSA はこの digest を Ed25519 のメッセージとして署名する。digest は
 * 「データ本体の SHA-256」ではなく、signature packet の hashed area と
 * trailer まで含めた SHA-256 である点に注意する。
 */
export async function openpgpDigest(data: Uint8Array, sigMeta: Uint8Array): Promise<Uint8Array> {
  const n = sigMeta.length;
  const trailer = new Uint8Array([
    4, 0xff,
    (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff,
  ]);
  const input = new Uint8Array(data.length + sigMeta.length + trailer.length);
  input.set(data, 0);
  input.set(sigMeta, data.length);
  input.set(trailer, data.length + sigMeta.length);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', input));
}

/**
 * 解錠中の v4 EdDSA 鍵で 32 byte の digest に署名し、raw 64 byte を返す。
 *
 * 秘密鍵の seed を OpenPGP.js の key packet から取り出し、WebCrypto の
 * Ed25519 に渡す。OpenPGP.js 自身も eddsa.js で同じことをしている。
 * ここで作るのは署名パケットではなく raw 署名。パケットは client が組む。
 */
export async function signDigest(armoredSecret: string, digest: Uint8Array): Promise<Uint8Array> {
  if (digest.length !== 32) throw new Error('digest は 32 byte である必要があります');
  const key = await openpgp.readPrivateKey({ armoredKey: armoredSecret });
  const packet = key.keyPacket as unknown as {
    privateParams?: { seed?: Uint8Array };
    publicParams?: { Q?: Uint8Array };
  };
  const seed = packet.privateParams?.seed;
  const Q = packet.publicParams?.Q;
  if (!seed || seed.length !== 32 || !Q || Q.length !== 33 || Q[0] !== 0x40) {
    throw new Error('この鍵は Ed25519 の digest 署名に対応していません');
  }
  const jwk: JsonWebKey = {
    kty: 'OKP',
    crv: 'Ed25519',
    d: b64url(seed),
    x: b64url(Q.slice(1)),
  };
  try {
    const cryptoKey = await crypto.subtle.importKey('jwk', jwk, 'Ed25519', false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('Ed25519', cryptoKey, digest));
  } catch (err) {
    throw new Error(`このブラウザは Ed25519 の WebCrypto に対応していません: ${(err as Error).message}`);
  }
}
