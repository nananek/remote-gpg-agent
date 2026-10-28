import * as openpgp from 'openpgp';

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
