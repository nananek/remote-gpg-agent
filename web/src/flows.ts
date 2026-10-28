import { api } from './api';
import { assertWithPrf, createPasskey } from './ceremonies';
import { generateKey, importBackup, selfTest, signDetached, describe, exportBackup } from './pgp';
import { deriveWrapKey, open, seal, type Envelope } from './vault';
import { state, type UnlockedKey } from './state';
import { sha256Hex, unb64 } from './b64';

export const PRF_MISSING =
  'この認証器は PRF 非対応です。iOS 18.4 以降 + iCloud キーチェーンのパスキーが必要です。';

const newSalt = (): Uint8Array => crypto.getRandomValues(new Uint8Array(32));

interface VaultPayload {
  secret: string;
  revocation: string;
}

function payloadOf(key: UnlockedKey): VaultPayload {
  return { secret: key.armoredSecret, revocation: key.revocation };
}

/**
 * 封印した直後に同じ鍵で開き直す。
 *
 * サーバは envelope を復号できない（PRF 出力を持たない）ので、壊れた ciphertext を
 * 受け取っても検証できない。送る前に往復させて、壊れたものはアップロードしない。
 */
async function sealVerified(
  plaintext: string,
  wrapKey: CryptoKey,
  fingerprint: string,
  hkdfSalt: Uint8Array,
): Promise<Envelope> {
  const env = await seal(plaintext, wrapKey, fingerprint, hkdfSalt);
  if ((await open(env, wrapKey, fingerprint)) !== plaintext) {
    throw new Error('envelope の自己検証に失敗しました（送信を中止しました）');
  }
  return env;
}

/** 1 つの鍵を、指定した PRF 出力で封印する（salt と IV は毎回新しくする）。 */
async function sealForKey(prfOutput: Uint8Array, key: UnlockedKey): Promise<Envelope> {
  const hkdfSalt = newSalt();
  const wrapKey = await deriveWrapKey(prfOutput, hkdfSalt);
  return sealVerified(JSON.stringify(payloadOf(key)), wrapKey, key.fingerprint, hkdfSalt);
}

/**
 * セッションの credential と、メモリ上の解錠状態がずれていないか確かめる。
 *
 * ずれたまま封印すると、サーバはセッションの credential 用の envelope として保存するのに
 * 中身は別 credential の PRF で暗号化され、どのパスキーからも開けない鍵になる。
 * 別タブでログインし直した場合などに起こり得る。
 */
async function assertSessionCredential(): Promise<void> {
  const me = await api.me();
  if (!me.authenticated || !me.credentialId) {
    throw new Error('ログインし直してください');
  }
  if (me.credentialId !== state.credentialId) {
    throw new Error('セッションのパスキーが切り替わりました。もう一度解錠してください');
  }
}

/**
 * パスキーの典礼で PRF 出力を得る。
 *
 * 登録 options には salt（prf.eval.first）が入っているので、create() が結果を返す。
 * 返ってこない認証器で「既存パスキーで assert して取り直す」のは誤り
 * （新しい credential の PRF ではないため、その envelope は二度と開けない）。
 */
async function prfFromRegistration(created: { prfOutput?: Uint8Array }): Promise<Uint8Array> {
  if (!created.prfOutput) {
    throw new Error(PRF_MISSING + '（登録時に PRF の評価結果が返りませんでした）');
  }
  return created.prfOutput;
}

/**
 * 初回セットアップ: パスキー登録 → 鍵生成 → 封印 → 公開。
 * 最初のパスキーは envelope を持てない（サーバの規則）ので、鍵は登録後に作る。
 */
export async function bootstrap(params: {
  bootstrapToken: string;
  label: string;
  name: string;
  email: string;
}): Promise<void> {
  const reg = await api.registerOptions(params.bootstrapToken);
  const created = await createPasskey(reg.options);
  if (!created.prfEnabled) throw new Error(PRF_MISSING);

  await api.registerVerify(reg.ceremonyId, created.response, params.label, [], params.bootstrapToken);
  const prfOutput = await prfFromRegistration(created);

  const generated = await generateKey(params.label, params.name, params.email);
  await selfTest(generated.armoredSecret);

  const hkdfSalt = newSalt();
  const wrapKey = await deriveWrapKey(prfOutput, hkdfSalt);
  const env = await sealVerified(
    JSON.stringify(payloadOf({
      fingerprint: generated.fingerprint,
      label: params.label,
      armoredSecret: generated.armoredSecret,
      revocation: generated.revocationCertificate,
    })),
    wrapKey,
    generated.fingerprint,
    hkdfSalt,
  );

  await api.sealKey({
    fingerprint: generated.fingerprint,
    label: params.label,
    publicKeyArmored: generated.armoredPublic,
    hkdfSaltB64: env.hkdfSaltB64,
    ivB64: env.ivB64,
    ciphertextB64: env.ciphertextB64,
  });

  state.set(created.credentialId, [{
    fingerprint: generated.fingerprint,
    label: params.label,
    armoredSecret: generated.armoredSecret,
    revocation: generated.revocationCertificate,
  }], prfOutput);
}

/**
 * 解錠: 1 回の Face ID でログインと PRF 取得を兼ね、その credential が解ける鍵を全部開ける。
 *
 * 復号に失敗した envelope はスキップし、失敗した鍵のラベルを返す。1 個の壊れた
 * envelope で他の鍵まで使えなくなるのを避ける（サーバは中身を検証できないので、
 * 過去のクライアント不具合や破損が混ざり得る）。
 */
export async function unlock(): Promise<string[]> {
  const login = await api.loginOptions();
  const assertion = await assertWithPrf(login.options);
  if (!assertion.prfOutput) throw new Error(PRF_MISSING);
  await api.loginVerify(login.ceremonyId, assertion.response);

  const vaultState = await api.state();
  const opened: UnlockedKey[] = [];
  const failed: string[] = [];

  for (const keyMeta of vaultState.keys) {
    const env = vaultState.envelopes.find(
      (e) => e.keyId === keyMeta.keyId && e.credentialId === assertion.credentialId,
    );
    if (!env) continue; // この端末では使えない鍵（バックアップから復元できる）

    try {
      const wrapKey = await deriveWrapKey(assertion.prfOutput, unb64(env.hkdfSaltB64));
      const raw = await open(env, wrapKey, keyMeta.fingerprint);
      const payload = JSON.parse(raw) as VaultPayload;
      await selfTest(payload.secret);
      opened.push({
        fingerprint: keyMeta.fingerprint,
        label: keyMeta.label,
        armoredSecret: payload.secret,
        revocation: payload.revocation,
      });
    } catch {
      failed.push(keyMeta.label || keyMeta.fingerprint);
    }
  }

  if (opened.length === 0) {
    if (failed.length > 0) {
      throw new Error(`鍵を復号できませんでした（envelope が壊れている可能性）: ${failed.join('、')}`);
    }
    throw new Error('この端末で使える鍵がありません。バックアップから復元してください。');
  }
  state.set(assertion.credentialId, opened, assertion.prfOutput);
  return failed;
}

/** パスキー追加: いま解錠中の鍵を、新しいパスキーの PRF 出力で再封印する。 */
export async function addPasskey(label: string): Promise<void> {
  if (!state.unlocked) throw new Error('先に解錠してください');
  await assertSessionCredential();

  const reg = await api.registerOptions();
  const created = await createPasskey(reg.options);
  if (!created.prfEnabled) throw new Error(PRF_MISSING);
  const prfOutput = await prfFromRegistration(created);

  const envelopes = [];
  for (const key of state.keys) {
    const env = await sealForKey(prfOutput, key);
    envelopes.push({
      keyId: key.fingerprint.slice(-16),
      hkdfSaltB64: env.hkdfSaltB64,
      ivB64: env.ivB64,
      ciphertextB64: env.ciphertextB64,
    });
  }
  await api.registerVerify(reg.ceremonyId, created.response, label, envelopes);

  // サーバはこの時点でセッションを新しい credential に張り替えている。
  // state を追随させないと、直後の addKey / restore が古い PRF 出力で封印してしまう。
  state.set(created.credentialId, state.keys, prfOutput);
}

/** 鍵の追加: いま解錠中の credential 用の envelope を 1 つ作る。 */
export async function addKey(params: { label: string; name: string; email: string }): Promise<UnlockedKey> {
  const prfOutput = state.prfOutput;
  if (!prfOutput) throw new Error('先に解錠してください');
  await assertSessionCredential();
  if (state.keys.some((k) => k.label === params.label)) {
    throw new Error(`ラベル "${params.label}" は既に使われています`);
  }

  const generated = await generateKey(params.label, params.name, params.email);
  await selfTest(generated.armoredSecret);

  const hkdfSalt = newSalt();
  const wrapKey = await deriveWrapKey(prfOutput, hkdfSalt);
  const env = await sealVerified(
    JSON.stringify({ secret: generated.armoredSecret, revocation: generated.revocationCertificate }),
    wrapKey,
    generated.fingerprint,
    hkdfSalt,
  );

  await api.sealKey({
    fingerprint: generated.fingerprint,
    label: params.label,
    publicKeyArmored: generated.armoredPublic,
    hkdfSaltB64: env.hkdfSaltB64,
    ivB64: env.ivB64,
    ciphertextB64: env.ciphertextB64,
  });

  const unlocked: UnlockedKey = {
    fingerprint: generated.fingerprint,
    label: params.label,
    armoredSecret: generated.armoredSecret,
    revocation: generated.revocationCertificate,
  };
  state.add(unlocked);
  return unlocked;
}

/** 承認: 要求のバイト列をそのまま署名する。 */
export async function approve(request: { id: string; dataB64: string; dataSha256: string }, fingerprint: string): Promise<void> {
  const key = state.find(fingerprint);
  if (!key) throw new Error(`${fingerprint.slice(-16)} はこの端末では解錠されていません`);

  const data = unb64(request.dataB64);
  const digest = await sha256Hex(data);
  if (digest !== request.dataSha256) {
    throw new Error('要求のハッシュが一致しません（通信中の改ざんの可能性）');
  }
  await api.sign(request.id, await signDetached(key.armoredSecret, data));
}

export async function deny(id: string): Promise<void> {
  await api.deny(id, 'PWA で拒否');
}

/** バックアップ用の armored 鍵（パスフレーズ保護）を作る。 */
export async function backup(fingerprint: string, passphrase: string): Promise<string> {
  const key = state.find(fingerprint);
  if (!key) throw new Error('鍵が見つかりません');
  return exportBackup(key.armoredSecret, passphrase);
}

/** バックアップから復元し、この credential 用に封印し直す。 */
export async function restore(armored: string, passphrase: string, label: string): Promise<void> {
  const prfOutput = state.prfOutput;
  if (!prfOutput) throw new Error('先に解錠してください');
  await assertSessionCredential();

  const secret = await importBackup(armored, passphrase);
  await selfTest(secret);
  const { fingerprint, armoredPublic } = await describe(secret);

  const hkdfSalt = newSalt();
  const wrapKey = await deriveWrapKey(prfOutput, hkdfSalt);
  const env = await sealVerified(JSON.stringify({ secret, revocation: '' }), wrapKey, fingerprint, hkdfSalt);

  await api.sealKey({
    fingerprint,
    label,
    publicKeyArmored: armoredPublic,
    hkdfSaltB64: env.hkdfSaltB64,
    ivB64: env.ivB64,
    ciphertextB64: env.ciphertextB64,
  });

  state.add({ fingerprint, label, armoredSecret: secret, revocation: '' });
}
