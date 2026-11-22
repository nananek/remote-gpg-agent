import { api } from './api';
import { assertWithPrf, createPasskey } from './ceremonies';
import { generateKey, importBackup, selfTest, signDetached, describe, exportBackup, openpgpDigest, signDigest } from './pgp';
import { deriveWrapKey, envelopeProofMessage, open, seal, type Envelope } from './vault';
import { state, type UnlockedKey } from './state';
import { b64, sha256Hex, unb64 } from './b64';

export const PRF_MISSING =
  'この認証器は PRF 非対応です。iOS 18.4 以降の iCloud キーチェーン、または Chrome の ' +
  'Google パスワード マネージャーのパスキーが必要です。';

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

interface SealedEnvelopeForUpload {
  keyId: string;
  hkdfSaltB64: string;
  ivB64: string;
  ciphertextB64: string;
  proof: string;
}

/**
 * 鍵を封印し、その鍵の秘密鍵で所持証明を付ける。
 *
 * サーバは envelope を復号できないので、「本当にその鍵を持っているか」を
 * 確かめる手段はこの証明だけ。credential と envelope の全フィールドを束ねる。
 */
async function sealForKey(
  prfOutput: Uint8Array,
  credentialId: string,
  key: { fingerprint: string; armoredSecret: string },
  payload: VaultPayload,
): Promise<{ env: Envelope; upload: SealedEnvelopeForUpload }> {
  const hkdfSalt = newSalt();
  const wrapKey = await deriveWrapKey(prfOutput, hkdfSalt);
  const env = await sealVerified(JSON.stringify(payload), wrapKey, key.fingerprint, hkdfSalt);
  const keyId = key.fingerprint.slice(-16);
  const proof = await signDetached(
    key.armoredSecret,
    envelopeProofMessage(credentialId, { keyId, ...env }),
  );
  return {
    env,
    upload: { keyId, hkdfSaltB64: env.hkdfSaltB64, ivB64: env.ivB64, ciphertextB64: env.ciphertextB64, proof },
  };
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
 * パスキーのセレモニーで PRF 出力を得る。
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

  const sealed = await sealForKey(
    prfOutput,
    created.credentialId,
    { fingerprint: generated.fingerprint, armoredSecret: generated.armoredSecret },
    { secret: generated.armoredSecret, revocation: generated.revocationCertificate },
  );

  await api.sealKey({
    credentialId: created.credentialId,
    fingerprint: generated.fingerprint,
    label: params.label,
    publicKeyArmored: generated.armoredPublic,
    hkdfSaltB64: sealed.env.hkdfSaltB64,
    ivB64: sealed.env.ivB64,
    ciphertextB64: sealed.env.ciphertextB64,
    proof: sealed.upload.proof,
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
    const sealed = await sealForKey(prfOutput, created.credentialId, key, payloadOf(key));
    envelopes.push(sealed.upload);
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

  const sealed = await sealForKey(
    prfOutput,
    state.credentialId,
    { fingerprint: generated.fingerprint, armoredSecret: generated.armoredSecret },
    { secret: generated.armoredSecret, revocation: generated.revocationCertificate },
  );

  await api.sealKey({
    credentialId: state.credentialId,
    fingerprint: generated.fingerprint,
    label: params.label,
    publicKeyArmored: generated.armoredPublic,
    hkdfSaltB64: sealed.env.hkdfSaltB64,
    ivB64: sealed.env.ivB64,
    ciphertextB64: sealed.env.ciphertextB64,
    proof: sealed.upload.proof,
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

/** 承認: digest モードは client が計算した digest に署名する。 */
export async function approve(
  request: {
    id: string;
    mode: 'digest' | 'data';
    dataSha256: string;
    dataSize: number;
    dataAvailable?: boolean;
    digestB64?: string;
    sigMetaB64?: string;
  },
  fingerprint: string,
): Promise<void> {
  const key = state.find(fingerprint);
  if (!key) throw new Error(`${fingerprint.slice(-16)} はこの端末では解錠されていません`);

  if (request.mode === 'digest') {
    if (!request.digestB64 || !request.sigMetaB64) {
      throw new Error('署名対象の digest が要求に含まれていません');
    }
    const digest = unb64(request.digestB64);
    const sigMeta = unb64(request.sigMetaB64);

    // データ本体が同梱されているときは、client が渡した digest を自分で
    // 計算し直して照合する。大きいデータは本体が無いので digest だけを
    // 信頼する（画面にその旨を出す）。
    if (request.dataAvailable && request.dataSize <= 1 << 20) {
      const data = await api.requestData(request.id);
      const expectedSize = request.dataSize;
      if (expectedSize >= 0 && data.length !== expectedSize) {
        throw new Error('要求のデータ長が一致しません');
      }
      const computed = await openpgpDigest(data, sigMeta);
      if (b64(computed) !== b64(digest)) {
        throw new Error('要求の digest が一致しません（通信中の改ざんの可能性）');
      }
    }

    const signature = await signDigest(key.armoredSecret, digest);
    await api.sign(request.id, { signatureB64: b64(signature) });
    return;
  }

  const data = await api.requestData(request.id);
  const digest = await sha256Hex(data);
  if (digest !== request.dataSha256) {
    throw new Error('要求のハッシュが一致しません（通信中の改ざんの可能性）');
  }
  await api.sign(request.id, { signatureArmored: await signDetached(key.armoredSecret, data) });
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

/** 公開鍵（armored）。GitHub などへの登録に使う。秘密鍵は含まれない。 */
export async function publicKey(fingerprint: string): Promise<string> {
  const key = state.find(fingerprint);
  if (!key) throw new Error('鍵が見つかりません');
  const { armoredPublic } = await describe(key.armoredSecret);
  return armoredPublic;
}

/** バックアップから復元し、この credential 用に封印し直す。 */
export async function restore(armored: string, passphrase: string, label: string): Promise<void> {
  const prfOutput = state.prfOutput;
  if (!prfOutput) throw new Error('先に解錠してください');
  await assertSessionCredential();

  const secret = await importBackup(armored, passphrase);
  await selfTest(secret);
  const { fingerprint, armoredPublic } = await describe(secret);

  const sealed = await sealForKey(
    prfOutput,
    state.credentialId,
    { fingerprint, armoredSecret: secret },
    { secret, revocation: '' },
  );

  await api.sealKey({
    credentialId: state.credentialId,
    fingerprint,
    label,
    publicKeyArmored: armoredPublic,
    hkdfSaltB64: sealed.env.hkdfSaltB64,
    ivB64: sealed.env.ivB64,
    ciphertextB64: sealed.env.ciphertextB64,
    proof: sealed.upload.proof,
  });

  state.add({ fingerprint, label, armoredSecret: secret, revocation: '' });
}

export interface PairingKeyPayload {
  fingerprint: string;
  label: string;
  secret: string;
  revocation: string;
}

/**
 * 追加端末から受け取った鍵を、この端末の PRF で封印し直して預ける。
 *
 * 受信した armored 秘密鍵から fingerprint を計算し直すので、申告と中身が
 * 食い違う鍵はここで落ちる。サーバは復号できないため、封印の自己検証と
 * 所持証明（sealForKey）が唯一の整合性チェックになる。
 */
export async function importFromPairing(items: PairingKeyPayload[]): Promise<{
  keys: UnlockedKey[];
  sealed: { keyId: string; ciphertextB64: string }[];
}> {
  const prfOutput = state.prfOutput;
  if (!prfOutput) throw new Error('先に解錠してください');
  await assertSessionCredential();
  if (items.length === 0) throw new Error('鍵が 1 つも届きませんでした');

  const keys: UnlockedKey[] = [];
  const sealed: { keyId: string; ciphertextB64: string }[] = [];
  for (const item of items) {
    if (!item || typeof item.secret !== 'string' || typeof item.label !== 'string') {
      throw new Error('受信した鍵の形式が不正です');
    }
    const described = await describe(item.secret);
    if (described.fingerprint !== item.fingerprint.toUpperCase()) {
      throw new Error(`鍵の fingerprint が一致しません: ${item.label}`);
    }
    await selfTest(item.secret);
    const revoked = typeof item.revocation === 'string' ? item.revocation : '';
    const result = await sealForKey(
      prfOutput,
      state.credentialId,
      { fingerprint: described.fingerprint, armoredSecret: item.secret },
      { secret: item.secret, revocation: revoked },
    );
    await api.sealKey({
      credentialId: state.credentialId,
      fingerprint: described.fingerprint,
      label: item.label,
      publicKeyArmored: described.armoredPublic,
      hkdfSaltB64: result.env.hkdfSaltB64,
      ivB64: result.env.ivB64,
      ciphertextB64: result.env.ciphertextB64,
      proof: result.upload.proof,
    });
    keys.push({
      fingerprint: described.fingerprint,
      label: item.label,
      armoredSecret: item.secret,
      revocation: revoked,
    });
    sealed.push({ keyId: result.upload.keyId, ciphertextB64: result.env.ciphertextB64 });
  }
  return { keys, sealed };
}
