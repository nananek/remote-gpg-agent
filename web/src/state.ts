export interface UnlockedKey {
  fingerprint: string;
  label: string;
  armoredSecret: string;
  revocation: string;
}

let keys: UnlockedKey[] = [];
let credentialId = '';
let prf: Uint8Array | undefined;

/** 解錠中の鍵と PRF 出力。メモリだけに置く（端末ストレージに残さない）。 */
export const state = {
  get keys(): UnlockedKey[] {
    return keys;
  },
  get credentialId(): string {
    return credentialId;
  },
  get prfOutput(): Uint8Array | undefined {
    return prf;
  },
  get unlocked(): boolean {
    return keys.length > 0;
  },
  set(id: string, unlocked: UnlockedKey[], prfOutput: Uint8Array): void {
    credentialId = id;
    keys = unlocked;
    prf = prfOutput;
  },
  add(key: UnlockedKey): void {
    keys = [...keys, key];
  },
  find(fingerprint: string): UnlockedKey | undefined {
    return keys.find((k) => k.fingerprint === fingerprint.toUpperCase());
  },
  clear(): void {
    keys = [];
    credentialId = '';
    prf = undefined;
  },
};
