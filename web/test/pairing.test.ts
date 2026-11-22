import { describe, expect, it } from 'vitest';
import {
  PAIR_FRAME_KEYS,
  PairChannel,
  derivePairCipher,
  dtlsFingerprint,
  pairJoinProof,
  pairingCode,
  type PairCipher,
} from '../src/pairing/psk';
import { buildPairUrl, parsePairHash } from '../src/pairing/flow';

const secret = new Uint8Array(32).fill(7);
const pairingId = 'AAAAAAAAAAAAAAAAAAAAAA';
const creatorCred = 'creator-credential';
const joinerCred = 'joiner-credential';
const fpCreator = 'AA:BB:CC:DD';
const fpJoiner = '11:22:33:44';

async function cipherPair(overrides?: {
  joinerSecret?: Uint8Array;
  joinerRemote?: string;
}): Promise<{ creator: PairCipher; joiner: PairCipher }> {
  const creator = await derivePairCipher({
    secret,
    pairingId,
    creatorCredentialId: creatorCred,
    joinerCredentialId: joinerCred,
    role: 'creator',
    localFingerprint: fpCreator,
    remoteFingerprint: fpJoiner,
  });
  const joiner = await derivePairCipher({
    secret: overrides?.joinerSecret ?? secret,
    pairingId,
    creatorCredentialId: creatorCred,
    joinerCredentialId: joinerCred,
    role: 'joiner',
    localFingerprint: overrides?.joinerRemote ?? fpJoiner,
    remoteFingerprint: fpCreator,
  });
  return { creator, joiner };
}

const text = new TextEncoder();

async function roundTrip(payload: Uint8Array): Promise<void> {
  const { creator, joiner } = await cipherPair();
  const sender = new PairChannel(creator);
  const receiver = new PairChannel(joiner);
  const frames = await sender.encode(PAIR_FRAME_KEYS, payload);
  let got: { type: number; payload: Uint8Array } | null = null;
  for (const frame of frames) got = await receiver.accept(frame);
  expect(got).not.toBeNull();
  expect(got!.type).toBe(PAIR_FRAME_KEYS);
  expect(new Uint8Array(got!.payload)).toEqual(payload);
}

describe('pairing psk', () => {
  it('round-trips a small message', async () => {
    await roundTrip(text.encode('hello pairing'));
  });

  it('splits and reassembles a payload larger than one chunk', async () => {
    const payload = new Uint8Array(40 * 1024);
    for (let i = 0; i < payload.length; i++) payload[i] = i % 251;
    await roundTrip(payload);
  });

  it('rejects a different pairing secret', async () => {
    const { creator, joiner } = await cipherPair({ joinerSecret: new Uint8Array(32).fill(8) });
    const frames = await new PairChannel(creator).encode(PAIR_FRAME_KEYS, text.encode('secret'));
    await expect(new PairChannel(joiner).accept(frames[0])).rejects.toThrow();
  });

  it('rejects a mismatched DTLS transcript (signaling MITM)', async () => {
    const { creator, joiner } = await cipherPair({ joinerRemote: '99:88:77:66' });
    const frames = await new PairChannel(creator).encode(PAIR_FRAME_KEYS, text.encode('secret'));
    await expect(new PairChannel(joiner).accept(frames[0])).rejects.toThrow();
  });

  it('rejects replayed frames', async () => {
    const { creator, joiner } = await cipherPair();
    const frames = await new PairChannel(creator).encode(PAIR_FRAME_KEYS, text.encode('secret'));
    const receiver = new PairChannel(joiner);
    await receiver.accept(frames[0]);
    await expect(receiver.accept(frames[0])).rejects.toThrow(/再生/);
  });

  it('rejects tampered ciphertext', async () => {
    const { creator, joiner } = await cipherPair();
    const frames = await new PairChannel(creator).encode(PAIR_FRAME_KEYS, text.encode('secret'));
    const tampered = new Uint8Array(frames[0]);
    tampered[tampered.length - 1] ^= 0x01;
    await expect(new PairChannel(joiner).accept(tampered)).rejects.toThrow();
  });

  it('derives the same confirmation code on both devices', async () => {
    const a = await pairingCode(secret, pairingId, [creatorCred, joinerCred]);
    const b = await pairingCode(secret, pairingId, [joinerCred, creatorCred]);
    expect(a).toBe(b);
    expect(a).toMatch(/^\d{6}$/);
    const other = await pairingCode(new Uint8Array(32).fill(9), pairingId, [creatorCred, joinerCred]);
    expect(other).not.toBe(a);
  });

  it('derives a join proof bound to the pairing id', async () => {
    const a = await pairJoinProof(secret, pairingId);
    const b = await pairJoinProof(secret, pairingId);
    const c = await pairJoinProof(secret, 'BBBBBBBBBBBBBBBBBBBBBB');
    expect(a).toBe(b);
    expect(a).not.toBe(c);
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});

describe('pairing url', () => {
  it('round-trips the QR fragment', () => {
    const url = buildPairUrl('https://rga.example.ts.net', pairingId, secret);
    expect(url.startsWith('https://rga.example.ts.net/#pair=')).toBe(true);
    const hash = url.slice(url.indexOf('#'));
    const parsed = parsePairHash(hash);
    expect(parsed).not.toBeNull();
    expect(parsed!.pairingId).toBe(pairingId);
    expect(Array.from(parsed!.secret)).toEqual(Array.from(secret));
  });

  it('ignores unrelated or malformed hashes', () => {
    expect(parsePairHash('')).toBeNull();
    expect(parsePairHash('#pair=short.secret')).toBeNull();
    expect(parsePairHash('#other=1')).toBeNull();
  });
});

describe('dtls fingerprint', () => {
  it('extracts and normalizes the sha-256 fingerprint', () => {
    const sdp = [
      'v=0',
      'o=- 1 2 IN IP4 0.0.0.0',
      'a=fingerprint:sha-256 ab:cd:ef:01',
      '',
    ].join('\r\n');
    expect(dtlsFingerprint(sdp)).toBe('AB:CD:EF:01');
  });

  it('fails when the SDP has no fingerprint', () => {
    expect(() => dtlsFingerprint('v=0\r\n')).toThrow(/fingerprint/);
  });
});
