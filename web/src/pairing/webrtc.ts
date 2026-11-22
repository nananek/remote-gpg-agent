import { b64url, unb64url } from '../b64';
import { dtlsFingerprint, type PairRole } from './psk';

const enc = new TextEncoder();
const dec = new TextDecoder();

export type SignalKind = 'offer' | 'answer' | 'candidate';

export interface IncomingSignal {
  seq: number;
  from: string;
  kind: string;
  blob: string;
}

const CONNECT_TIMEOUT_MS = 60_000;

/**
 * 1 本の WebRTC DataChannel を張る。SDP と ICE は呼び出し側が中継する
 * （サーバは中身を解釈しない）。鍵素材はこのチャネルの上を AEAD で流れる。
 */
export class P2PConnection {
  private readonly pc: RTCPeerConnection;
  private readonly open: Promise<void>;
  private openResolve!: () => void;
  private openReject!: (err: Error) => void;
  private dc?: RTCDataChannel;
  private opened = false;
  private closed = false;
  private candidateCount = 0;
  private trickle = false;
  private outgoing: string[] = [];
  private queued: RTCIceCandidateInit[] = [];
  private frameHandler?: (frame: Uint8Array) => void;
  private inbox: Uint8Array[] = [];

  constructor(
    readonly role: PairRole,
    private readonly sendSignal: (kind: SignalKind, blob: string) => Promise<void>,
  ) {
    this.pc = new RTCPeerConnection({
      iceServers: [],
      bundlePolicy: 'max-bundle',
      rtcpMuxPolicy: 'require',
    });
    this.open = new Promise<void>((resolve, reject) => {
      this.openResolve = resolve;
      this.openReject = reject;
    });
    // waitOpen が付く前に失敗しても unhandled rejection にしない。
    void this.open.catch(() => {});
    this.pc.onicecandidate = (e) => {
      if (!e.candidate) return;
      this.candidateCount++;
      const blob = b64url(enc.encode(JSON.stringify(e.candidate.toJSON())));
      if (this.trickle) void this.sendSignal('candidate', blob).catch(() => {});
      else this.outgoing.push(blob);
    };
    this.pc.onconnectionstatechange = () => {
      if (this.pc.connectionState === 'failed' && !this.opened) {
        this.fail('P2P 接続に失敗しました');
      }
    };
    if (role === 'creator') {
      this.attach(this.pc.createDataChannel('rga-pair', { ordered: true }));
    } else {
      this.pc.ondatachannel = (e) => this.attach(e.channel);
    }
  }

  private attach(dc: RTCDataChannel): void {
    this.dc = dc;
    dc.binaryType = 'arraybuffer';
    dc.onopen = () => {
      this.opened = true;
      this.openResolve();
    };
    dc.onclose = () => {
      if (!this.opened) this.fail('データチャネルが閉じました');
    };
    dc.onmessage = (e) => {
      const frame = new Uint8Array(e.data as ArrayBuffer);
      if (this.frameHandler) this.frameHandler(frame);
      else this.inbox.push(frame);
    };
  }

  onFrame(handler: (frame: Uint8Array) => void): void {
    this.frameHandler = handler;
    const queued = this.inbox;
    this.inbox = [];
    for (const frame of queued) handler(frame);
  }

  /** creator 側だけが呼ぶ。offer を送ってから候補の送信を始める。 */
  async start(): Promise<void> {
    const offer = await this.pc.createOffer();
    await this.pc.setLocalDescription(offer);
    const sdp = this.pc.localDescription?.sdp;
    if (!sdp) throw new Error('offer を作れませんでした');
    await this.sendSignal('offer', b64url(enc.encode(sdp)));
    await this.flushCandidates();
  }

  /** 中継されたシグナルを適用する。offer が来る前の候補は保留する。 */
  async apply(sig: IncomingSignal): Promise<void> {
    if (sig.kind === 'offer' && this.role === 'joiner') {
      await this.pc.setRemoteDescription({ type: 'offer', sdp: dec.decode(unb64url(sig.blob)) });
      await this.drainCandidates();
      const answer = await this.pc.createAnswer();
      await this.pc.setLocalDescription(answer);
      const sdp = this.pc.localDescription?.sdp;
      if (!sdp) throw new Error('answer を作れませんでした');
      await this.sendSignal('answer', b64url(enc.encode(sdp)));
      await this.flushCandidates();
      return;
    }
    if (sig.kind === 'answer' && this.role === 'creator') {
      await this.pc.setRemoteDescription({ type: 'answer', sdp: dec.decode(unb64url(sig.blob)) });
      await this.drainCandidates();
      return;
    }
    if (sig.kind === 'candidate') {
      const init = JSON.parse(dec.decode(unb64url(sig.blob))) as RTCIceCandidateInit;
      if (!this.pc.remoteDescription) {
        this.queued.push(init);
        return;
      }
      // 接続に寄与しない候補（別 interface など）は捨ててよい。
      await this.pc.addIceCandidate(init).catch(() => {});
    }
  }

  private async flushCandidates(): Promise<void> {
    this.trickle = true;
    const pending = this.outgoing;
    this.outgoing = [];
    for (const blob of pending) await this.sendSignal('candidate', blob);
  }

  private async drainCandidates(): Promise<void> {
    const pending = this.queued;
    this.queued = [];
    for (const init of pending) await this.pc.addIceCandidate(init).catch(() => {});
  }

  get localFingerprint(): string {
    return dtlsFingerprint(this.pc.localDescription?.sdp ?? '');
  }

  get remoteFingerprint(): string {
    return dtlsFingerprint(this.pc.remoteDescription?.sdp ?? '');
  }

  async waitOpen(timeoutMs = CONNECT_TIMEOUT_MS): Promise<void> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<void>((_, reject) => {
      timer = setTimeout(() => reject(new Error(this.timeoutMessage())), timeoutMs);
    });
    try {
      await Promise.race([this.open, timeout]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  private timeoutMessage(): string {
    const state = this.pc.connectionState;
    const ice = this.pc.iceConnectionState;
    return (
      `2 台を直接つなげませんでした（候補 ${this.candidateCount} 件、状態 ${state}/${ice}）。` +
      '同じ Wi-Fi に接続し、両方の画面を開いたまま再試行してください。' +
      'Wi-Fi が端末間通信を禁止している（AP アイソレーション）場合は接続できません。'
    );
  }

  async send(frame: Uint8Array): Promise<void> {
    if (!this.dc || this.dc.readyState !== 'open') throw new Error('データチャネルが開いていません');
    while (this.dc.bufferedAmount > 512 * 1024) {
      await new Promise((r) => setTimeout(r, 20));
    }
    this.dc.send(frame as unknown as ArrayBuffer);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    if (!this.opened) this.openReject(new Error('接続を中止しました'));
    try {
      this.dc?.close();
    } catch {
      /* すでに閉じている */
    }
    try {
      this.pc.close();
    } catch {
      /* 同上 */
    }
  }

  private fail(reason: string): void {
    if (this.closed) return;
    this.closed = true;
    this.openReject(new Error(this.timeoutMessage() + `（${reason}）`));
  }
}

/**
 * サーバに溜まったシグナルを拾って適用する。自分のメッセージは無視する。
 * 一時的な失敗は無視し、最終的には waitOpen のタイムアウトが拾う。
 */
export function startSignalPump(
  peer: P2PConnection,
  fetchSignals: (after: number) => Promise<IncomingSignal[]>,
  intervalMs = 400,
): { stop: () => void } {
  let cursor = 0;
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const self = peer.role;

  const tick = async (): Promise<void> => {
    if (stopped) return;
    try {
      const signals = await fetchSignals(cursor);
      for (const sig of signals) {
        cursor = sig.seq;
        if (sig.from === self) continue;
        await peer.apply(sig);
      }
    } catch {
      /* 一時的な失敗は次の周回で回収する */
    }
    if (!stopped) timer = setTimeout(() => void tick(), intervalMs);
  };
  void tick();

  return {
    stop: () => {
      stopped = true;
      if (timer !== undefined) clearTimeout(timer);
    },
  };
}
