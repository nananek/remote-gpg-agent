/**
 * 署名要求が来たことを知らせる短いチャイム。
 * 音声ファイルは持たず Web Audio で合成する（dist にアセットを増やさない）。
 *
 * iOS はユーザー操作の中でしか AudioContext を開始できないので、
 * 最初のタップ / キー入力で primeSound() を呼んでおく。
 */

const STORAGE_KEY = 'rga.sound';

let ctx: AudioContext | null = null;
let loaded = false;
let enabled = true;

function loadPreference(): void {
  if (loaded) return;
  loaded = true;
  try {
    enabled = localStorage.getItem(STORAGE_KEY) !== 'off';
  } catch {
    /* ストレージが使えなくても既定で鳴らす */
  }
}

export function soundEnabled(): boolean {
  loadPreference();
  return enabled;
}

export function setSoundEnabled(on: boolean): void {
  loadPreference();
  enabled = on;
  try {
    localStorage.setItem(STORAGE_KEY, on ? 'on' : 'off');
  } catch {
    /* 保存できなくても、この画面では反映する */
  }
}

function audioContext(): AudioContext | null {
  if (ctx) return ctx;
  const Ctor =
    window.AudioContext ??
    (window as Window & { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
  if (!Ctor) return null;
  try {
    ctx = new Ctor();
    return ctx;
  } catch {
    return null;
  }
}

/** ユーザー操作のイベントハンドラから呼ぶ。何度呼んでもよい。 */
export function primeSound(): void {
  const c = audioContext();
  if (c?.state === 'suspended') void c.resume().catch(() => {});
}

function tone(c: AudioContext, at: number, frequency: number, peak: number): void {
  const osc = c.createOscillator();
  const env = c.createGain();
  osc.type = 'sine';
  osc.frequency.setValueAtTime(frequency, at);
  // 短いアタックと指数減衰。2 音を重ねても割れない程度の音量にする。
  env.gain.setValueAtTime(0.0001, at);
  env.gain.exponentialRampToValueAtTime(peak, at + 0.012);
  env.gain.exponentialRampToValueAtTime(0.0001, at + 0.38);
  osc.connect(env);
  env.connect(c.destination);
  osc.start(at);
  osc.stop(at + 0.4);
}

/** 「ピコン」と 2 音。連続で来てもうるさくならないよう短く小さく鳴らす。 */
export function playRequestChime(): void {
  if (!soundEnabled()) return;
  const c = audioContext();
  if (!c) return;

  const play = (): void => {
    const at = c.currentTime + 0.02;
    tone(c, at, 987.77, 0.09); // B5
    tone(c, at + 0.11, 1318.51, 0.07); // E6
  };

  if (c.state === 'suspended') {
    // 解錠時のタップで primeSound() 済みなら鳴る。ダメなら黙って諦める。
    void c.resume().then(play).catch(() => {});
    return;
  }
  play();
}
