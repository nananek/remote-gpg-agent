export interface CountdownState {
  remainingMs: number;
  totalMs: number;
  /** 残り時間の割合（1 = 満タン、0 = 期限切れ）。 */
  fraction: number;
  expired: boolean;
  /** "残り 14:59" または "期限切れ"。 */
  label: string;
  /** ドーナツの色。緑から赤へ連続的に変わる。 */
  color: string;
}

/** SVG のドーナツ。r=18 の円周。 */
export const DONUT_RADIUS = 18;
export const DONUT_CIRCUMFERENCE = 2 * Math.PI * DONUT_RADIUS;

const FALLBACK_TOTAL_MS = 15 * 60 * 1000;

const clamp = (n: number, lo: number, hi: number): number => Math.min(hi, Math.max(lo, n));

/** 残り時間を m:ss（1 時間以上は h:mm:ss）で表す。 */
export function formatRemaining(ms: number): string {
  const total = Math.ceil(Math.max(0, ms) / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const ss = String(s).padStart(2, '0');
  if (h > 0) return `${h}:${String(m).padStart(2, '0')}:${ss}`;
  return `${m}:${ss}`;
}

/**
 * 残り時間の割合から色を作る。満タンは緑 (hue 140)、
 * 減るにつれて黄・橙を経て赤 (hue 0) になる。
 */
export function donutColor(fraction: number): string {
  const f = clamp(fraction, 0, 1);
  return `hsl(${Math.round(140 * f)} 70% 38%)`;
}

/** ドーナツの残り弧の長さ（stroke-dashoffset に渡す）。 */
export function donutOffset(fraction: number): number {
  return DONUT_CIRCUMFERENCE * (1 - clamp(fraction, 0, 1));
}

/**
 * createdAt / expiresAt から残り時間を計算する。nowMs はサーバ時刻に
 * 補正済みの「いま」を渡す（端末の時計ずれでカウントダウンが狂わないように）。
 */
export function countdownState(createdAt: string, expiresAt: string, nowMs: number): CountdownState {
  const created = Date.parse(createdAt);
  const expires = Date.parse(expiresAt);
  const totalMs =
    Number.isFinite(created) && Number.isFinite(expires) && expires > created
      ? expires - created
      : FALLBACK_TOTAL_MS;
  const remainingMs = Number.isFinite(expires) ? clamp(expires - nowMs, 0, totalMs) : 0;
  const fraction = totalMs > 0 ? remainingMs / totalMs : 0;
  return {
    remainingMs,
    totalMs,
    fraction,
    expired: remainingMs <= 0,
    label: remainingMs <= 0 ? '期限切れ' : `残り ${formatRemaining(remainingMs)}`,
    color: donutColor(fraction),
  };
}
