import { describe, expect, it } from 'vitest';
import {
  countdownState,
  donutColor,
  donutOffset,
  DONUT_CIRCUMFERENCE,
  formatRemaining,
} from '../src/countdown';

const CREATED = '2026-11-13T00:00:00Z';
const EXPIRES = '2026-11-13T00:15:00Z';

describe('formatRemaining', () => {
  it('m:ss と h:mm:ss を出す', () => {
    expect(formatRemaining(0)).toBe('0:00');
    expect(formatRemaining(65_000)).toBe('1:05');
    expect(formatRemaining(59_100)).toBe('1:00');
    expect(formatRemaining(3_661_000)).toBe('1:01:01');
  });
});

describe('countdownState', () => {
  it('残り時間と割合を返す', () => {
    const now = Date.parse(CREATED) + 5 * 60_000;
    const s = countdownState(CREATED, EXPIRES, now);
    expect(s.label).toBe('残り 10:00');
    expect(s.expired).toBe(false);
    expect(s.fraction).toBeCloseTo(2 / 3, 5);
    expect(s.totalMs).toBe(15 * 60_000);
  });

  it('緑から赤へ変わる', () => {
    expect(donutColor(1)).toBe('hsl(140 70% 38%)');
    expect(donutColor(0.5)).toBe('hsl(70 70% 38%)');
    expect(donutColor(0)).toBe('hsl(0 70% 38%)');
  });

  it('期限を過ぎたら expired で 0 に丸める', () => {
    const s = countdownState(CREATED, EXPIRES, Date.parse(EXPIRES) + 1000);
    expect(s.expired).toBe(true);
    expect(s.remainingMs).toBe(0);
    expect(s.label).toBe('期限切れ');
    expect(s.fraction).toBe(0);
  });

  it('端末時計が戻っていても満タン以上にはしない', () => {
    const s = countdownState(CREATED, EXPIRES, Date.parse(CREATED) - 60_000);
    expect(s.fraction).toBe(1);
    expect(s.label).toBe('残り 15:00');
  });

  it('壊れた時刻は期限切れとして扱う', () => {
    const s = countdownState('', 'not-a-date', Date.now());
    expect(s.expired).toBe(true);
    expect(s.label).toBe('期限切れ');
  });
});

describe('donutOffset', () => {
  it('満タンで 0、空で円周ぶんになる', () => {
    expect(donutOffset(1)).toBe(0);
    expect(donutOffset(0)).toBeCloseTo(DONUT_CIRCUMFERENCE, 5);
    expect(donutOffset(0.5)).toBeCloseTo(DONUT_CIRCUMFERENCE / 2, 5);
  });
});
