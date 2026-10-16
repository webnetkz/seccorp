import type { ReactNode } from "react";

/** Circular progress (0..100); `sweep` shows an indeterminate radar sweep. */
export function ProgressRing({ value, sweep, children }: { value: number; sweep?: boolean; children?: ReactNode }) {
  const r = 52;
  const c = 2 * Math.PI * r;
  const v = Math.max(0, Math.min(100, value));
  return (
    <div className="ring-wrap">
      {sweep && <div className="ring-sweep" />}
      <svg viewBox="0 0 120 120" aria-hidden>
        <defs>
          <linearGradient id="ringGradient" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="#2dd4bf" />
            <stop offset="0.5" stopColor="#22b8f0" />
            <stop offset="1" stopColor="#3b6cf6" />
          </linearGradient>
        </defs>
        <circle className="ring-track" cx="60" cy="60" r={r} strokeWidth="8" />
        <circle className="ring-value" cx="60" cy="60" r={r} strokeWidth="8" strokeDasharray={c} strokeDashoffset={c * (1 - v / 100)} />
      </svg>
      <div className="ring-center">{children}</div>
    </div>
  );
}

/** Small score ring used on the device page. */
export function ScoreRing({ value, color }: { value: number; color: string }) {
  const r = 40;
  const c = 2 * Math.PI * r;
  return (
    <div className="score-ring">
      <svg viewBox="0 0 100 100" aria-hidden>
        <circle cx="50" cy="50" r={r} fill="none" stroke="var(--track)" strokeWidth="9" />
        <circle cx="50" cy="50" r={r} fill="none" stroke={color} strokeWidth="9" strokeLinecap="round" strokeDasharray={c} strokeDashoffset={c * (1 - value / 100)} style={{ transition: "stroke-dashoffset .5s" }} />
      </svg>
      <div className="value num">{Math.round(value)}</div>
    </div>
  );
}
