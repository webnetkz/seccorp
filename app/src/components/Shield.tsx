// Animated protection status shield.

export type ShieldState = "protected" | "attention" | "danger" | "idle";

const gradients: Record<ShieldState, [string, string, string]> = {
  protected: ["#34e5c5", "#22b8f0", "#3b6cf6"],
  attention: ["#fde68a", "#fbbf24", "#f59e0b"],
  danger: ["#fda4af", "#fb7185", "#e11d48"],
  idle: ["#94a3b8", "#64748b", "#475569"],
};

export function Shield({ state, size }: { state: ShieldState; size?: number }) {
  const [a, b, c] = gradients[state];
  const id = `shield-${state}`;
  const mark =
    state === "protected" ? (
      <path d="M38 52 L47 61 L64 43" fill="none" stroke="#fff" strokeWidth="7" strokeLinecap="round" strokeLinejoin="round" />
    ) : state === "danger" ? (
      <path d="M41 40 L59 58 M59 40 L41 58" fill="none" stroke="#fff" strokeWidth="7" strokeLinecap="round" />
    ) : state === "attention" ? (
      <>
        <path d="M50 35 L50 54" stroke="#fff" strokeWidth="7" strokeLinecap="round" />
        <circle cx="50" cy="65" r="4.2" fill="#fff" />
      </>
    ) : (
      <circle cx="50" cy="50" r="6" fill="#fff" opacity="0.8" />
    );
  return (
    <div className={`shield-wrap ${state}`} style={size ? { width: size, height: size } : undefined}>
      <span className="shield-ring" />
      <span className="shield-ring r2" />
      <span className="shield-ring r3" />
      <span className="shield-disc" />
      <svg className="shield-svg" viewBox="0 0 100 100" aria-hidden>
        <defs>
          <linearGradient id={id} x1="0.15" y1="0" x2="0.85" y2="1">
            <stop offset="0" stopColor={a} />
            <stop offset="0.55" stopColor={b} />
            <stop offset="1" stopColor={c} />
          </linearGradient>
        </defs>
        <path
          d="M50 6 L83 18 C85 19 86 20.5 86 22.5 L86 45 C86 67 72 84 52.5 91.5 C50.8 92.2 49.2 92.2 47.5 91.5 C28 84 14 67 14 45 L14 22.5 C14 20.5 15 19 17 18 Z"
          fill={`url(#${id})`}
        />
        <path d="M50 14 L78 24 L78 45 C78 63 66.5 77.5 50 84 C33.5 77.5 22 63 22 45 L22 24 Z" fill="#0b1b3a" opacity="0.16" />
        {mark}
      </svg>
    </div>
  );
}
