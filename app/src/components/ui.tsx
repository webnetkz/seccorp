import { X } from "lucide-react";
import { useEffect, type ButtonHTMLAttributes, type ReactNode } from "react";

type Variant = "primary" | "secondary" | "ghost" | "danger";

export function Button({
  variant = "secondary",
  size,
  block,
  icon,
  loading,
  children,
  className = "",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: Variant;
  size?: "sm" | "lg";
  block?: boolean;
  icon?: ReactNode;
  loading?: boolean;
}) {
  const cls = ["btn", `btn-${variant}`, size ? `btn-${size}` : "", block ? "btn-block" : "", className].filter(Boolean).join(" ");
  return (
    <button className={cls} disabled={loading || rest.disabled} {...rest}>
      {loading ? <span className="spinner" style={{ width: 16, height: 16, borderTopColor: "currentColor" }} /> : icon}
      {children}
    </button>
  );
}

export function IconButton({ label, children, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { label: string }) {
  return (
    <button className="btn btn-ghost btn-icon" aria-label={label} title={label} {...rest}>
      {children}
    </button>
  );
}

export function Toggle({ on, onChange, disabled, label }: { on: boolean; onChange: (v: boolean) => void; disabled?: boolean; label?: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label={label}
      className={`toggle ${on ? "on" : ""}`}
      disabled={disabled}
      onClick={() => onChange(!on)}
    />
  );
}

export function Segmented<T extends string | number>({
  value,
  options,
  onChange,
}: {
  value: T;
  options: { value: T; label: string }[];
  onChange: (v: T) => void;
}) {
  return (
    <div className="segmented" role="radiogroup">
      {options.map((o) => (
        <button key={String(o.value)} role="radio" aria-checked={o.value === value} className={o.value === value ? "active" : ""} onClick={() => onChange(o.value)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Badge({ tone, dot, children }: { tone?: "ok" | "warn" | "danger" | "accent"; dot?: boolean; children: ReactNode }) {
  return <span className={`badge ${tone ?? ""} ${dot ? "badge-dot" : ""}`}>{children}</span>;
}

export function Card({ children, className = "", flat, style, onClick }: { children: ReactNode; className?: string; flat?: boolean; style?: React.CSSProperties; onClick?: () => void }) {
  return (
    <div className={`card ${flat ? "card-flat" : ""} ${className}`} style={style} onClick={onClick}>
      {children}
    </div>
  );
}

export function CardHeader({ icon, title, sub, tone, right }: { icon?: ReactNode; title: ReactNode; sub?: ReactNode; tone?: "ok" | "warn" | "danger" | "muted"; right?: ReactNode }) {
  return (
    <div className={`card-header ${sub ? "" : "center"}`}>
      <div className="row" style={{ gap: 12, alignItems: sub ? "flex-start" : "center", minWidth: 0 }}>
        {icon && <span className={`icon-tile ${tone ?? ""}`}>{icon}</span>}
        <div style={{ minWidth: 0 }}>
          <div className="card-title">{title}</div>
          {sub && <div className="card-sub">{sub}</div>}
        </div>
      </div>
      {right}
    </div>
  );
}

export function IconTile({ tone, size, children }: { tone?: "ok" | "warn" | "danger" | "muted"; size?: "sm" | "lg"; children: ReactNode }) {
  return <span className={`icon-tile ${tone ?? ""} ${size ?? ""}`}>{children}</span>;
}

export function Empty({ icon, title, desc, action, tone }: { icon: ReactNode; title: string; desc?: string; action?: ReactNode; tone?: "ok" | "warn" | "danger" | "muted" }) {
  return (
    <div className="empty">
      <span className={`icon-tile ${tone ?? ""}`}>{icon}</span>
      <div className="empty-title">{title}</div>
      {desc && <div className="empty-desc">{desc}</div>}
      {action && <div style={{ marginTop: 10 }}>{action}</div>}
    </div>
  );
}

export function Setting({
  title,
  desc,
  children,
  stackMobile,
  stack,
}: {
  title: ReactNode;
  desc?: ReactNode;
  children?: ReactNode;
  /** Put the control under the text on phones. */
  stackMobile?: boolean;
  /** Always put the control under the text (wide controls). */
  stack?: boolean;
}) {
  return (
    <div className={`setting ${stack ? "stacked" : stackMobile ? "stack-mobile" : ""}`}>
      <div className="setting-text">
        <div className="setting-title">{title}</div>
        {desc && <div className="setting-desc">{desc}</div>}
      </div>
      {children}
    </div>
  );
}

export function Progress({ value, indeterminate }: { value: number; indeterminate?: boolean }) {
  return (
    <div className={`progress ${indeterminate ? "indeterminate" : ""}`}>
      <div className="progress-bar" style={{ width: `${Math.max(0, Math.min(100, value))}%` }} />
    </div>
  );
}

export function Modal({ open, onClose, children, wide }: { open: boolean; onClose: () => void; children: ReactNode; wide?: boolean }) {
  useEffect(() => {
    if (!open) return;
    const h = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`modal ${wide ? "modal-wide" : ""}`} role="dialog" aria-modal="true">
        {children}
      </div>
    </div>
  );
}

export function ModalHeader({ title, onClose }: { title: string; onClose: () => void }) {
  return (
    <div className="row-between" style={{ marginBottom: 6 }}>
      <div className="modal-title">{title}</div>
      <IconButton label="close" onClick={onClose}>
        <X size={18} />
      </IconButton>
    </div>
  );
}

export function PageHeader({ title, subtitle, right }: { title: string; subtitle?: string; right?: ReactNode }) {
  return (
    <div className="page-header">
      <div style={{ minWidth: 0 }}>
        <h1 className="page-title">{title}</h1>
        {subtitle && <div className="page-subtitle">{subtitle}</div>}
      </div>
      {right && <div className="page-actions">{right}</div>}
    </div>
  );
}

export function Spinner({ size = 18 }: { size?: number }) {
  return <span className="spinner" style={{ width: size, height: size }} />;
}
