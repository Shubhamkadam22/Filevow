import { useEffect, useRef, type ReactNode } from "react";

interface DialogProps {
  open: boolean;
  title: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  width?: number;
  labelledBy?: string;
}

/** Modal dialog in the Windows ContentDialog style. Escape and clicking outside close it. */
export function Dialog({ open, title, onClose, children, footer, width = 480, labelledBy = "dialog-title" }: DialogProps) {
  const panel = useRef<HTMLDivElement>(null);
  // Keep the latest onClose without re-running the open effect: callers usually pass a new
  // function on every render, and re-running would steal focus while the user types.
  const closeRef = useRef(onClose);
  closeRef.current = onClose;

  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    panel.current?.querySelector<HTMLElement>("input, textarea, select, button")?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") closeRef.current();
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      previous?.focus();
    };
  }, [open]);

  if (!open) return null;
  return (
    <div
      className="scrim on"
      role="dialog"
      aria-modal="true"
      aria-labelledby={labelledBy}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className="dialog" style={{ width }} ref={panel}>
        <div className="db">
          <h3 id={labelledBy}>{title}</h3>
          {children}
        </div>
        {footer && <div className="df">{footer}</div>}
      </div>
    </div>
  );
}
