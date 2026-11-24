import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from "react";
import { Icon } from "./Icon";

interface ToastAction {
  label: string;
  run: () => void;
}

interface ToastMessage {
  id: number;
  title: string;
  text?: string;
  action?: ToastAction;
}

type ShowToast = (title: string, text?: string, action?: ToastAction) => void;
const ToastContext = createContext<ShowToast>(() => undefined);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toast, setToast] = useState<ToastMessage | null>(null);
  const timer = useRef<number>();

  const show = useCallback<ShowToast>((title, text, action) => {
    window.clearTimeout(timer.current);
    setToast({ id: Date.now(), title, text, action });
    timer.current = window.setTimeout(() => setToast(null), action ? 7000 : 4200);
  }, []);

  return (
    <ToastContext.Provider value={show}>
      {children}
      <div className={`toast ${toast ? "on" : ""}`} role="status" aria-live="polite" key={toast?.id}>
        {toast && (
          <>
            <img src="/favicon.svg" alt="" />
            <div className="tt">
              <div className="t1">FileVow</div>
              <b>{toast.title}</b>
              {toast.text && <div className="muted" style={{ fontSize: 13 }}>{toast.text}</div>}
            </div>
            {toast.action && (
              <button
                className="btn ta"
                onClick={() => {
                  setToast(null);
                  toast.action?.run();
                }}
              >
                {toast.action.label}
              </button>
            )}
            <button className="x" aria-label="Dismiss" onClick={() => setToast(null)}>
              <Icon name="x" />
            </button>
          </>
        )}
      </div>
    </ToastContext.Provider>
  );
}

export const useToast = () => useContext(ToastContext);
