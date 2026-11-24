import { useEffect, useRef } from "react";

export type HotkeyMap = Record<string, (event: KeyboardEvent) => void>;

function isTyping(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.isContentEditable) return true;
  if (target instanceof HTMLInputElement) return target.type !== "checkbox" && target.type !== "radio";
  return target instanceof HTMLTextAreaElement || target instanceof HTMLSelectElement;
}

function describe(event: KeyboardEvent): string {
  const key = event.key.toLowerCase();
  const parts: string[] = [];
  if (event.ctrlKey || event.metaKey) parts.push("ctrl");
  if (event.altKey) parts.push("alt");
  // Shift only counts as a modifier with other modifiers or named keys; "?" already implies it.
  if (event.shiftKey && (event.ctrlKey || event.metaKey || event.altKey || key.length > 1)) parts.push("shift");
  parts.push(key);
  return parts.join("+");
}

/**
 * Keyboard shortcuts. Keys look like "ctrl+k", "alt+1", "j" or "?". Plain-letter shortcuts
 * are ignored while the user is typing in a field or a dialog is open.
 */
export function useHotkeys(map: HotkeyMap, enabled = true) {
  const latest = useRef(map);
  latest.current = map;

  useEffect(() => {
    if (!enabled) return;
    const onKey = (event: KeyboardEvent) => {
      const combo = describe(event);
      const handler = latest.current[combo];
      if (!handler) return;
      const plain = !event.ctrlKey && !event.metaKey && !event.altKey;
      if (plain && (isTyping(event.target) || document.querySelector(".scrim.on"))) return;
      event.preventDefault();
      handler(event);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [enabled]);
}
