import { useState } from "react";
import { Icon } from "./Icon";
import { useToast } from "./Toast";

export async function copyText(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const area = document.createElement("textarea");
    area.value = text;
    document.body.appendChild(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  }
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const toast = useToast();
  return (
    <button
      className="copy"
      title={label}
      aria-label={label}
      style={copied ? { color: "var(--fv-verified)" } : undefined}
      onClick={async (event) => {
        event.stopPropagation();
        await copyText(text);
        setCopied(true);
        toast("Copied", text.length > 60 ? `${text.slice(0, 60)}…` : text);
        window.setTimeout(() => setCopied(false), 1200);
      }}
    >
      <Icon name={copied ? "check" : "copy"} />
    </button>
  );
}
