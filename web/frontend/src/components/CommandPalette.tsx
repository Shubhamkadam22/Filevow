import { useEffect, useMemo, useRef, useState } from "react";
import { Icon, SeverityIcon } from "./Icon";

export interface Command {
  group: string;
  label: string;
  hint?: string;
  icon?: string;
  severity?: string;
  mono?: boolean;
  run: () => void;
}

interface Props {
  open: boolean;
  commands: Command[];
  onClose: () => void;
}

export function CommandPalette({ open, commands, onClose }: Props) {
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const list = useRef<HTMLDivElement>(null);

  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    const matching = q ? commands.filter((c) => `${c.label} ${c.hint ?? ""} ${c.group}`.toLowerCase().includes(q)) : commands;
    return matching.slice(0, 40);
  }, [commands, query]);

  useEffect(() => {
    if (open) {
      setQuery("");
      setActive(0);
      input.current?.focus();
    }
  }, [open]);

  useEffect(() => setActive(0), [query]);
  useEffect(() => {
    list.current?.querySelector(".opt.act")?.scrollIntoView({ block: "nearest" });
  }, [active]);

  if (!open) return null;

  const run = (index: number) => {
    const command = results[index];
    if (!command) return;
    onClose();
    command.run();
  };

  let lastGroup = "";
  return (
    <div className="scrim top on" role="dialog" aria-modal="true" aria-label="Command palette" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="palette">
        <div className="pin">
          <Icon name="search" />
          <input
            ref={input}
            value={query}
            placeholder="Type a file, page, setting or command"
            aria-label="Search"
            autoComplete="off"
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") { e.preventDefault(); setActive((a) => (a + 1) % Math.max(results.length, 1)); }
              else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => (a - 1 + results.length) % Math.max(results.length, 1)); }
              else if (e.key === "Enter") { e.preventDefault(); run(active); }
              else if (e.key === "Escape") onClose();
            }}
          />
          <kbd>Esc</kbd>
        </div>
        <div className="res" ref={list} role="listbox">
          {results.length === 0 && <div className="empty" style={{ padding: 24 }}>No results for “{query}”</div>}
          {results.map((command, index) => {
            const header = command.group !== lastGroup ? <div className="grp">{command.group}</div> : null;
            lastGroup = command.group;
            return (
              <div key={`${command.group}-${command.label}-${index}`}>
                {header}
                <div className={`opt ${index === active ? "act" : ""}`} role="option" aria-selected={index === active}
                  onMouseEnter={() => setActive(index)} onClick={() => run(index)}>
                  {command.severity ? <SeverityIcon severity={command.severity} /> : <Icon name={command.icon ?? "chev"} />}
                  <span className={command.mono ? "mono" : ""} style={{ fontSize: command.mono ? 13 : 14 }}>{command.label}</span>
                  {command.hint && <span className="s">{command.hint}</span>}
                </div>
              </div>
            );
          })}
        </div>
        <div className="foot">
          <span><kbd>↑</kbd><kbd>↓</kbd> move</span>
          <span><kbd>Enter</kbd> open</span>
          <span><kbd>Esc</kbd> close</span>
        </div>
      </div>
    </div>
  );
}
