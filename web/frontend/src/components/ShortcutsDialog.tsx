import { Dialog } from "./Dialog";

const GROUPS: [string, [string, string[]][]][] = [
  ["Anywhere", [
    ["Search and commands", ["Ctrl", "K"]],
    ["Go to a page", ["Alt", "1–7"]],
    ["Back", ["Alt", "←"]],
    ["Verify all files now", ["Ctrl", "Shift", "V"]],
    ["Show this list", ["?"]],
  ]],
  ["Review changes", [
    ["Next / previous change", ["J", "K"]],
    ["Select for bulk action", ["X"]],
    ["Filter the list", ["/"]],
    ["Accept change", ["A"]],
    ["Restore approved version", ["R"]],
    ["Mark as false positive", ["F"]],
    ["Escalate", ["E"]],
    ["Copy observed hash", ["C"]],
  ]],
];

export function ShortcutsDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <Dialog open={open} onClose={onClose} title="Keyboard shortcuts" width={560}
      footer={<button className="btn" onClick={onClose} style={{ gridColumn: "1 / -1" }}>Close</button>}>
      <div className="keys">
        {GROUPS.map(([group, rows]) => [
          <h4 key={group}>{group}</h4>,
          ...rows.flatMap(([label, combo]) => [
            <span key={`${label}-l`}>{label}</span>,
            <span key={`${label}-k`}>{combo.map((k) => <kbd key={k} style={{ marginLeft: 4 }}>{k}</kbd>)}</span>,
          ]),
        ])}
      </div>
    </Dialog>
  );
}
