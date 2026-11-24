import type { ReactNode } from "react";
import type { DiffLine } from "../api/types";

type Block = DiffLine | { fold: number };

function wordMarks(oldText: string, newText: string): [ReactNode, ReactNode] {
  let start = 0;
  while (start < oldText.length && start < newText.length && oldText[start] === newText[start]) start++;
  let end = 0;
  while (
    end < oldText.length - start &&
    end < newText.length - start &&
    oldText[oldText.length - 1 - end] === newText[newText.length - 1 - end]
  )
    end++;
  const mark = (text: string) => (
    <>
      {text.slice(0, start)}
      <mark>{text.slice(start, text.length - end)}</mark>
      {text.slice(text.length - end)}
    </>
  );
  return [mark(oldText), mark(newText)];
}

function foldUnchanged(lines: DiffLine[], onlyChanges: boolean): Block[] {
  if (!onlyChanges) return lines;
  const blocks: Block[] = [];
  let run = 0;
  for (const line of lines) {
    if (line.kind === "same") {
      run++;
      continue;
    }
    if (run) blocks.push({ fold: run });
    run = 0;
    blocks.push(line);
  }
  if (run) blocks.push({ fold: run });
  return blocks;
}

const foldRow = (count: number, key: string) => (
  <div className="ln fold" key={key}>{count} unchanged line{count > 1 ? "s" : ""}</div>
);
const emptyRow = (key: string) => <div className="ln empty" key={key}><i /><span /></div>;

export function DiffView({ lines, mode, onlyChanges, approvedLabel }: {
  lines: DiffLine[];
  mode: "split" | "unified";
  onlyChanges: boolean;
  approvedLabel: string;
}) {
  const blocks = foldUnchanged(lines, onlyChanges);

  if (mode === "split") {
    const left: ReactNode[] = [];
    const right: ReactNode[] = [];
    blocks.forEach((block, i) => {
      if ("fold" in block) {
        left.push(foldRow(block.fold, `l${i}`));
        right.push(foldRow(block.fold, `r${i}`));
        return;
      }
      const [oldMarked, newMarked] =
        block.kind === "mod" ? wordMarks(block.old_text ?? "", block.new_text ?? "") : [block.old_text, block.new_text];
      left.push(block.old_number === null ? emptyRow(`l${i}`) : (
        <div className={`ln ${block.kind === "del" || block.kind === "mod" ? "del" : ""}`} key={`l${i}`}>
          <i>{block.old_number}</i><span>{oldMarked}</span>
        </div>
      ));
      right.push(block.new_number === null ? emptyRow(`r${i}`) : (
        <div className={`ln ${block.kind === "add" || block.kind === "mod" ? "add" : ""}`} key={`r${i}`}>
          <i>{block.new_number}</i><span>{newMarked}</span>
        </div>
      ));
    });
    return (
      <div className="diff">
        <div className="hd"><div>{approvedLabel}</div><div>Now on disk · saved as evidence</div></div>
        <div className="body"><div className="col">{left}</div><div className="col">{right}</div></div>
      </div>
    );
  }

  const rows: ReactNode[] = [];
  blocks.forEach((block, i) => {
    if ("fold" in block) {
      rows.push(foldRow(block.fold, `u${i}`));
      return;
    }
    if (block.kind === "same") {
      rows.push(<div className="ln" key={`u${i}`}><i>{block.old_number}</i><i>{block.new_number}</i><u> </u><span>{block.old_text}</span></div>);
      return;
    }
    const [oldMarked, newMarked] =
      block.kind === "mod" ? wordMarks(block.old_text ?? "", block.new_text ?? "") : [block.old_text, block.new_text];
    if (block.old_number !== null)
      rows.push(<div className="ln del" key={`u${i}d`}><i>{block.old_number}</i><i /><u>−</u><span>{oldMarked}</span></div>);
    if (block.new_number !== null)
      rows.push(<div className="ln add" key={`u${i}a`}><i /><i>{block.new_number}</i><u>+</u><span>{newMarked}</span></div>);
  });
  return (
    <div className="diff uni">
      <div className="hd"><div>{approvedLabel} → now on disk</div></div>
      <div className="body"><div className="col">{rows}</div></div>
    </div>
  );
}
