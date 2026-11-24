import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DiffView } from "../components/DiffView";
import { countdown, shortHash, timeAgo } from "../lib/format";
import type { DiffLine } from "../api/types";

describe("format helpers", () => {
  it("formats relative times", () => {
    const now = Date.parse("2026-11-24T10:00:00Z");
    expect(timeAgo("2026-11-24T09:59:30Z", now)).toBe("30 s ago");
    expect(timeAgo("2026-11-24T09:45:00Z", now)).toBe("15 min ago");
    expect(timeAgo(null, now)).toBe("never");
  });

  it("shortens hashes and counts down", () => {
    expect(shortHash("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")).toBe("9f86d081…0a08");
    expect(countdown("2026-11-24T10:12:05Z", Date.parse("2026-11-24T10:00:00Z"))).toBe("12:05");
  });
});

describe("DiffView", () => {
  const lines: DiffLine[] = [
    { kind: "same", old_number: 1, new_number: 1, old_text: "<head>", new_text: "<head>" },
    { kind: "mod", old_number: 2, new_number: 2, old_text: "<h1>Hello</h1>", new_text: "<h1>Hello, visitor</h1>" },
    { kind: "add", old_number: null, new_number: 3, old_text: null, new_text: "<script></script>" },
  ];

  it("highlights only the changed words", () => {
    const { container } = render(<DiffView lines={lines} mode="split" onlyChanges={false} approvedLabel="Approved" />);
    const marks = [...container.querySelectorAll("mark")].map((m) => m.textContent);
    expect(marks).toEqual(["", ", visitor"]);
  });

  it("folds unchanged lines in unified mode", () => {
    render(<DiffView lines={lines} mode="unified" onlyChanges approvedLabel="Approved" />);
    expect(screen.getByText("1 unchanged line")).toBeInTheDocument();
    expect(screen.getByText("<script></script>")).toBeInTheDocument();
  });
});

describe("keyboard hotkeys", () => {
  it("ignores plain letters while typing", async () => {
    const { useHotkeys } = await import("../hooks/useHotkeys");
    const hits: string[] = [];
    function Probe() {
      useHotkeys({ j: () => hits.push("j"), "ctrl+k": () => hits.push("palette") });
      return <input aria-label="field" />;
    }
    render(<Probe />);
    await userEvent.keyboard("j");
    await userEvent.click(screen.getByLabelText("field"));
    await userEvent.keyboard("j");
    await userEvent.keyboard("{Control>}k{/Control}");
    expect(hits).toEqual(["j", "palette"]);
  });
});
