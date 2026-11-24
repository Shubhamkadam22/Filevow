import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { Dialog } from "../components/Dialog";

// Regression test: typing in a later field must not send focus back to the first field.
function TwoFieldDialog() {
  const [reason, setReason] = useState("");
  return (
    <Dialog open title="Confirm" onClose={() => undefined /* new function every render, like real callers */}>
      <input aria-label="Password" />
      <input aria-label="Reason" value={reason} onChange={(e) => setReason(e.target.value)} />
    </Dialog>
  );
}

it("keeps focus in the field the user is typing in", async () => {
  render(<TwoFieldDialog />);
  expect(screen.getByLabelText("Password")).toHaveFocus();
  await userEvent.click(screen.getByLabelText("Reason"));
  await userEvent.keyboard("planned release");
  expect(screen.getByLabelText("Reason")).toHaveFocus();
  expect(screen.getByLabelText("Reason")).toHaveValue("planned release");
});
