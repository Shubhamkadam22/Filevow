import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { PasswordInput } from "../components/PasswordInput";

function Field() {
  const [value, setValue] = useState("");
  return <PasswordInput aria-label="Passphrase" value={value} onChange={(e) => setValue(e.target.value)} />;
}

describe("PasswordInput", () => {
  it("hides what's typed until the eye is clicked, and keeps the text", async () => {
    const user = userEvent.setup();
    render(<Field />);
    const box = screen.getByLabelText("Passphrase");
    await user.type(box, "my cat sleeps on the router");
    expect(box).toHaveAttribute("type", "password");

    await user.click(screen.getByRole("button", { name: "Show password" }));
    expect(box).toHaveAttribute("type", "text");
    expect(box).toHaveValue("my cat sleeps on the router");

    await user.click(screen.getByRole("button", { name: "Hide password" }));
    expect(box).toHaveAttribute("type", "password");
  });
});
