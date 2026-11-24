import { useState, type InputHTMLAttributes } from "react";
import { Icon } from "./Icon";

type Props = Omit<InputHTMLAttributes<HTMLInputElement>, "type">;

/** A password / passphrase box with an eye button to show or hide what's typed. */
export function PasswordInput(props: Props) {
  const [visible, setVisible] = useState(false);
  const label = visible ? "Hide password" : "Show password";
  return (
    <div className="pw-input">
      <input {...props} type={visible ? "text" : "password"} spellCheck={false} />
      <button
        type="button"
        className="pw-eye"
        aria-label={label}
        aria-pressed={visible}
        title={label}
        // Keep the cursor in the box when the eye is clicked.
        onMouseDown={(event) => event.preventDefault()}
        onClick={() => setVisible((shown) => !shown)}
      >
        <Icon name={visible ? "eye-off" : "eye"} />
      </button>
    </div>
  );
}
