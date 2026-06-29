import { useState } from "react";
import { Icon } from "./Icon";

// Password input with a show/hide reveal so people can check what they typed.
export function PasswordField(props: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  autoFocus?: boolean;
  autoComplete?: string;
}) {
  const [shown, setShown] = useState(false);
  return (
    <div className="pwfield">
      <input
        type={shown ? "text" : "password"}
        value={props.value}
        onChange={(e) => props.onChange(e.currentTarget.value)}
        placeholder={props.placeholder}
        autoFocus={props.autoFocus}
        autoComplete={props.autoComplete ?? "off"}
      />
      <button
        type="button"
        className="reveal"
        onClick={() => setShown((s) => !s)}
        aria-label={shown ? "Hide password" : "Show password"}
      >
        <Icon name={shown ? "eyeOff" : "eye"} size={16} />
        {shown ? "Hide" : "Show"}
      </button>
    </div>
  );
}
