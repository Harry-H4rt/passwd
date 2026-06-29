import { useState, type ReactNode } from "react";
import { Icon } from "./Icon";

type State = "idle" | "loading" | "success";

// A button that gives tactile feedback for async actions: it shows a spinner
// while working, then a green check + success label briefly, so the user can see
// the action actually happened. `onClick` returns false to signal failure (the
// caller surfaces the error); anything else counts as success.
export function AsyncButton(props: {
  onClick: () => Promise<boolean | void>;
  children: ReactNode;
  variant?: "primary" | "ghost";
  danger?: boolean;
  loadingLabel?: string;
  successLabel?: string;
  onSuccess?: () => void;
}) {
  const [state, setState] = useState<State>("idle");
  const variant = props.variant ?? "primary";
  const cls = [variant, props.danger ? "danger" : "", state === "success" ? "success" : ""]
    .filter(Boolean)
    .join(" ");

  async function handle() {
    if (state !== "idle") return;
    setState("loading");
    try {
      const result = await props.onClick();
      if (result === false) {
        setState("idle");
        return;
      }
      setState("success");
      setTimeout(() => {
        setState("idle");
        props.onSuccess?.();
      }, 1000);
    } catch {
      setState("idle");
    }
  }

  return (
    <button type="button" className={cls} disabled={state === "loading"} onClick={handle}>
      {state === "loading" && <span className="spinner" />}
      {state === "success" && <Icon name="check" size={16} />}
      <span>
        {state === "loading"
          ? props.loadingLabel ?? "Working"
          : state === "success"
            ? props.successLabel ?? "Done"
            : props.children}
      </span>
    </button>
  );
}
