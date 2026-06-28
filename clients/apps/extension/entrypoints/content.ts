import type { FillMessage } from "../utils/protocol";

// Content script: fills credentials into the page only when the popup explicitly
// asks (user-initiated). It never receives or holds credentials otherwise.
export default defineContentScript({
  matches: ["http://*/*", "https://*/*"],
  main() {
    browser.runtime.onMessage.addListener((message: unknown): Promise<unknown> | undefined => {
      const msg = message as FillMessage;
      if (msg?.type === "fill") {
        const ok = fillLoginForm(msg.username, msg.password);
        return Promise.resolve({ ok });
      }
      return undefined;
    });
  },
});

function fillLoginForm(username: string, password: string): boolean {
  const pw = document.querySelector<HTMLInputElement>('input[type="password"]');
  if (!pw) return false;
  const scope: ParentNode = pw.closest("form") ?? document;
  const user = scope.querySelector<HTMLInputElement>(
    'input[type="email"], input[autocomplete="username"], input[name*="user" i], input[id*="user" i], input[name*="email" i], input[type="text"]',
  );
  if (user && username) setValue(user, username);
  setValue(pw, password);
  return true;
}

// Set a value the way React/Vue-style listeners expect (native setter + events).
function setValue(el: HTMLInputElement, value: string): void {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  setter ? setter.call(el, value) : (el.value = value);
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
}
