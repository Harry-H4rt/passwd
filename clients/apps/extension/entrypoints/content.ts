import type { BgRequest, FillMessage } from "../utils/protocol";

// Content script: fills credentials into the page only when the popup explicitly
// asks (user-initiated), and reports a login on submit so the popup can offer to
// save it. It never stores credentials itself and shows no UI on the page.
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

    // Save-on-submit: when a form with a password is submitted, hand the entered
    // credentials to the background worker, which holds them briefly so the popup
    // can offer to save. Capture phase so we still see it if the page calls
    // preventDefault or navigates immediately.
    window.addEventListener("submit", (e) => captureFrom(e.target), true);
  },
});

function captureFrom(target: EventTarget | null): void {
  const scope = target instanceof HTMLElement ? target : document;
  const pw = scope.querySelector<HTMLInputElement>('input[type="password"]');
  if (!pw?.value) return;
  const user = scope.querySelector<HTMLInputElement>(
    'input[type="email"], input[autocomplete="username"], input[name*="user" i], input[id*="user" i], input[name*="email" i], input[type="text"], input[type="tel"]',
  );
  const capture: BgRequest = {
    type: "captureLogin",
    url: location.href,
    username: user?.value ?? "",
    password: pw.value,
  };
  browser.runtime.sendMessage(capture).catch(() => {
    // background may be mid-wake or the page is closing; the capture is best-effort
  });
}

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
