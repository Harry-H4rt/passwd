// Inline SVG icons (currentColor) so the vault ships no emoji.
const paths: Record<string, string> = {
  lock: "M4 10h16v11H4zM8 10V7a4 4 0 0 1 8 0v3",
  eye: "M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6",
  eyeOff: "M3 3l18 18 M10.6 10.6a2 2 0 0 0 2.8 2.8 M9.6 5.1A9 9 0 0 1 12 5c6 0 10 7 10 7a13 13 0 0 1-2.3 2.9 M6.2 6.2A13 13 0 0 0 2 12s4 7 10 7a9 9 0 0 0 3.6-.8",
  check: "M20 6L9 17l-5-5",
  search: "M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16z M21 21l-4.3-4.3",
};

export function Icon({ name, size = 18 }: { name: keyof typeof paths | string; size?: number }) {
  const d = paths[name] ?? "";
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {d.split(" M").map((seg, i) => (
        <path key={i} d={i === 0 ? seg : "M" + seg} />
      ))}
    </svg>
  );
}
