/**
 * A quiet mono label with a hairline rule running off to the right.
 *
 * Shared by the landing and coverage pages so the two long reference pages
 * mark their sections the same way. Deliberately muted rather than accent
 * coloured: on a page with six sections, six blue eyebrows spend the accent
 * on furniture instead of on the things a reader can act on.
 */
export function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="sec-label">
      <span>{children}</span>
      <i aria-hidden="true" />
    </div>
  );
}
