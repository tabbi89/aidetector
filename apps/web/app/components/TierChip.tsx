export type Tier = "verified" | "heuristic" | "planned" | "premium";

/**
 * The glyph carries the same ladder the colour does — a check for proof, a
 * half-filled disc for a partial signal, a dashed ring for something not built
 * yet, a diamond for the paid tier. Colour alone would leave the distinction
 * invisible to a colour-blind reader and in a greyscale print of the PDF
 * report, and teal/amber is exactly the pair that fails first.
 */
const GLYPH: Record<Tier, React.ReactNode> = {
  verified: (
    <>
      <circle cx="6" cy="6" r="4.6" />
      <path d="M3.9 6.1 5.4 7.6 8.2 4.5" />
    </>
  ),
  heuristic: (
    <>
      <circle cx="6" cy="6" r="4.6" />
      <path d="M6 1.4a4.6 4.6 0 0 1 0 9.2z" fill="currentColor" stroke="none" />
    </>
  ),
  planned: <circle cx="6" cy="6" r="4.6" strokeDasharray="2.1 1.9" />,
  premium: <path d="M6 1.3 10.7 6 6 10.7 1.3 6z" />,
};

/**
 * The evidence-tier label, shared by the landing and the coverage page so
 * "verified" reads identically wherever it appears.
 */
export function TierChip({
  tier,
  children,
}: {
  tier: Tier;
  children?: React.ReactNode;
}) {
  return (
    <span className={`conf ${tier}`}>
      <svg
        viewBox="0 0 12 12"
        aria-hidden="true"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.3"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        {GLYPH[tier]}
      </svg>
      {children}
    </span>
  );
}
