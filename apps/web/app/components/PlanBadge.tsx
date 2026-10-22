import { TierChip } from "./TierChip";

/** Plan access is separate from runtime availability and evidence confidence. */
export function PlanBadge({ premium = false }: { premium?: boolean }) {
  return premium ? (
    <TierChip tier="premium">Premium</TierChip>
  ) : (
    <span className="plan-included">Included</span>
  );
}
