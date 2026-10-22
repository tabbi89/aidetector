import Link from "next/link";
import { PlanBadge } from "./PlanBadge";

export function WebRunNotice() {
  return (
    <div className="web-run-notice" role="note">
      <PlanBadge premium />
      <h3>Web scans require Premium</h3>
      <p>Run scans from the browser and schedule automatic runs with a Premium workspace.</p>
      <p>On Free, configure your scan here, run it locally with the CLI, and review the results in this workspace.</p>
      <div className="actions">
        <Link className="btn quiet sm" href="/cli">Run with the CLI <span aria-hidden="true">↗</span></Link>
        <Link className="link-arrow" href="/#plans">Compare plans →</Link>
      </div>
    </div>
  );
}
