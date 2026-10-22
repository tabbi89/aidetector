import Link from "next/link";
import { PlanBadge } from "../../components/PlanBadge";
import type { CapabilitiesState } from "../../components/useCapabilities";
import styles from "./ScanPlanSummary.module.css";

export function ScanPlanSummary({ capabilities }: { capabilities: CapabilitiesState }) {
  const { premium, loading, error, reload } = capabilities;
  const status = loading
    ? "Checking plan…"
    : error || !premium
      ? "Plan not confirmed"
      : premium.available
        ? "Premium access enabled"
        : "Free workspace";

  return (
    <section className={styles.panel} aria-label="Plan access">
      <div className={styles.heading}>
        <div>
          <h2>What your plan includes</h2>
          <p>Plan access unlocks features. You choose what runs.</p>
        </div>
        <span className={`${styles.status} ${premium?.available && !error && !loading ? styles.enabled : ""}`} role="status">
          {loading && <span className="spinner" aria-hidden="true" />}
          {status}
        </span>
      </div>
      <div className={styles.columns}>
        <div className={styles.core}>
          <div className={styles.label}><PlanBadge /><strong>On every plan</strong></div>
          <p>Local CLI scans at all three levels, core checks, schema fuzzing, results &amp; history.</p>
          <span className={styles.note}>Optional write testing and AI planning &amp; review are included in local runs.</span>
        </div>
        <div className={styles.premium}>
          <div className={styles.label}>
            <PlanBadge premium />
            <strong>{premium?.available && !error ? "Unlocked for this workspace" : "Additional features"}</strong>
          </div>
          <p><strong>Run from the web &amp; schedule scans.</strong> Plus advanced detections, adaptive AI, Ask your scan, finding ownership &amp; team comments, schema context and pentest reports.</p>
          <Link href="/coverage?plan=premium#check-details">Explore Premium checks <span aria-hidden="true">↗</span></Link>
        </div>
      </div>
      <div className={styles.footer}>
        <p>AI spends tokens and needs a configured provider. External tools need server setup. Writes always need explicit consent.</p>
        {(error || (!loading && !premium)) && (
          <div className={styles.recovery}>
            <span>{error ? "Could not verify plan access." : "This server did not report a plan."} The server checks access when you run.</span>
            <button type="button" className="btn quiet sm" onClick={reload} disabled={loading}>Retry plan check</button>
          </div>
        )}
      </div>
    </section>
  );
}
