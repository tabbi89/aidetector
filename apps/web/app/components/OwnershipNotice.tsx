"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api, type TargetOwnership } from "@/lib/api";
import { useConnection } from "@/lib/connection";

const DOMAINS = "/workspace?section=domains";

/**
 * Says, before the run, whether this scan's target still needs its ownership
 * proven — otherwise the first a person hears of it is the run being refused.
 * Advisory: the run gate proves ownership live, so a "verified" here can still
 * fail if the DNS record or token has since been taken down. Re-asks when the
 * tab regains focus, so verifying in another tab shows up on return.
 */
export function useTargetOwnership(scanId: string, target: string): TargetOwnership | null {
  const [status, setStatus] = useState<TargetOwnership | null>(null);

  useEffect(() => {
    let live = true;
    const load = () => {
      api.targetOwnership(scanId).then(
        (next) => live && setStatus(next),
        // An older API has no such route; say nothing rather than guess.
        () => live && setStatus(null),
      );
    };
    load();
    window.addEventListener("focus", load);
    return () => {
      live = false;
      window.removeEventListener("focus", load);
    };
  }, [scanId, target]);

  return status;
}

/** The host this workspace has proven it owns, when the target needs that proof and has it. */
export function verifiedHostOf(status: TargetOwnership | null): string | null {
  return status && status.allowed && status.required && status.verified_at ? status.host : null;
}

const EXEMPT_LABEL: Record<NonNullable<TargetOwnership["exempt"]>, string | null> = {
  private: "Private target — no domain proof needed",
  allowlist: "Allowlisted by the operator — no domain proof needed",
  disabled: null,
};

/**
 * The scan header's one-glance answer to "may this target be scanned?": the
 * domain's verification state, linking admins to where it is proved.
 */
export function OwnershipChip({ scanId, target }: { scanId: string; target: string }) {
  const { role } = useConnection();
  const status = useTargetOwnership(scanId, target);
  if (!status) return null;

  let tone: "ok" | "warn" | "muted";
  let label: string;
  let title: string;
  if (!status.allowed) {
    tone = "warn";
    label = "Target refused";
    title = status.reason ?? "The egress policy refuses this target.";
  } else if (!status.required) {
    const exempt = status.exempt ? EXEMPT_LABEL[status.exempt] : null;
    if (!exempt) return null;
    tone = "muted";
    label = status.exempt === "private" ? "Private target" : "Allowlisted";
    title = exempt;
  } else if (status.verified_at) {
    tone = "ok";
    label = "Domain verified";
    title = `This workspace has proven it owns ${status.host}; every run checks it again.`;
  } else {
    tone = "warn";
    label = "Domain not verified";
    title = status.last_error
      ? `Last check: ${status.last_error}`
      : `Runs are refused until this workspace proves it owns ${status.host}.`;
  }

  const body = (
    <>
      <span className="domain-chip-dot" aria-hidden="true" />
      {label}
    </>
  );
  // Only admins can open the Domains section; for anyone else it is a label.
  return role === "admin" && status.allowed && status.required ? (
    <Link className={`domain-chip ${tone}`} href={DOMAINS} title={title}>
      {body}
    </Link>
  ) : (
    <span className={`domain-chip ${tone}`} title={title}>
      {body}
    </span>
  );
}

export function OwnershipNotice({ scanId, target }: { scanId: string; target: string }) {
  const { role } = useConnection();
  const status = useTargetOwnership(scanId, target);

  if (!status || (status.allowed && !status.required)) return null;

  if (!status.allowed) {
    return (
      <div className="target-help is-warn" role="note">
        <span className="target-help-label">This target can&rsquo;t be scanned</span>
        <p>{status.reason}</p>
      </div>
    );
  }

  if (status.verified_at) {
    return (
      <div className="target-help is-ok" role="note">
        <span className="target-help-label">Domain verified</span>
        <p>
          This workspace has proven it owns <code>{status.host}</code>. The proof
          is checked again when the run starts, so keep the DNS record and token
          published.
        </p>
      </div>
    );
  }

  const where =
    role === "admin" ? (
      <Link href={DOMAINS}>Workspace → Domains</Link>
    ) : (
      "Workspace → Domains (a workspace admin can do this)"
    );

  return (
    <div className="target-help is-warn" role="note">
      <span className="target-help-label">Verify this domain before running</span>
      <p>
        <code>{status.host}</code> is a public address, so the run will be
        refused until this workspace proves it owns it.{" "}
        {status.domain_id ? (
          <>
            It is listed under {where} but not verified yet: publish the DNS TXT
            record and HTTP token shown there, then press Check now.
          </>
        ) : (
          <>
            Add it under {where}, publish the DNS TXT record and HTTP token shown
            there, then press Check now.
          </>
        )}
      </p>
      {status.last_error && <p className="muted-sm">Last check: {status.last_error}</p>}
    </div>
  );
}
