import { request } from "./transport";

/** One proof's outcome from the last check. Mirrors `DomainProofOut`. */
export interface DomainProof {
  proof: "dns" | "http";
  ok: boolean;
  /** Why it failed, phrased as the fix; null when it passed. */
  detail: string | null;
}

/** A public scan target whose ownership this workspace has to prove. */
export interface DomainVerification {
  id: string;
  host: string;
  token: string;
  /** Null for an IP literal: there is no name to prove. */
  dns_record_name: string | null;
  dns_record_value: string;
  http_path: string;
  /** `http_path` on `https://<host>`, ready to open. */
  http_url: string;
  verified_at: string | null;
  last_checked_at: string | null;
  last_error: string | null;
  /** DNS then HTTP; empty before the first check or when the host is refused outright. */
  last_checks: DomainProof[];
  created_at: string;
}

/**
 * Whether running a scan needs proof the workspace owns its target. Mirrors
 * `TargetOwnershipOut`; advisory, since the run proves ownership live.
 */
export interface TargetOwnership {
  host: string;
  /** False when the egress policy refuses the target outright; `reason` says why. */
  allowed: boolean;
  required: boolean;
  exempt: "disabled" | "allowlist" | "private" | null;
  domain_id: string | null;
  verified_at: string | null;
  last_error: string | null;
  reason: string | null;
}

export const domainsApi = {
  targetOwnership: (scanId: string) =>
    request<TargetOwnership>(`/scans/${scanId}/ownership`),
  listDomains: () => request<DomainVerification[]>("/workspace/domains"),
  addDomain: (host: string) =>
    request<DomainVerification>("/workspace/domains", {
      method: "POST",
      body: JSON.stringify({ host }),
    }),
  // A failed proof is still a 200: the row comes back with last_error set.
  verifyDomain: (id: string, url?: string | null) =>
    request<DomainVerification>(`/workspace/domains/${id}/verify`, {
      method: "POST",
      body: JSON.stringify({ url: url ?? null }),
    }),
  deleteDomain: (id: string) =>
    request<{ status: string }>(`/workspace/domains/${id}`, { method: "DELETE" }),
};
