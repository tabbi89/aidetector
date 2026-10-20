import { request } from "./transport";

/** Mirrors `Role` in `app/domain/permissions.py`. */
export type WorkspaceRole = "admin" | "analyst" | "viewer";

export interface WorkspaceUser {
  id: string;
  email: string;
  display_name: string;
}

export interface Workspace {
  tenant: string;
  name: string;
  plan: string;
  role: WorkspaceRole;
  user: WorkspaceUser | null;
  members: number;
}

export interface WorkspaceMember {
  user_id: string;
  email: string;
  display_name: string;
  role: WorkspaceRole;
  created_at: string;
}

export interface WorkspaceToken {
  id: string;
  user_id: string;
  email: string;
  display_name: string;
  prefix: string;
  last4: string;
  label: string;
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
}

export interface CreatedToken extends WorkspaceToken {
  token: string;
}

export interface WorkspaceAuditRow {
  id: string;
  actor: WorkspaceUser | null;
  action: string;
  object_type: string;
  object_id: string;
  summary: Record<string, unknown>;
  created_at: string;
}

export interface MemberInput {
  email: string;
  display_name: string;
  role: WorkspaceRole;
}

/** A self-service access request waiting for an admin. */
export interface PendingSignup {
  user_id: string;
  email: string;
  display_name: string;
  requested_at: string;
}

export interface SignUpInput {
  email: string;
  display_name: string;
  password: string;
}

export interface SignInInput {
  email: string;
  password: string;
}

/** A signed-in session. The token is an ordinary API token, sent as X-API-Key. */
export interface SignInResult {
  token: string;
  expires_at: string;
  tenant: string;
  role: WorkspaceRole;
  user: WorkspaceUser;
}

export interface TokenInput {
  user_id: string;
  label?: string;
}

export interface Budget {
  tenant: string;
  plan: string;
  ai_monthly_micros: number | null;
  ai_per_scan_micros: number | null;
  max_concurrent_runs: number | null;
  max_queued_runs: number | null;
  scans_per_day: number | null;
  month_spent_micros: number;
  month_remaining_micros: number | null;
  active_runs: number;
  queued_runs: number;
}

export interface BudgetInput {
  ai_monthly_micros?: number | null;
  ai_per_scan_micros?: number | null;
  max_concurrent_runs?: number | null;
  max_queued_runs?: number | null;
  scans_per_day?: number | null;
}

export const workspaceApi = {
  signUp: (input: SignUpInput) =>
    request<{ status: string }>("/auth/signup", {
      method: "POST",
      body: JSON.stringify(input),
    }),
  signIn: (input: SignInInput) =>
    request<SignInResult>("/auth/login", {
      method: "POST",
      body: JSON.stringify(input),
    }),
  signOut: () => request<{ status: string }>("/auth/logout", { method: "POST" }),
  listSignups: () => request<PendingSignup[]>("/workspace/signups"),
  approveSignup: (userId: string, role: WorkspaceRole = "analyst") =>
    request<WorkspaceMember>(`/workspace/signups/${userId}/approve`, {
      method: "POST",
      body: JSON.stringify({ role }),
    }),
  rejectSignup: (userId: string) =>
    request<{ status: string }>(`/workspace/signups/${userId}`, {
      method: "DELETE",
    }),
  getWorkspace: () => request<Workspace>("/workspace"),
  listMembers: () => request<WorkspaceMember[]>("/workspace/members"),
  addMember: (input: MemberInput) =>
    request<WorkspaceMember>("/workspace/members", {
      method: "POST",
      body: JSON.stringify(input),
    }),
  changeRole: (userId: string, role: WorkspaceRole) =>
    request<WorkspaceMember>(`/workspace/members/${userId}`, {
      method: "PATCH",
      body: JSON.stringify({ role }),
    }),
  removeMember: (userId: string) =>
    request<{ status: string }>(`/workspace/members/${userId}`, {
      method: "DELETE",
    }),
  listTokens: () => request<WorkspaceToken[]>("/workspace/tokens"),
  createToken: (input: TokenInput) =>
    request<CreatedToken>("/workspace/tokens", {
      method: "POST",
      body: JSON.stringify(input),
    }),
  revokeToken: (tokenId: string) =>
    request<{ status: string }>(`/workspace/tokens/${tokenId}`, {
      method: "DELETE",
    }),
  getBudget: () => request<Budget>("/workspace/budgets"),
  setBudget: (input: BudgetInput) =>
    request<Budget>("/workspace/budgets", {
      method: "PUT",
      body: JSON.stringify(input),
    }),
  listAudit: () => request<WorkspaceAuditRow[]>("/workspace/audit"),
};
