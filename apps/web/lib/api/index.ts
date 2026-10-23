// Public surface of the API client: re-export the types and assemble `api`
// from the feature modules. `lib/api.ts` re-exports this file unchanged.
import { databaseApi } from "./database";
import { domainsApi } from "./domains";
import { notificationsApi } from "./notifications";
import { scansApi } from "./scans";
import { request } from "./transport";
import type { AuthStatus, Capabilities, Health } from "./types";
import { workspaceApi } from "./workspace";

export * from "./types";
export * from "./transport";
export * from "./scans";
export * from "./database";
export * from "./workspace";
export * from "./notifications";
export * from "./domains";

export const api = {
  ...databaseApi,
  ...workspaceApi,
  ...notificationsApi,
  ...domainsApi,
  health: () => request<Health>("/health"),
  capabilities: () => request<Capabilities>("/capabilities"),
  authStatus: () => request<AuthStatus>("/auth/status"),
  ...scansApi,
};
