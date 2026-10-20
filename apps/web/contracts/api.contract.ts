/** Exact wire-shape comparison, including optionality, nullability and enum members. */
import type * as Client from "../lib/api";
import type { components, paths } from "./generated";

type Server = components["schemas"];
type Shape<T> = T extends object ? { [K in keyof T]: Shape<T[K]> } : T;
type Equal<A, B> =
  (<T>() => T extends Shape<A> ? 1 : 2) extends
  (<T>() => T extends Shape<B> ? 1 : 2) ? true : false;
type Expect<T extends true> = T;

// Both sides must have exactly the same keys/types. One-way assignability would
// silently accept extra fields, narrower enums and some optionality differences.
export type ResponseContracts = [
  Expect<Equal<Client.EvidenceSource, Server["EvidenceSourceOut"]>>,
  Expect<Equal<Client.InfrastructureMonitor, Server["MonitoringOut"]>>,
  Expect<Equal<Client.MonitoringSetupView, Server["MonitoringSetupOut"]>>,
  Expect<Equal<Client.MonitoringRun, Server["MonitoringRunOut"]>>,
  Expect<Equal<Client.MonitoringBots, Server["MonitoringBotsOut"]>>,
  Expect<Equal<Client.MonitoringBriefing, Server["MonitoringBriefingOut"]>>,
  Expect<Equal<Client.MonitoringRoutes, Server["MonitoringRoutesOut"]>>,
  Expect<Equal<Client.MonitoringClients, Server["MonitoringClientsOut"]>>,
  Expect<Equal<Client.SchemaContext, Server["SchemaContextOut"]>>,
  Expect<Equal<Client.SchemaContextDeleted, Server["SchemaContextDeleted"]>>,
  Expect<Equal<Client.Health, Server["HealthOut"]>>,
  Expect<Equal<Client.Operation, Server["OperationOut"]>>,
  Expect<Equal<Client.Credential, Server["CredentialOut"]>>,
  Expect<Equal<Client.Scan, Server["ScanOut"]>>,
  Expect<Equal<Client.ScanSummary, Server["ScanSummary"]>>,
  Expect<Equal<Client.ScanEvent, Server["ScanEventOut"]>>,
  Expect<Equal<Client.RunFinding, Server["RunFindingOut"]>>,
  Expect<Equal<Client.RunDiff, Server["RunDiffOut"]>>,
  Expect<Equal<Client.CoverageRow, Server["CoverageRow"]>>,
  Expect<Equal<Client.PlanRow, Server["PlanRow"]>>,
  Expect<Equal<Client.ScanRun, Server["ScanRunOut"]>>,
  Expect<Equal<Client.Finding, Server["FindingOut"]>>,
  Expect<Equal<Client.AskAnswer, Server["AskOut"]>>,
  Expect<Equal<Client.LedgerEntry, Server["LedgerEntryOut"]>>,
  Expect<Equal<Client.AiModelUsage, Server["AiModelUsage"]>>,
  Expect<Equal<Client.Cost, Server["CostOut"]>>,
  Expect<Equal<Client.RunAccepted, Server["RunAccepted"]>>,
];

export type RequestContracts = [
  Expect<Equal<Client.EvidenceSourceInput, JsonRequest<"/monitoring/sources", "post">>>,
  Expect<Equal<Client.MonitoringInput, JsonRequest<"/monitoring", "post">>>,
  Expect<Equal<Client.MonitoringSetupInput, JsonRequest<"/monitoring/setup", "post">>>,
  Expect<Equal<Client.MonitoringSetupUpdate, JsonRequest<"/monitoring/{monitor_id}/setup", "put">>>,
  Expect<Equal<Client.ScanInput, JsonRequest<"/scans", "post">>>,
  Expect<Equal<Client.ScanInput, JsonRequest<"/scans/{scan_id}", "patch">>>,
  Expect<Equal<Client.RequestRateInput,
    JsonRequest<"/scans/{scan_id}/request-rate", "put">>>,
  Expect<Equal<Client.SpecInput, JsonRequest<"/scans/{scan_id}/spec", "post">>>,
  Expect<Equal<Client.OperationsInput, JsonRequest<"/scans/{scan_id}/operations", "patch">>>,
  Expect<Equal<Client.CredentialInput, JsonRequest<"/scans/{scan_id}/credentials", "post">>>,
  Expect<Equal<Client.CredentialUpdateInput,
    JsonRequest<"/scans/{scan_id}/credentials/{cred_id}", "patch">>>,
  Expect<Equal<Client.ScheduleInput, JsonRequest<"/scans/{scan_id}/schedule", "put">>>,
  Expect<Equal<Client.VerdictInput,
    JsonRequest<"/scans/{scan_id}/findings/{finding_id}", "patch">>>,
  Expect<Equal<Client.AskInput, JsonRequest<"/scans/{scan_id}/ask", "post">>>,
  Expect<Equal<Client.RunInput, JsonRequest<"/scans/{scan_id}/run", "post">>>,
];

type JsonRequest<P extends keyof paths, M extends keyof paths[P]> =
  paths[P][M] extends { requestBody: { content: { "application/json": infer T } } } ? T : never;
type JsonResponse<P extends keyof paths, M extends keyof paths[P], S extends number = 200> =
  paths[P][M] extends { responses: Record<S, { content: { "application/json": infer T } }> }
    ? T : never;
type Result<M extends keyof typeof Client.api> = Awaited<ReturnType<typeof Client.api[M]>>;

// Bind the actual client functions to their routes too: keeping a model in the
// schema must not hide an endpoint switching to a different response model.
export type RouteContracts = [
  Expect<Equal<Result<"getSchemaContext">,
    JsonResponse<"/scans/{scan_id}/schema-context", "get">>>,
  Expect<Equal<Result<"deleteSchemaContext">,
    JsonResponse<"/scans/{scan_id}/schema-context", "delete">>>,
  Expect<Equal<Result<"health">, JsonResponse<"/health", "get">>>,
  Expect<Equal<Result<"setupMonitor">, JsonResponse<"/monitoring/setup", "post", 201>>>,
  Expect<Equal<Result<"getMonitorSetup">, JsonResponse<"/monitoring/{monitor_id}/setup", "get">>>,
  Expect<Equal<Result<"updateMonitorSetup">,
    JsonResponse<"/monitoring/{monitor_id}/setup", "put">>>,
  Expect<Equal<Result<"createExampleMonitor">, JsonResponse<"/monitoring/example", "post", 201>>>,
  Expect<Equal<Result<"createExampleScan">, JsonResponse<"/scans/example", "post", 201>>>,
  Expect<Equal<Result<"monitoringBots">, JsonResponse<"/monitoring/{monitor_id}/bots", "get">>>,
  Expect<Equal<Result<"monitoringRoutes">,
    JsonResponse<"/monitoring/{monitor_id}/routes", "get">>>,
  Expect<Equal<Result<"monitoringClients">,
    JsonResponse<"/monitoring/{monitor_id}/clients", "get">>>,
  Expect<Equal<Result<"monitoringBriefing">,
    JsonResponse<"/monitoring/{monitor_id}/briefing", "get">>>,
  Expect<Equal<Result<"briefMonitoring">,
    JsonResponse<"/monitoring/{monitor_id}/briefing", "post", 202>>>,
  Expect<Equal<Result<"explainObservation">,
    JsonResponse<"/monitoring/{monitor_id}/runs/{run_id}/observations/{fingerprint}/explain",
      "post", 202>>>,
  Expect<Equal<Result<"listScans">, JsonResponse<"/scans", "get">>>,
  Expect<Equal<Result<"createScan">, JsonResponse<"/scans", "post", 201>>>,
  Expect<Equal<Result<"getScan">, JsonResponse<"/scans/{scan_id}", "get">>>,
  Expect<Equal<Result<"updateScan">, JsonResponse<"/scans/{scan_id}", "patch">>>,
  Expect<Equal<Result<"setRequestRate">,
    JsonResponse<"/scans/{scan_id}/request-rate", "put">>>,
  Expect<Equal<Result<"uploadSpec">, JsonResponse<"/scans/{scan_id}/spec", "post">>>,
  Expect<Equal<Result<"setOperations">, JsonResponse<"/scans/{scan_id}/operations", "patch">>>,
  Expect<Equal<Result<"addCredential">, JsonResponse<"/scans/{scan_id}/credentials", "post", 201>>>,
  Expect<Equal<Result<"updateCredential">,
    JsonResponse<"/scans/{scan_id}/credentials/{cred_id}", "patch">>>,
  Expect<Equal<Result<"runScan">, JsonResponse<"/scans/{scan_id}/run", "post", 202>>>,
  Expect<Equal<Result<"getCost">, JsonResponse<"/scans/{scan_id}/cost", "get">>>,
  Expect<Equal<Result<"setSchedule">, JsonResponse<"/scans/{scan_id}/schedule", "put">>>,
  Expect<Equal<Result<"cancelScan">, JsonResponse<"/scans/{scan_id}/cancel", "post">>>,
  Expect<Equal<Result<"getEvents">, JsonResponse<"/scans/{scan_id}/events", "get">>>,
  Expect<Equal<Result<"getRuns">, JsonResponse<"/scans/{scan_id}/runs", "get">>>,
  Expect<Equal<Result<"getDiff">, JsonResponse<"/scans/{scan_id}/diff", "get">>>,
  Expect<Equal<Result<"getFindings">, JsonResponse<"/scans/{scan_id}/findings", "get">>>,
  Expect<Equal<Result<"ask">, JsonResponse<"/scans/{scan_id}/ask", "post">>>,
  Expect<Equal<Result<"setVerdict">,
    JsonResponse<"/scans/{scan_id}/findings/{finding_id}", "patch">>>,
];

// Deliberately broken fixtures prove the gate rejects each kind of drift. If
// Equal ever stops catching one, tsc fails on the unused @ts-expect-error.
type OptionalProgress = Omit<Client.Scan, "progress"> & { progress?: number };
type NonNullableSchedule = Omit<Client.Scan, "schedule_minutes"> & { schedule_minutes: number };
type MissingField = Omit<Client.Scan, "target_base_url">;
type ExtraField = Client.Scan & { invented: string };
type WrongEnum = Omit<Client.Finding, "verdict"> & { verdict: string };
// @ts-expect-error Optional response fields are not interchangeable with required fields.
export type RejectOptional = Expect<Equal<OptionalProgress, Server["ScanOut"]>>;
// @ts-expect-error null is part of the wire contract.
export type RejectNullability = Expect<Equal<NonNullableSchedule, Server["ScanOut"]>>;
// @ts-expect-error Missing keys must fail.
export type RejectMissing = Expect<Equal<MissingField, Server["ScanOut"]>>;
// @ts-expect-error Extra keys must fail too.
export type RejectExtra = Expect<Equal<ExtraField, Server["ScanOut"]>>;
// @ts-expect-error A string cannot replace the verdict enum.
export type RejectEnum = Expect<Equal<WrongEnum, Server["FindingOut"]>>;
// @ts-expect-error Request optionality is checked, independently of response types.
export type RejectRequest = Expect<Equal<Required<Client.ScheduleInput>, Server["ScheduleRequest"]>>;
