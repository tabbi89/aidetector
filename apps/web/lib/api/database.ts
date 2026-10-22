// A scan's read-only schema snapshot, captured by an `runpentests` CLI run.
import { request } from "./transport";

export interface SchemaAttempt {
  run_number: number;
  status: "available" | "unavailable";
  reason: string | null;
  captured_at: string;
}
export interface SchemaTableSummary {
  schema_name: string;
  table_name: string;
  column_count: number;
  constraint_count: number;
}
export interface SchemaSnapshotSummary {
  run_number: number;
  captured_at: string;
  warnings: string[];
  tables: SchemaTableSummary[];
}
export interface SchemaContext {
  latest: SchemaAttempt | null;
  snapshot: SchemaSnapshotSummary | null;
}
export interface SchemaContextDeleted { removed: number }

export const databaseApi = {
  getSchemaContext: (id: string) =>
    request<SchemaContext>(`/scans/${id}/schema-context`),
  deleteSchemaContext: (id: string) =>
    request<SchemaContextDeleted>(`/scans/${id}/schema-context`, { method: "DELETE" }),
};
