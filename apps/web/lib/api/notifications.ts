import { request } from "./transport";

export type NotificationEvent =
  | "finding.new"
  | "work.overdue"
  | "run.failed"
  | "run.recovered";

export type NotificationSeverity = "info" | "low" | "medium" | "high" | "critical";
export type NotificationKind = "webhook" | "slack";

export interface NotificationEndpoint {
  id: string;
  kind: NotificationKind;
  destination_hint: string;
  events: NotificationEvent[];
  min_severity: NotificationSeverity;
  active: boolean;
  created_at: string;
}

export interface CreatedNotificationEndpoint extends NotificationEndpoint {
  signing_secret: string | null;
}

export interface NotificationDelivery {
  id: string;
  event_type: string;
  state: string;
  attempts: number;
  last_error: string | null;
  created_at: string;
  delivered_at: string | null;
}

export interface NotificationEndpointInput {
  kind: NotificationKind;
  destination: string;
  events: NotificationEvent[];
  min_severity: NotificationSeverity;
  active?: boolean;
}

export interface NotificationEndpointUpdate {
  events?: NotificationEvent[];
  min_severity?: NotificationSeverity;
  active?: boolean;
}

export const notificationsApi = {
  listNotifications: () =>
    request<NotificationEndpoint[]>("/workspace/notifications"),
  createNotification: (input: NotificationEndpointInput) =>
    request<CreatedNotificationEndpoint>("/workspace/notifications", {
      method: "POST",
      body: JSON.stringify(input),
    }),
  updateNotification: (id: string, input: NotificationEndpointUpdate) =>
    request<NotificationEndpoint>(`/workspace/notifications/${id}`, {
      method: "PATCH",
      body: JSON.stringify(input),
    }),
  deleteNotification: (id: string) =>
    request<{ status: string }>(`/workspace/notifications/${id}`, {
      method: "DELETE",
    }),
  testNotification: (id: string) =>
    request<{ status: string; delivery_id: string }>(
      `/workspace/notifications/${id}/test`,
      { method: "POST" },
    ),
  listNotificationDeliveries: () =>
    request<NotificationDelivery[]>("/workspace/notifications/deliveries"),
};
