import type { AlertStatus, SecurityAlert } from "../types/alert";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";

export interface FetchRecentAlertsOptions {
  count?: number;
  status?: AlertStatus;
  requiresHumanReview?: boolean;
}

export interface AlertStatusUpdateRequest {
  status: AlertStatus;
  analyst_note?: string;
  handled_by?: string;
}

export async function fetchRecentAlerts(
  options: FetchRecentAlertsOptions = {},
): Promise<SecurityAlert[]> {
  const params = new URLSearchParams({
    count: String(options.count ?? 20),
  });

  if (options.status) {
    params.set("status", options.status);
  }

  if (options.requiresHumanReview !== undefined) {
    params.set("requires_human_review", String(options.requiresHumanReview));
  }

  const response = await fetch(`${API_BASE_URL}/api/alerts/recent?${params.toString()}`);

  if (!response.ok) {
    throw new Error(`Failed to fetch alerts: ${response.status}`);
  }

  return response.json();
}

export async function updateAlertStatus(
  alertId: string,
  update: AlertStatusUpdateRequest,
): Promise<SecurityAlert> {
  const response = await fetch(`${API_BASE_URL}/api/alerts/${alertId}/status`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(update),
  });

  if (!response.ok) {
    throw new Error(`Failed to update alert status: ${response.status}`);
  }

  return response.json();
}
