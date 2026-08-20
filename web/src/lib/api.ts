/**
 * Typed client for the local control-panel API (ADR 0004).
 *
 * Thin wrapper over `fetch`, one function per backend endpoint defined in
 * `src/cfdi_vault/adapters/webapi/app.py`. No other endpoints exist — do not
 * add calls here for anything not implemented on the backend.
 */

// Loopback only, always (ADR 0004 security contract). Never default to a
// non-loopback host, even via the env override.
export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://127.0.0.1:8420";

export class ApiError extends Error {
  status: number;
  reason?: string;

  constructor(status: number, reason?: string) {
    super(reason ?? `Request failed with status ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.reason = reason;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
  });

  if (!response.ok) {
    let reason: string | undefined;
    try {
      const body = (await response.json()) as { detail?: { reason?: string } };
      reason = body?.detail?.reason;
    } catch {
      // Response had no JSON body; fall back to the generic message.
    }
    throw new ApiError(response.status, reason);
  }

  return (await response.json()) as T;
}

export interface HealthResponse {
  status: string;
}

export function getHealth(): Promise<HealthResponse> {
  return request<HealthResponse>("/health");
}

export interface ProfileStatusResponse {
  profile_id: string;
  status: string;
}

export function getProfileStatus(profileId: string): Promise<ProfileStatusResponse> {
  return request<ProfileStatusResponse>(
    `/api/profile/${encodeURIComponent(profileId)}/status`,
  );
}

// Shape of the campaign status/run dict varies by campaign state — render
// defensively (e.g. as a key/value list), do not assume a fixed schema.
export type CampaignRecord = Record<string, unknown>;

export function getCampaignStatus(
  profileId: string,
  campaignRef: string,
): Promise<CampaignRecord> {
  return request<CampaignRecord>(
    `/api/campaign/${encodeURIComponent(profileId)}/${encodeURIComponent(campaignRef)}/status`,
  );
}

// The endpoint queues the run and returns immediately (202) — it no longer
// waits for the live SAT sequence, which now executes out of process in the
// host-only campaign-run consumer (ADR 0005). Poll getCampaignStatus()'s
// `last_run` field to observe the outcome.
export interface CampaignRunQueuedResponse {
  status: string;
  run_ref: string;
  campaign_ref: string;
  requested_at: string;
}

export function runCampaign(
  profileId: string,
  campaignRef: string,
  grant: string,
): Promise<CampaignRunQueuedResponse> {
  return request<CampaignRunQueuedResponse>(
    `/api/campaign/${encodeURIComponent(profileId)}/${encodeURIComponent(campaignRef)}/run`,
    {
      method: "POST",
      body: JSON.stringify({ grant }),
    },
  );
}

export interface DockerServiceStatus {
  service: string;
  state: string;
}

export function getDockerServices(): Promise<DockerServiceStatus[]> {
  return request<DockerServiceStatus[]>("/api/docker/services");
}

export interface DockerActionResponse {
  service: string;
  action: string;
}

export function startDockerService(service: string): Promise<DockerActionResponse> {
  return request<DockerActionResponse>(
    `/api/docker/${encodeURIComponent(service)}/start`,
    { method: "POST" },
  );
}

export function stopDockerService(service: string): Promise<DockerActionResponse> {
  return request<DockerActionResponse>(
    `/api/docker/${encodeURIComponent(service)}/stop`,
    { method: "POST" },
  );
}
