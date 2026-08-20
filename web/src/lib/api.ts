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

// ADR 0006 typed-confirmation gate. `confirm` must equal `profileId` exactly:
// case-sensitive, no trimming, no normalization. The backend re-checks this as
// its first statement, so a disabled button in the panel is convenience only —
// the server is the security boundary.
export function createCampaign(
  profileId: string,
  confirm: string,
): Promise<CampaignRecord> {
  return request<CampaignRecord>(
    `/api/campaign/${encodeURIComponent(profileId)}/create`,
    {
      method: "POST",
      body: JSON.stringify({ confirm }),
    },
  );
}

export interface CampaignAuthorizeRequest {
  confirm: string;
  phase: string;
  expires_days: number;
  reason: string;
}

export interface CampaignAuthorizeResponse {
  grant_ref: string;
  phase: string;
  expires_at: string;
  max_open_operations: number;
}

// Same gate as createCampaign, but `confirm` must equal `campaignRef`. The
// value rules for phase/expires_days/reason live in the backend and surface as
// `campaign-grant-*` reason codes — do not duplicate them here (ADR 0006).
export function authorizeCampaign(
  profileId: string,
  campaignRef: string,
  body: CampaignAuthorizeRequest,
): Promise<CampaignAuthorizeResponse> {
  return request<CampaignAuthorizeResponse>(
    `/api/campaign/${encodeURIComponent(profileId)}/${encodeURIComponent(campaignRef)}/authorize`,
    {
      method: "POST",
      body: JSON.stringify(body),
    },
  );
}

export type CredentialMode = "copied" | "referenced";

// `source_folder`, `certificate_path` and `private_key_path` are filesystem
// paths on the machine running the panel API, typed by the operator — never
// browser uploads. ADR 0004 forbids sending certificate or private-key bytes
// through the browser, so there is no multipart route and no file input.
//
// `phrase` travels in the request body only. It must never be placed in a URL,
// query string, log line, or any browser storage (ADR 0004/0006).
export interface SetupRequest {
  rfc: string;
  source_folder: string;
  phrase: string;
  profile_id?: string;
  certificate_path?: string;
  private_key_path?: string;
  credential_mode?: CredentialMode;
}

// The response never carries the phrase back; `rfc` arrives already redacted.
export interface SetupResponse {
  profile_id: string;
  rfc: string;
  credential_mode: string;
  credentials_imported: boolean;
  phrase_stored: boolean;
}

export function runSetup(body: SetupRequest): Promise<SetupResponse> {
  return request<SetupResponse>("/api/setup", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

// Onboarding is not setup. It writes a local JSON config file (the same file
// `POST /api/config/validate` reads) and validates the certificate/key without
// copying them anywhere. `phrase` is checked for presence and discarded, which
// is why the response reports `phrase_stored: false`.
//
// `config_path`, `storage_root`, `certificate_path` and `private_key_path` are
// filesystem paths on the machine running the panel API, typed by the operator
// — never browser uploads (ADR 0004).
//
// `phrase` travels in the request body only. It must never be placed in a URL,
// query string, log line, or any browser storage.
export interface OnboardRequest {
  rfc: string;
  storage_root: string;
  start_date: string;
  certificate_path: string;
  private_key_path: string;
  phrase: string;
  profile_id?: string;
  config_path?: string;
  download_mode?: string;
  end_date?: string;
  periodicity?: string;
  interval_minutes?: number;
  daily_at?: string;
  max_concurrency?: number;
  timezone?: string;
  credential_ref_prefix?: string;
  replace_existing?: boolean;
}

// Carries no filesystem path back: the caller supplied every path it sent, and
// the backend refuses to echo its own expanded storage root. `rfc` arrives
// already redacted; `credential_refs` are non-secret reference URIs.
export interface OnboardResponse {
  profile_id: string;
  rfc: string;
  certificate_fingerprint: string;
  credential_refs: Record<string, string>;
  config_written: boolean;
  storage_ready: boolean;
  credentials_copied: boolean;
  phrase_stored: boolean;
}

export function runOnboard(body: OnboardRequest): Promise<OnboardResponse> {
  return request<OnboardResponse>("/api/onboard", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

// `value` carries raw credential material and is handled exactly like the FIEL
// phrase: body-only, never logged, never persisted client-side.
export interface SecretRegisterRequest {
  reference: string;
  value: string;
  kind?: string;
  purpose?: string;
}

// Echoes the reference and kind only — never the registered value.
export interface SecretRegisterResponse {
  reference: string;
  kind: string;
}

export function registerSecret(
  body: SecretRegisterRequest,
): Promise<SecretRegisterResponse> {
  return request<SecretRegisterResponse>("/api/secret/register", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export interface SecretDeleteRequest {
  reference: string;
  kind?: string;
  purpose?: string;
}

export interface SecretDeleteResponse {
  reference: string;
  kind: string;
  deleted: boolean;
}

// POST, not DELETE /api/secret/{reference}: a credential reference is a full
// scheme URI and cannot ride in a path segment without hand-written escaping
// (ADR 0006).
export function deleteSecret(
  body: SecretDeleteRequest,
): Promise<SecretDeleteResponse> {
  return request<SecretDeleteResponse>("/api/secret/delete", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export interface SecretVerifyResponse {
  reference: string;
  kind: string;
  exists: boolean;
}

// Existence check only. The query string carries the reference and kind — both
// non-secret identifiers. A credential *value* must never reach a query string.
export function verifySecret(
  reference: string,
  kind = "generic",
): Promise<SecretVerifyResponse> {
  const query = new URLSearchParams({ reference, kind });
  return request<SecretVerifyResponse>(`/api/secret/verify?${query.toString()}`);
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
