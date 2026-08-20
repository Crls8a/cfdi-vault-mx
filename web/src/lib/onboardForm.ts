/**
 * Onboarding form state and its mapping to the `POST /api/onboard` body.
 *
 * This lives outside `_components/` on purpose: it is data and pure functions,
 * not UI, so the component files stay component-only.
 *
 * The phrase is deliberately NOT part of `OnboardFormState` and never passes
 * through this module's state. `OnboardCard` holds it in its own `useState` and
 * passes it to `toOnboardRequest` as a separate argument, so the code that
 * clears it on submit is impossible to confuse with ordinary form state, and no
 * future "reset the form" helper can treat it as just another field.
 */

import type { OnboardRequest } from "@/lib/api";

export interface OnboardFormState {
  profileId: string;
  rfc: string;
  configPath: string;
  storageRoot: string;
  certificatePath: string;
  privateKeyPath: string;
  downloadMode: string;
  periodicity: string;
  startDate: string;
  endDate: string;
  intervalMinutes: string;
  dailyAt: string;
  maxConcurrency: string;
  timezone: string;
  credentialRefPrefix: string;
  replaceExisting: boolean;
}

export type OnboardFieldSetter = <K extends keyof OnboardFormState>(
  key: K,
  value: OnboardFormState[K],
) => void;

export const INITIAL_ONBOARD_FORM: OnboardFormState = {
  profileId: "default",
  rfc: "",
  configPath: "cfdi-vault.local.json",
  storageRoot: "",
  certificatePath: "",
  privateKeyPath: "",
  downloadMode: "both",
  periodicity: "disabled",
  startDate: "",
  endDate: "",
  intervalMinutes: "",
  dailyAt: "",
  maxConcurrency: "2",
  timezone: "America/Mexico_City",
  credentialRefPrefix: "",
  replaceExisting: false,
};

export const DOWNLOAD_MODES = ["issued", "received", "both"] as const;
export const PERIODICITIES = ["disabled", "interval", "daily"] as const;

/**
 * Every field the backend requires, plus the periodicity-dependent one.
 *
 * This gates the submit button only. The backend re-checks everything and owns
 * the real value rules, reporting them as `onboard-*` reason codes.
 */
export function isOnboardFormComplete(form: OnboardFormState): boolean {
  const scheduleComplete =
    (form.periodicity !== "interval" || form.intervalMinutes.length > 0) &&
    (form.periodicity !== "daily" || form.dailyAt.length > 0);

  return (
    form.profileId.length > 0 &&
    form.rfc.length > 0 &&
    form.configPath.length > 0 &&
    form.storageRoot.length > 0 &&
    form.startDate.length > 0 &&
    form.certificatePath.length > 0 &&
    form.privateKeyPath.length > 0 &&
    scheduleComplete
  );
}

/** Map form strings to the request, omitting optional fields left blank. */
export function toOnboardRequest(
  form: OnboardFormState,
  phrase: string,
): OnboardRequest {
  return {
    profile_id: form.profileId,
    rfc: form.rfc,
    config_path: form.configPath,
    storage_root: form.storageRoot,
    certificate_path: form.certificatePath,
    private_key_path: form.privateKeyPath,
    download_mode: form.downloadMode,
    start_date: form.startDate,
    end_date: form.endDate || undefined,
    periodicity: form.periodicity,
    interval_minutes: form.intervalMinutes
      ? Number(form.intervalMinutes)
      : undefined,
    daily_at: form.dailyAt || undefined,
    max_concurrency: form.maxConcurrency
      ? Number(form.maxConcurrency)
      : undefined,
    timezone: form.timezone,
    credential_ref_prefix: form.credentialRefPrefix || undefined,
    replace_existing: form.replaceExisting,
    phrase,
  };
}
