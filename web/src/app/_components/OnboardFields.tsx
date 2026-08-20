"use client";

import type {
  OnboardFieldSetter,
  OnboardFormState,
} from "@/lib/onboardForm";
import { DOWNLOAD_MODES, PERIODICITIES } from "@/lib/onboardForm";
import { Field } from "./Field";
import { SelectField } from "./SelectField";

/**
 * The non-secret half of the onboarding form.
 *
 * The phrase is deliberately not rendered here and is not part of
 * `OnboardFormState`; see `@/lib/onboardForm` for why it is kept separate.
 */
export function OnboardFields({
  form,
  set,
}: {
  form: OnboardFormState;
  set: OnboardFieldSetter;
}) {
  return (
    <>
      <div className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Field
          id="onboard-profile-id"
          label="Profile ID"
          placeholder="default"
          value={form.profileId}
          onChange={(value) => set("profileId", value)}
        />
        <Field
          id="onboard-rfc"
          label="RFC"
          placeholder="RFC"
          value={form.rfc}
          onChange={(value) => set("rfc", value)}
        />
        <Field
          id="onboard-config-path"
          label="Config path"
          placeholder="cfdi-vault.local.json"
          helper="Config file to create or update, on the panel API machine."
          value={form.configPath}
          onChange={(value) => set("configPath", value)}
        />
        <Field
          id="onboard-storage-root"
          label="Storage root"
          placeholder="C:\path\to\storage"
          helper="Root folder for metadata, packages, XML, logs, and exports."
          value={form.storageRoot}
          onChange={(value) => set("storageRoot", value)}
        />
        <Field
          id="onboard-certificate-path"
          label="Certificate path (.cer)"
          placeholder="C:\path\to\certificate.cer"
          helper="Validated and hashed. The file is not copied."
          value={form.certificatePath}
          onChange={(value) => set("certificatePath", value)}
        />
        <Field
          id="onboard-private-key-path"
          label="Private key path (.key)"
          placeholder="C:\path\to\private-key.key"
          helper="Validated only. The file is not copied."
          value={form.privateKeyPath}
          onChange={(value) => set("privateKeyPath", value)}
        />
        <SelectField
          id="onboard-download-mode"
          label="Download mode"
          value={form.downloadMode}
          onChange={(value) => set("downloadMode", value)}
          options={DOWNLOAD_MODES}
        />
        <SelectField
          id="onboard-periodicity"
          label="Periodicity"
          value={form.periodicity}
          onChange={(value) => set("periodicity", value)}
          options={PERIODICITIES}
        />
        <Field
          id="onboard-start-date"
          label="Initial start date"
          placeholder="2024-01-01"
          value={form.startDate}
          onChange={(value) => set("startDate", value)}
        />
        <Field
          id="onboard-end-date"
          label="Initial end date (optional)"
          placeholder="2024-01-31"
          value={form.endDate}
          onChange={(value) => set("endDate", value)}
        />
        <Field
          id="onboard-interval-minutes"
          label="Interval minutes"
          type="number"
          min={1}
          helper="Required when periodicity is interval."
          value={form.intervalMinutes}
          onChange={(value) => set("intervalMinutes", value)}
          disabled={form.periodicity !== "interval"}
        />
        <Field
          id="onboard-daily-at"
          label="Daily at (HH:MM)"
          placeholder="03:00"
          helper="Required when periodicity is daily."
          value={form.dailyAt}
          onChange={(value) => set("dailyAt", value)}
          disabled={form.periodicity !== "daily"}
        />
        <Field
          id="onboard-max-concurrency"
          label="Max concurrency"
          type="number"
          min={1}
          max={10}
          value={form.maxConcurrency}
          onChange={(value) => set("maxConcurrency", value)}
        />
        <Field
          id="onboard-timezone"
          label="Timezone"
          placeholder="America/Mexico_City"
          value={form.timezone}
          onChange={(value) => set("timezone", value)}
        />
        <Field
          id="onboard-credential-ref-prefix"
          label="Credential ref prefix (optional)"
          placeholder="windows-credential-manager://cfdi-vault/default"
          helper="Non-secret reference prefix for external credential custody."
          value={form.credentialRefPrefix}
          onChange={(value) => set("credentialRefPrefix", value)}
        />
      </div>

      <div className="mb-4 flex items-center gap-2">
        <input
          id="onboard-replace-existing"
          type="checkbox"
          className="h-4 w-4 rounded border-zinc-300 dark:border-zinc-700"
          checked={form.replaceExisting}
          onChange={(e) => set("replaceExisting", e.target.checked)}
        />
        <label
          htmlFor="onboard-replace-existing"
          className="text-sm text-zinc-600 dark:text-zinc-400"
        >
          Replace an existing profile with the same profile id
        </label>
      </div>
    </>
  );
}
