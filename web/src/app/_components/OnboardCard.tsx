"use client";

import { useCallback, useState } from "react";
import { ApiError, OnboardResponse, runOnboard } from "@/lib/api";
import type { OnboardFormState } from "@/lib/onboardForm";
import {
  INITIAL_ONBOARD_FORM,
  isOnboardFormComplete,
  toOnboardRequest,
} from "@/lib/onboardForm";
import { Field } from "./Field";
import { OnboardFields } from "./OnboardFields";
import { RecordList } from "./RecordList";
import { Section } from "./Section";

/**
 * Safe first-run onboarding — the panel equivalent of `cfdi-vault onboard`.
 *
 * This is NOT `SetupCard`. Onboarding writes a local JSON config file and
 * validates the certificate/key without copying them; setup creates the
 * AppData profile and stores the phrase through the secret provider. The
 * difference is visible in the result: `phrase_stored` is always false here.
 *
 * The phrase field follows the identical discipline `SetupCard` documents,
 * because ADR 0004 binds it the same way regardless of what the endpoint does
 * with it:
 *
 * - It is masked and marked `autoComplete="off"` (see `Field`).
 * - It rides in the POST body only. Never a query string, never a path segment.
 * - It is never passed to `console.*` or any other logging call, including in
 *   the catch below: the caught error is an `ApiError` carrying a bounded
 *   backend reason slug, and nothing interpolates the phrase into it.
 * - It is cleared from React state in `finally`, so it survives the submit
 *   handler on success and on failure alike and not one moment longer.
 * - It is held in its own `useState`, deliberately outside the `OnboardFormState`
 *   object the other fields share, so clearing it stays a distinct statement.
 * - Nothing here writes to `localStorage`, `sessionStorage`, or a cookie.
 *
 * The path fields are filesystem paths on the machine running the panel API,
 * typed by the operator. There is deliberately no `<input type="file">`:
 * ADR 0004 forbids moving certificate or private-key bytes through the browser.
 */
export function OnboardCard() {
  const [form, setForm] = useState<OnboardFormState>(INITIAL_ONBOARD_FORM);
  const [phrase, setPhrase] = useState("");
  const [result, setResult] = useState<OnboardResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const set = useCallback(
    <K extends keyof OnboardFormState>(key: K, value: OnboardFormState[K]) => {
      setForm((current) => ({ ...current, [key]: value }));
    },
    [],
  );

  const complete = isOnboardFormComplete(form) && phrase.length > 0;

  const handleSubmit = async () => {
    if (!complete) return;
    setPending(true);
    setError(null);
    setResult(null);
    try {
      setResult(await runOnboard(toOnboardRequest(form, phrase)));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "request failed");
    } finally {
      // Drop the phrase the instant the request settles — success or failure.
      // It must not outlive the submit handler in React state.
      setPhrase("");
      setPending(false);
    }
  };

  return (
    <Section title="Onboarding">
      <p className="mb-4 text-sm text-zinc-600 dark:text-zinc-400">
        Writes a local profile config. Credential files are validated but never
        copied, and the private-key phrase is checked for presence only — it is
        never written to the config.
      </p>

      <OnboardFields form={form} set={set} />

      <div className="mb-4 max-w-sm">
        <Field
          id="onboard-phrase"
          label="Private-key phrase"
          type="password"
          helper="Checked for presence, then discarded. Never written to config."
          value={phrase}
          onChange={setPhrase}
        />
      </div>

      <button
        type="button"
        className="mb-3 rounded bg-zinc-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900"
        disabled={pending || !complete}
        onClick={handleSubmit}
      >
        {pending ? "Running onboarding..." : "Run onboarding"}
      </button>

      {error && <p className="text-sm text-red-500">{error}</p>}

      {/*
        Everything shown comes from the response. The RFC arrives already
        redacted by the backend, the credential refs are non-secret by design,
        and no filesystem path is echoed back.
      */}
      {result && <RecordList record={{ ...result }} />}
    </Section>
  );
}
