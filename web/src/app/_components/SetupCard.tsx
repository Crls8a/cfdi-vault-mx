"use client";

import { useState } from "react";
import {
  ApiError,
  CredentialMode,
  SetupResponse,
  runSetup,
} from "@/lib/api";
import { Field } from "./Field";
import { Section } from "./Section";

/**
 * FIEL onboarding — the panel equivalent of the retired `cfdi-vault setup`.
 *
 * The phrase field is the most sensitive element in this frontend. ADR 0004,
 * restated by ADR 0006, binds it:
 *
 * - It is masked and marked `autoComplete="off"` (see `Field`).
 * - It rides in the POST body only. Never a query string, never a path segment.
 * - It is never passed to `console.*` or any other logging call, including in
 *   the catch below: the caught error is an `ApiError` carrying a bounded
 *   backend reason slug, and nothing interpolates the phrase into it.
 * - It is cleared from React state in `finally`, so it survives the submit
 *   handler on success and on failure alike and not one moment longer.
 * - Nothing here writes to `localStorage`, `sessionStorage`, or a cookie.
 *
 * The three path fields are filesystem paths on the machine running the panel
 * API, typed by the operator. There is deliberately no `<input type="file">`:
 * ADR 0004 forbids moving certificate or private-key bytes through the browser.
 */
export function SetupCard() {
  const [profileId, setProfileId] = useState("default");
  const [rfc, setRfc] = useState("");
  const [sourceFolder, setSourceFolder] = useState("");
  const [certificatePath, setCertificatePath] = useState("");
  const [privateKeyPath, setPrivateKeyPath] = useState("");
  const [credentialMode, setCredentialMode] = useState<CredentialMode>("copied");
  const [phrase, setPhrase] = useState("");
  const [result, setResult] = useState<SetupResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const complete =
    profileId.length > 0 &&
    rfc.length > 0 &&
    sourceFolder.length > 0 &&
    phrase.length > 0;

  const handleSubmit = async () => {
    if (!complete) return;
    setPending(true);
    setError(null);
    setResult(null);
    try {
      setResult(
        await runSetup({
          profile_id: profileId,
          rfc,
          source_folder: sourceFolder,
          phrase,
          certificate_path: certificatePath || undefined,
          private_key_path: privateKeyPath || undefined,
          credential_mode: credentialMode,
        }),
      );
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
    <Section title="FIEL setup">
      <div className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Field
          id="setup-profile-id"
          label="Profile ID"
          placeholder="default"
          value={profileId}
          onChange={setProfileId}
        />
        <Field
          id="setup-rfc"
          label="RFC"
          placeholder="RFC"
          value={rfc}
          onChange={setRfc}
        />
        <Field
          id="setup-source-folder"
          label="Source folder"
          placeholder="C:\path\to\fiel"
          helper="Filesystem path on the machine running the panel API."
          value={sourceFolder}
          onChange={setSourceFolder}
        />
        <div>
          <label
            htmlFor="setup-credential-mode"
            className="mb-1 block text-sm text-zinc-600 dark:text-zinc-400"
          >
            Credential mode
          </label>
          <select
            id="setup-credential-mode"
            className="w-full rounded border border-zinc-300 bg-transparent px-3 py-2 text-sm dark:border-zinc-700"
            value={credentialMode}
            onChange={(e) => setCredentialMode(e.target.value as CredentialMode)}
          >
            <option value="copied">copied</option>
            <option value="referenced">referenced</option>
          </select>
        </div>
        <Field
          id="setup-certificate-path"
          label="Certificate path (optional)"
          placeholder="C:\path\to\certificate.cer"
          value={certificatePath}
          onChange={setCertificatePath}
        />
        <Field
          id="setup-private-key-path"
          label="Private key path (optional)"
          placeholder="C:\path\to\private-key.key"
          value={privateKeyPath}
          onChange={setPrivateKeyPath}
        />
        <Field
          id="setup-phrase"
          label="Private-key phrase"
          type="password"
          helper="Sent once with this request, then cleared. Never stored by the panel."
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
        {pending ? "Running setup..." : "Run setup"}
      </button>

      {error && <p className="text-sm text-red-500">{error}</p>}

      {result && (
        // Everything shown here comes from the response. The RFC arrives
        // already redacted by the backend, and nothing the operator typed is
        // echoed back.
        <dl className="divide-y divide-zinc-200 rounded border border-zinc-200 text-sm dark:divide-zinc-800 dark:border-zinc-800">
          <div className="flex justify-between gap-4 px-3 py-2">
            <dt className="font-medium text-zinc-600 dark:text-zinc-400">
              profile_id
            </dt>
            <dd className="text-right break-all">{result.profile_id}</dd>
          </div>
          <div className="flex justify-between gap-4 px-3 py-2">
            <dt className="font-medium text-zinc-600 dark:text-zinc-400">
              rfc (redacted)
            </dt>
            <dd className="text-right break-all">{result.rfc}</dd>
          </div>
          <div className="flex justify-between gap-4 px-3 py-2">
            <dt className="font-medium text-zinc-600 dark:text-zinc-400">
              credential_mode
            </dt>
            <dd className="text-right break-all">{result.credential_mode}</dd>
          </div>
          <div className="flex justify-between gap-4 px-3 py-2">
            <dt className="font-medium text-zinc-600 dark:text-zinc-400">
              credentials_imported
            </dt>
            <dd className="text-right">
              {String(result.credentials_imported)}
            </dd>
          </div>
          <div className="flex justify-between gap-4 px-3 py-2">
            <dt className="font-medium text-zinc-600 dark:text-zinc-400">
              phrase_stored
            </dt>
            <dd className="text-right">{String(result.phrase_stored)}</dd>
          </div>
        </dl>
      )}
    </Section>
  );
}
