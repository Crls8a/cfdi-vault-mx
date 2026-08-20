"use client";

import { useState } from "react";
import { ApiError, deleteSecret, registerSecret, verifySecret } from "@/lib/api";
import { Field } from "./Field";
import { Section } from "./Section";

type Mode = "register" | "delete" | "verify";

type SecretResult =
  | { mode: "register"; reference: string; kind: string }
  | { mode: "delete"; reference: string; kind: string; deleted: boolean }
  | { mode: "verify"; reference: string; kind: string; exists: boolean };

const MODES: { id: Mode; label: string }[] = [
  { id: "register", label: "Register" },
  { id: "delete", label: "Delete" },
  { id: "verify", label: "Verify" },
];

/**
 * Credential-reference management.
 *
 * The registered `value` carries raw credential material and gets the same
 * treatment as the FIEL phrase: masked, `autoComplete="off"`, POST body only,
 * never handed to `console.*`, never written to `localStorage`,
 * `sessionStorage`, or a cookie, and cleared from state as soon as the request
 * settles — success or failure.
 *
 * Delete is deliberately not gated by a typed confirmation. ADR 0006 gates the
 * direction that grants access; removing a reference grants nothing and fails
 * closed, and gating it would train operators to type confirmations reflexively.
 */
export function SecretCard() {
  const [mode, setMode] = useState<Mode>("register");
  const [reference, setReference] = useState("");
  const [kind, setKind] = useState("generic");
  const [purpose, setPurpose] = useState("");
  const [value, setValue] = useState("");
  const [result, setResult] = useState<SecretResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const handleModeChange = (next: Mode) => {
    setMode(next);
    setResult(null);
    setError(null);
    // Never carry a typed credential value across a mode switch.
    setValue("");
  };

  const complete =
    reference.length > 0 && (mode !== "register" || value.length > 0);

  const handleSubmit = async () => {
    if (!complete) return;
    setPending(true);
    setError(null);
    setResult(null);
    try {
      if (mode === "register") {
        const response = await registerSecret({
          reference,
          value,
          kind: kind || undefined,
          purpose: purpose || undefined,
        });
        setResult({ mode: "register", ...response });
      } else if (mode === "delete") {
        const response = await deleteSecret({
          reference,
          kind: kind || undefined,
          purpose: purpose || undefined,
        });
        setResult({ mode: "delete", ...response });
      } else {
        const response = await verifySecret(reference, kind || "generic");
        setResult({ mode: "verify", ...response });
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "request failed");
    } finally {
      // Drop the credential value the instant the request settles.
      setValue("");
      setPending(false);
    }
  };

  const actionLabel =
    mode === "register" ? "Register" : mode === "delete" ? "Delete" : "Verify";

  return (
    <Section title="Credential references">
      <div className="mb-4 flex gap-2">
        {MODES.map((entry) => (
          <button
            key={entry.id}
            type="button"
            aria-pressed={mode === entry.id}
            className={`rounded border px-3 py-1 text-xs font-medium ${
              mode === entry.id
                ? "border-zinc-900 bg-zinc-900 text-white dark:border-zinc-100 dark:bg-zinc-100 dark:text-zinc-900"
                : "border-zinc-300 dark:border-zinc-700"
            }`}
            onClick={() => handleModeChange(entry.id)}
          >
            {entry.label}
          </button>
        ))}
      </div>

      <div className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Field
          id="secret-reference"
          label="Reference"
          placeholder="windows-credential-manager://cfdi-vault/..."
          value={reference}
          onChange={setReference}
        />
        <Field
          id="secret-kind"
          label="Kind"
          placeholder="generic"
          value={kind}
          onChange={setKind}
        />
        {mode !== "verify" && (
          <Field
            id="secret-purpose"
            label="Purpose (optional)"
            placeholder="why this call is being made"
            value={purpose}
            onChange={setPurpose}
          />
        )}
        {mode === "register" && (
          <Field
            id="secret-value"
            label="Value"
            type="password"
            helper="Sent once with this request, then cleared. Never stored by the panel."
            value={value}
            onChange={setValue}
          />
        )}
      </div>

      <button
        type="button"
        className="mb-3 rounded bg-zinc-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900"
        disabled={pending || !complete}
        onClick={handleSubmit}
      >
        {pending ? `${actionLabel}...` : actionLabel}
      </button>

      {error && <p className="text-sm text-red-500">{error}</p>}

      {result && (
        // Register echoes back the reference and kind only — never the value.
        <dl className="divide-y divide-zinc-200 rounded border border-zinc-200 text-sm dark:divide-zinc-800 dark:border-zinc-800">
          <div className="flex justify-between gap-4 px-3 py-2">
            <dt className="font-medium text-zinc-600 dark:text-zinc-400">
              reference
            </dt>
            <dd className="text-right font-mono break-all">
              {result.reference}
            </dd>
          </div>
          <div className="flex justify-between gap-4 px-3 py-2">
            <dt className="font-medium text-zinc-600 dark:text-zinc-400">
              kind
            </dt>
            <dd className="text-right break-all">{result.kind}</dd>
          </div>
          {result.mode === "delete" && (
            <div className="flex justify-between gap-4 px-3 py-2">
              <dt className="font-medium text-zinc-600 dark:text-zinc-400">
                deleted
              </dt>
              <dd className="text-right">{String(result.deleted)}</dd>
            </div>
          )}
          {result.mode === "verify" && (
            <div className="flex justify-between gap-4 px-3 py-2">
              <dt className="font-medium text-zinc-600 dark:text-zinc-400">
                exists
              </dt>
              <dd className="text-right">{String(result.exists)}</dd>
            </div>
          )}
        </dl>
      )}
    </Section>
  );
}
