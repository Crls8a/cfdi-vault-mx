"use client";

import { useState } from "react";
import {
  ApiError,
  CampaignAuthorizeResponse,
  authorizeCampaign,
} from "@/lib/api";
import { Field } from "./Field";
import { Section } from "./Section";

/**
 * Authorize exactly one grant, behind ADR 0006's typed-confirmation gate.
 *
 * One human request produces one grant. Nothing here schedules, retries, or
 * renews — that is the part of ADR 0004 the panel is not allowed to weaken.
 *
 * The value rules for phase, `expires_days` and reason live in
 * `authorize_campaign` on the backend and come back as `campaign-grant-*`
 * reason codes. The 1-14 bounds on the number input are an affordance; they are
 * deliberately not re-implemented as client-side validation, because a second
 * copy of the rule would drift from the one that actually decides.
 */
export function CampaignAuthorizeCard() {
  const [profileId, setProfileId] = useState("");
  const [campaignRef, setCampaignRef] = useState("");
  const [phase, setPhase] = useState("");
  const [expiresDays, setExpiresDays] = useState("1");
  const [reason, setReason] = useState("");
  const [confirm, setConfirm] = useState("");
  const [result, setResult] = useState<CampaignAuthorizeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  // Exact string equality against the campaign ref, mirroring the backend.
  const confirmed = campaignRef.length > 0 && confirm === campaignRef;
  const complete =
    profileId.length > 0 &&
    phase.length > 0 &&
    reason.length > 0 &&
    expiresDays.length > 0;

  const handleAuthorize = async () => {
    if (!confirmed || !complete) return;
    setPending(true);
    setError(null);
    setResult(null);
    try {
      setResult(
        await authorizeCampaign(profileId, campaignRef, {
          confirm,
          phase,
          expires_days: Number(expiresDays),
          reason,
        }),
      );
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "request failed");
    } finally {
      setPending(false);
    }
  };

  return (
    <Section title="Authorize campaign grant">
      <div className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Field
          id="campaign-authorize-profile-id"
          label="Profile ID"
          placeholder="profile id"
          value={profileId}
          onChange={setProfileId}
        />
        <Field
          id="campaign-authorize-campaign-ref"
          label="Campaign ref"
          placeholder="campaign ref"
          value={campaignRef}
          onChange={setCampaignRef}
        />
        <Field
          id="campaign-authorize-phase"
          label="Phase"
          placeholder="metadata-proof"
          value={phase}
          onChange={setPhase}
        />
        <Field
          id="campaign-authorize-expires-days"
          label="Expires (days)"
          type="number"
          min={1}
          max={14}
          helper="1-14 days."
          value={expiresDays}
          onChange={setExpiresDays}
        />
        <Field
          id="campaign-authorize-reason"
          label="Reason"
          placeholder="why this grant exists"
          value={reason}
          onChange={setReason}
        />
        <Field
          id="campaign-authorize-confirm"
          label="Confirm"
          placeholder="repeat the campaign ref"
          helper="Type the campaign ref exactly to confirm."
          value={confirm}
          onChange={setConfirm}
        />
      </div>

      <button
        type="button"
        className="mb-3 rounded bg-zinc-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900"
        disabled={pending || !confirmed || !complete}
        onClick={handleAuthorize}
      >
        {pending ? "Authorizing..." : "Authorize"}
      </button>

      {error && <p className="text-sm text-red-500">{error}</p>}

      {result && (
        <dl className="divide-y divide-zinc-200 rounded border border-zinc-200 text-sm dark:divide-zinc-800 dark:border-zinc-800">
          <div className="flex justify-between gap-4 px-3 py-2">
            <dt className="font-medium text-zinc-600 dark:text-zinc-400">
              grant_ref
            </dt>
            <dd className="text-right font-mono break-all">
              {result.grant_ref}
            </dd>
          </div>
          <div className="flex justify-between gap-4 px-3 py-2">
            <dt className="font-medium text-zinc-600 dark:text-zinc-400">
              phase
            </dt>
            <dd className="text-right break-all">{result.phase}</dd>
          </div>
          <div className="flex justify-between gap-4 px-3 py-2">
            <dt className="font-medium text-zinc-600 dark:text-zinc-400">
              expires_at
            </dt>
            <dd className="text-right break-all">{result.expires_at}</dd>
          </div>
        </dl>
      )}
    </Section>
  );
}
