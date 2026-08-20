"use client";

import { useState } from "react";
import { ApiError, CampaignRecord, createCampaign } from "@/lib/api";
import { Field } from "./Field";
import { RecordList } from "./RecordList";
import { Section } from "./Section";

/**
 * Create the fixed campaign behind ADR 0006's typed-confirmation gate.
 *
 * The disabled button is UX, not the control. The backend compares `confirm`
 * against the path `profile_id` as the first statement of its handler, so a
 * request that skips this panel entirely is rejected on the same line. Keeping
 * the check here too just means the operator finds out before the round trip.
 */
export function CampaignCreateCard() {
  const [profileId, setProfileId] = useState("");
  const [confirm, setConfirm] = useState("");
  const [result, setResult] = useState<CampaignRecord | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  // Exact string equality: case-sensitive, no trimming, no normalization —
  // the same comparison the backend performs (ADR 0006).
  const confirmed = profileId.length > 0 && confirm === profileId;

  const handleCreate = async () => {
    if (!confirmed) return;
    setPending(true);
    setError(null);
    setResult(null);
    try {
      setResult(await createCampaign(profileId, confirm));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "request failed");
    } finally {
      setPending(false);
    }
  };

  return (
    <Section title="Create campaign">
      <div className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Field
          id="campaign-create-profile-id"
          label="Profile ID"
          placeholder="profile id"
          value={profileId}
          onChange={setProfileId}
        />
        <Field
          id="campaign-create-confirm"
          label="Confirm"
          placeholder="repeat the profile id"
          helper="Type the profile ID exactly to confirm."
          value={confirm}
          onChange={setConfirm}
        />
      </div>

      <button
        type="button"
        className="mb-3 rounded bg-zinc-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900"
        disabled={pending || !confirmed}
        onClick={handleCreate}
      >
        {pending ? "Creating..." : "Create"}
      </button>

      {error && <p className="text-sm text-red-500">{error}</p>}
      {result && <RecordList record={result} />}
    </Section>
  );
}
