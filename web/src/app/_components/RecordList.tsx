import type { CampaignRecord } from "@/lib/api";

/**
 * Defensive key/value rendering for campaign aggregates.
 *
 * The shape varies by campaign state, so nothing here assumes a fixed schema.
 */
export function RecordList({ record }: { record: CampaignRecord }) {
  return (
    <dl className="divide-y divide-zinc-200 rounded border border-zinc-200 text-sm dark:divide-zinc-800 dark:border-zinc-800">
      {Object.entries(record).map(([key, value]) => (
        <div key={key} className="flex justify-between gap-4 px-3 py-2">
          <dt className="font-medium text-zinc-600 dark:text-zinc-400">{key}</dt>
          <dd className="text-right break-all">
            {typeof value === "object" ? JSON.stringify(value) : String(value)}
          </dd>
        </div>
      ))}
    </dl>
  );
}
