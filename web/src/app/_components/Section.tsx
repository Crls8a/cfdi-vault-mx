/**
 * Card shell shared by every dashboard section.
 *
 * Extracted from `page.tsx` unchanged so the credential/authorization cards in
 * this folder render identically to the ones already on the dashboard.
 */
export function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-lg border border-zinc-200 bg-white p-5 dark:border-zinc-800 dark:bg-zinc-950">
      <h2 className="mb-4 text-lg font-medium">{title}</h2>
      {children}
    </section>
  );
}
