/** The approved B1 evaluation interval is exactly one UTC day from its clock. */
export function phase10ReportWindow(
  clock: string,
): Readonly<{ from: string; to: string }> {
  const fromMs = Date.parse(clock);
  if (!Number.isFinite(fromMs))
    throw new Error("PHASE10_MANIFEST_CLOCK_INVALID");
  return Object.freeze({
    from: new Date(fromMs).toISOString(),
    to: new Date(fromMs + 24 * 60 * 60 * 1_000).toISOString(),
  });
}
