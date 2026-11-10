const days = (v: string) => {
  const n = Number(v.match(/\d+/)?.[0]);
  return [v, n === 1 ? "1 day after last access" : `${n} days after last access`] as [string, string];
};

/** TransitionToIA and TransitionToArchive values, in order. */
export const IA_OPTIONS = ["AFTER_1_DAY", "AFTER_7_DAYS", "AFTER_14_DAYS", "AFTER_30_DAYS", "AFTER_60_DAYS", "AFTER_90_DAYS", "AFTER_180_DAYS", "AFTER_270_DAYS", "AFTER_365_DAYS"].map(days);
export const ARCHIVE_OPTIONS = IA_OPTIONS;

export const label = (v: string | undefined) => (v ? (IA_OPTIONS.find(([k]) => k === v)?.[1] ?? v) : undefined);
