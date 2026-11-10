export const RETENTION = [
  0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827,
  2192, 2557, 2922, 3288, 3653,
];
export const retentionLabel = (d: number) =>
  d === 0
    ? "Never expire"
    : d < 30
      ? `${d} days`
      : d < 365
        ? `${Math.round(d / 30)} months`
        : `${Math.round(d / 365)} years`;
