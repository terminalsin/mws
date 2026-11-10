// Alarm vocabulary shared by the server pages and the alarm form.

export const OP: Record<string, string> = {
  GreaterThanThreshold: ">",
  GreaterThanOrEqualToThreshold: "≥",
  LessThanThreshold: "<",
  LessThanOrEqualToThreshold: "≤",
  LessThanLowerOrGreaterThanUpperThreshold: "outside",
  LessThanLowerThreshold: "<",
  GreaterThanUpperThreshold: ">",
};

export const period = (s: number | undefined) =>
  !s
    ? ""
    : s % 86400 === 0
      ? `${s / 86400} d`
      : s % 3600 === 0
        ? `${s / 3600} h`
        : s % 60 === 0
          ? `${s / 60} min`
          : `${s} s`;

// Periods the AWS console offers; PutMetricAlarm takes 10, 20, 30 or any multiple of 60.
export const PERIODS: [number, string][] = [
  [10, "10 s"],
  [30, "30 s"],
  [60, "1 min"],
  [300, "5 min"],
  [900, "15 min"],
  [3600, "1 h"],
  [21600, "6 h"],
  [86400, "1 day"],
];

/** The statistics the console offers: the five standard ones, then the
 * common percentiles (sent as ExtendedStatistic). */
export const STATISTICS = [
  "Sum",
  "Average",
  "Maximum",
  "Minimum",
  "SampleCount",
  "p99",
  "p95",
  "p90",
  "p50",
];
