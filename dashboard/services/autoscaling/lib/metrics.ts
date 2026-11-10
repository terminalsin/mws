/** The predefined metrics a target tracking policy can follow. */
export const METRICS: [string, string][] = [
  ["ASGAverageCPUUtilization", "Average CPU utilization (%)"],
  ["ASGAverageNetworkIn", "Average network in (bytes)"],
  ["ASGAverageNetworkOut", "Average network out (bytes)"],
  ["ALBRequestCountPerTarget", "Requests per target"],
];
