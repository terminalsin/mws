import "server-only";

import { mws } from "@mws-dashboard/aws";

/** MWS's emulated "now": Cost Explorer's data, anomalies and backfills run on
 * it, so the console's date ranges must too (the clock can be advanced from
 * the control page). Falls back to the wall clock. */
export async function mwsNow(): Promise<Date> {
  try {
    const clock = await mws<{ now: string }>("/_mws/clock");
    const d = new Date(clock.now);
    return Number.isNaN(d.getTime()) ? new Date() : d;
  } catch {
    return new Date();
  }
}

export const day = (d: Date) => d.toISOString().slice(0, 10);
export const addDays = (d: Date, n: number) => new Date(d.getTime() + n * 86_400_000);
export const monthStart = (d: Date, offset = 0) => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + offset, 1));

export const money = (n: number) => {
  // Fractions of a cent keep four digits; large amounts drop the cents.
  const digits = n > 0 && n < 0.01 ? 4 : Math.abs(n) >= 10_000 ? 0 : 2;
  return n.toLocaleString("en-US", { style: "currency", currency: "USD", minimumFractionDigits: digits, maximumFractionDigits: digits });
};
