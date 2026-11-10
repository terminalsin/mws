import "server-only";

import {
  FilterLogEventsCommand,
  type FilteredLogEvent,
} from "@aws-sdk/client-cloudwatch-logs";
import { mws } from "@mws-dashboard/aws";

import { logs } from "./clients";

/** MWS's emulated clock, in milliseconds (event timestamps follow it). */
export async function clockNow(): Promise<number> {
  try {
    return new Date((await mws<{ now: string }>("/_mws/clock")).now).getTime();
  } catch {
    return Date.now();
  }
}

const CAP = 20_000;
const MINUTE = 60_000;
const SPANS = [
  5 * MINUTE,
  60 * MINUTE,
  24 * 60 * MINUTE,
  7 * 24 * 60 * MINUTE,
  30 * 24 * 60 * MINUTE,
  Infinity,
];

export interface Query {
  group: string;
  streams?: string[];
  prefix?: string;
  pattern?: string;
  /** Only events before this time (exclusive): the next page of older events. */
  before?: number;
  /** Only events at or after this time. */
  after?: number;
}

/** Every matching event in [start, end), oldest first, up to CAP. */
async function window(
  q: Query,
  start: number | undefined,
  end: number | undefined,
) {
  const client = await logs();
  const events: FilteredLogEvent[] = [];
  let nextToken: string | undefined;
  do {
    const out = await client.send(
      new FilterLogEventsCommand({
        logGroupName: q.group,
        nextToken,
        limit: 10_000,
        startTime: start,
        endTime: end,
        ...(q.streams?.length
          ? { logStreamNames: q.streams }
          : q.prefix
            ? { logStreamNamePrefix: q.prefix }
            : {}),
        ...(q.pattern ? { filterPattern: q.pattern } : {}),
      }),
    );
    events.push(...(out.events ?? []));
    nextToken = out.nextToken;
  } while (nextToken && events.length < CAP);
  return { events, truncated: !!nextToken };
}

/** The newest `limit` matching events, newest first. FilterLogEvents
 * answers oldest first, so this widens a window back from the end until it
 * holds enough events (and narrows it when a window holds too many to read),
 * then keeps the newest, never splitting one millisecond across pages. */
export async function newestEvents(
  q: Query,
  limit = 200,
): Promise<{ events: FilteredLogEvent[]; older?: number }> {
  const end = q.before ?? (await clockNow());
  for (const span of SPANS) {
    let start =
      span === Infinity ? q.after : Math.max(end - span, q.after ?? -Infinity);
    let got = await window(q, start, q.before);
    // Too many to read in one go: shrink the window towards the end.
    let width =
      span === Infinity ? end - (got.events[0]?.timestamp ?? end) : span;
    while (got.truncated && width > 1000) {
      width = Math.floor(width / 4);
      start = end - width;
      got = await window(q, start, q.before);
    }
    const reachedStart = start === undefined || start === q.after;
    if (got.events.length >= limit || reachedStart || got.truncated) {
      const all = got.events;
      let cut = Math.max(0, all.length - limit);
      // Keep every event of the oldest millisecond shown on this page.
      while (cut > 0 && all[cut - 1].timestamp === all[cut].timestamp) cut--;
      const page = all.slice(cut).reverse();
      const oldest = page[page.length - 1]?.timestamp;
      const more = cut > 0 || !reachedStart;
      return {
        events: page,
        older: more && oldest !== undefined ? oldest : undefined,
      };
    }
  }
  return { events: [] };
}
