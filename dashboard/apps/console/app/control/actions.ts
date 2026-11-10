"use server";

import { act, mws, required, text, type ActionResult } from "@mws-dashboard/aws";

const PAGE = "/control";

function seconds(form: FormData): number {
  const amount = Number(required(form, "amount", "Amount"));
  const unit = text(form, "unit") || "seconds";
  const scale = { seconds: 1, minutes: 60, hours: 3600, days: 86400 }[unit] ?? 1;
  if (!Number.isFinite(amount) || amount <= 0) throw new Error("Amount must be a positive number");
  return Math.round(amount * scale);
}

export async function advanceClock(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const s = seconds(form);
    const clock = await mws<{ now: string }>("/_mws/clock", { method: "POST", json: { advanceSeconds: s } });
    return `Clock moved forward ${s}s; it is now ${clock.now}`;
  }, PAGE);
}

export async function resetClock(_: ActionResult | null) {
  return act(async () => {
    await mws("/_mws/clock", { method: "POST", json: { offsetSeconds: 0 } });
    return "Clock back to real time";
  }, PAGE);
}

export async function saveSnapshot(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Name");
    await mws(`/_mws/snapshots/${encodeURIComponent(name)}`, { method: "PUT" });
    return `Saved snapshot ${name}`;
  }, PAGE);
}

export async function restoreSnapshot(name: string) {
  return act(async () => {
    await mws(`/_mws/snapshots/${encodeURIComponent(name)}/restore`, { method: "POST" });
    return `Restored ${name}`;
  }, PAGE);
}

export async function deleteSnapshot(name: string) {
  return act(async () => {
    await mws(`/_mws/snapshots/${encodeURIComponent(name)}`, { method: "DELETE" });
    return `Deleted ${name}`;
  }, PAGE);
}

export async function reset(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const to = text(form, "to") === "empty" ? "empty" : "baseline";
    await mws(`/_mws/reset?to=${to}`, { method: "POST" });
    return to === "empty" ? "Every service is empty again" : "Back to the baseline";
  }, PAGE);
}

export async function importState(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const file = form.get("state");
    if (!(file instanceof File) || file.size === 0) throw new Error("Choose a state file");
    const body = await file.text();
    JSON.parse(body);
    await mws("/_mws/state", { method: "PUT", body, headers: { "content-type": "application/json" } });
    return `Imported ${file.name}`;
  }, PAGE);
}
