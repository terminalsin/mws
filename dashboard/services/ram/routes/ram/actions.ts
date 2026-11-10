"use server";

import { AcceptResourceShareInvitationCommand, CreateResourceShareCommand, DeleteResourceShareCommand, RejectResourceShareInvitationCommand } from "@aws-sdk/client-ram";
import { act, FieldError, frameInfo, required, text, type ActionResult } from "@mws-dashboard/aws";
import { closest, type Repair } from "@mws-dashboard/ui/validation";
import { redirect } from "next/navigation";

import { ram, shareTargets } from "../../lib/clients";

const lines = (s: string) => s.split(/[\s,]+/).filter(Boolean);

// RAM names the resource or principal it rejects; these put the problem on
// that item of its list field, in a few words. (Principals outside the
// organization stay under the form: the fix is the checkbox, not the item.)
const REJECTIONS: [RegExp, string, "missing" | "server"][] = [
  [/could not be found/, "Not found", "missing"],
  [/can't be shared with AWS RAM/, "Can't be shared with RAM", "server"],
  [/is not valid/, "Not a valid ARN", "server"],
  [/is malformed/, "Not an account, ARN or service", "server"],
  [/Your account doesn't own/, "Owned by another account", "server"],
  [/IAM roles and users only inside/, "Roles and users only inside your organization", "server"],
  [/sharing with AWS Organizations is not enabled/, "Organization sharing is off", "server"],
  [/only with your own organization/, "Not your organization", "server"],
  [/owner can't be a principal/, "That's your own account", "server"],
];

const short = (v: string) => (v.length > 32 ? `…${v.split(/[:/]/).pop()!.slice(-28)}` : v);

async function rejected(e: unknown, resources: string[], principals: string[]): Promise<FieldError | null> {
  if (!(e instanceof Error)) return null;
  const rule = REJECTIONS.find(([re]) => re.test(e.message));
  if (!rule) return null;
  const [, message, code] = rule;
  const own = /owner can't be a principal/.test(e.message) ? (await frameInfo()).account : null;
  const named = (v: string) => (own ? v === own : e.message.includes(v));
  // The longest match wins: an account ID is also part of its role ARNs.
  const hit = (list: string[]) => list.filter(named).sort((a, b) => b.length - a.length)[0];
  const organization = /Organizations is not enabled/.test(e.message) ? principals.find((p) => p.startsWith("arn:aws:organizations")) : undefined;
  const principal = hit(principals) ?? organization;
  const resource = hit(resources);
  const [field, value, list] = resource && (!principal || resource.length > principal.length) ? (["resources", resource, resources] as const) : principal ? (["principals", principal, principals] as const) : [];
  if (!field || !value || !list) return null;
  // The item it was probably meant to be, or the list without it.
  const targets = code === "missing" ? await shareTargets() : null;
  const at = (v: string | null) => list.flatMap((x) => (x === value ? (v === null ? [] : [v]) : [x])).join("\n");
  const repairs: Repair[] = closest(value, targets?.[field] ?? [], 2).map((v) => ({ value: at(v), label: `Did you mean ${short(v)}?`, kind: "suggest" }));
  if (list.length > 1) repairs.push({ value: at(null), label: `Remove ${short(value)}`, kind: "fix" });
  return new FieldError(field, `${short(value)}: ${message}`, code, undefined, repairs);
}

export async function createShare(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const resourceArns = lines(text(form, "resources"));
    const principals = lines(text(form, "principals"));
    const name = required(form, "name", "Name");
    const out = await (await ram())
      .send(new CreateResourceShareCommand({ name, resourceArns, principals, allowExternalPrincipals: text(form, "external") === "on" }))
      .catch(async (e: unknown) => {
        throw (await rejected(e, resourceArns, principals)) ?? e;
      });
    redirect(`/ram/share?arn=${encodeURIComponent(out.resourceShare!.resourceShareArn!)}`);
  });
}

export async function deleteShare(arn: string) {
  return act(async () => {
    await (await ram()).send(new DeleteResourceShareCommand({ resourceShareArn: arn }));
    redirect("/ram");
  });
}

export async function answerInvitation(arn: string, accept: boolean) {
  return act(async () => {
    const client = await ram();
    if (accept) await client.send(new AcceptResourceShareInvitationCommand({ resourceShareInvitationArn: arn }));
    else await client.send(new RejectResourceShareInvitationCommand({ resourceShareInvitationArn: arn }));
    return accept ? "Accepted" : "Rejected";
  }, "/ram");
}
