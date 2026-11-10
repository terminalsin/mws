"use server";

import { AcceptResourceShareInvitationCommand, CreateResourceShareCommand, DeleteResourceShareCommand, RejectResourceShareInvitationCommand } from "@aws-sdk/client-ram";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { ram } from "../../lib/clients";

const lines = (s: string) => s.split(/[\s,]+/).filter(Boolean);

export async function createShare(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await ram()).send(
      new CreateResourceShareCommand({
        name: required(form, "name", "Name"),
        resourceArns: lines(text(form, "resources")),
        principals: lines(text(form, "principals")),
        allowExternalPrincipals: text(form, "external") === "on",
      }),
    );
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
