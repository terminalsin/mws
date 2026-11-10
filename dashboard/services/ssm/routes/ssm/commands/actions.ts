"use server";

import { CancelCommandCommand, SendCommandCommand } from "@aws-sdk/client-ssm";
import { act, FieldError, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { ssm } from "../../../lib/clients";
import { parseTargets } from "../../../lib/status";

/** Run a command: the document, its parameters (`param:<name>` fields; a
 * StringList takes one value a line), and the nodes, picked or by targets. */
export async function sendCommand(document: string, listParams: string[], _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Parameters: Record<string, string[]> = {};
    for (const [k, v] of form.entries()) {
      if (!k.startsWith("param:") || typeof v !== "string" || v.trim() === "") continue;
      const name = k.slice(6);
      Parameters[name] = listParams.includes(name) ? v.split("\n").map((l) => l.replace(/\r$/, "")).filter((l) => l.trim() !== "") : [v];
    }
    const instances = form.getAll("instances").map(String).filter(Boolean);
    const targets = text(form, "targets");
    if (!instances.length && !targets) throw new FieldError("targets", "Choose nodes or give targets", "required");
    const timeout = Number(text(form, "timeout") || 0);
    const out = await (await ssm()).send(
      new SendCommandCommand({
        DocumentName: document,
        DocumentVersion: text(form, "version") || undefined,
        InstanceIds: instances.length ? instances : undefined,
        Targets: !instances.length && targets ? parseTargets(targets) : undefined,
        Parameters,
        Comment: text(form, "comment") || undefined,
        TimeoutSeconds: timeout || undefined,
        MaxConcurrency: text(form, "maxConcurrency") || undefined,
        MaxErrors: text(form, "maxErrors") || undefined,
      }),
    );
    redirect(`/ssm/command?id=${out.Command!.CommandId}`);
  }, {
    fields: {
      InstanceIds: "targets",
      Targets: "targets",
      InvalidInstanceId: "targets",
      InvalidTarget: "targets",
      Comment: "comment",
      TimeoutSeconds: "timeout",
      MaxConcurrency: "maxConcurrency",
      MaxErrors: "maxErrors",
      DocumentVersion: "version",
      InvalidDocumentVersion: "version",
    },
  });
}

export async function cancelCommand(id: string, instance?: string) {
  return act(async () => {
    await (await ssm()).send(new CancelCommandCommand({ CommandId: id, InstanceIds: instance ? [instance] : undefined }));
    return "Cancelling";
  }, "/ssm/command", "/ssm/commands");
}

/** Run the same command again, on the same nodes. */
export async function rerun(_: string, input: { DocumentName: string; DocumentVersion?: string; Parameters?: Record<string, string[]>; InstanceIds?: string[]; Targets?: { Key?: string; Values?: string[] }[]; Comment?: string; TimeoutSeconds?: number }) {
  return act(async () => {
    const out = await (await ssm()).send(new SendCommandCommand({ ...input, InstanceIds: input.InstanceIds?.length ? input.InstanceIds : undefined, Targets: input.Targets?.length ? input.Targets : undefined }));
    redirect(`/ssm/command?id=${out.Command!.CommandId}`);
  });
}
