"use server";

import { InvokeCommand } from "@aws-sdk/client-lambda";
import { act, text, type ActionResult } from "@mws-dashboard/aws";

import { lambda } from "../../lib/clients";

/** Invoke the function synchronously and show its response and log tail. */
export async function invoke(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const payload = text(form, "payload") || "{}";
    try {
      JSON.parse(payload);
    } catch {
      throw new Error("The payload must be JSON");
    }
    const out = await (await lambda()).send(
      new InvokeCommand({ FunctionName: name, Payload: new TextEncoder().encode(payload), LogType: "Tail" }),
    );
    const response = out.Payload ? new TextDecoder().decode(out.Payload) : "";
    let pretty = response;
    try {
      pretty = JSON.stringify(JSON.parse(response), null, 2);
    } catch {
      // not JSON
    }
    const logs = out.LogResult ? Buffer.from(out.LogResult, "base64").toString("utf8") : "";
    return {
      ok: !out.FunctionError,
      message: out.FunctionError
        ? `Function error (${out.FunctionError}), status ${out.StatusCode}`
        : `Status ${out.StatusCode}, version ${out.ExecutedVersion ?? "$LATEST"}`,
      detail: `${pretty}${logs ? `\n\n--- log tail ---\n${logs}` : ""}`,
    };
  });
}
