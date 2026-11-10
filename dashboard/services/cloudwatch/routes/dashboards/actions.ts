"use server";

import {
  DeleteDashboardsCommand,
  GetDashboardCommand,
  PutDashboardCommand,
} from "@aws-sdk/client-cloudwatch";
import {
  act,
  FieldError,
  region,
  required,
  text,
  type ActionResult,
} from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { cloudwatch } from "../../lib/clients";

const href = (name: string) =>
  `/dashboards/dashboard?${new URLSearchParams({ name })}`;

type Body = { widgets: Record<string, unknown>[]; [k: string]: unknown };

/** PutDashboard, reporting the validation messages it answers with. */
async function put(name: string, body: string, field = "body") {
  const out = await (await cloudwatch())
    .send(new PutDashboardCommand({ DashboardName: name, DashboardBody: body }))
    .catch((e: unknown) => {
      if (e instanceof Error && /DashboardBody|dashboard body/i.test(e.message))
        throw new FieldError(field, e.message, "server");
      throw e;
    });
  const warnings = (out.DashboardValidationMessages ?? []).map(
    (m) => `${m.DataPath}: ${m.Message}`,
  );
  return warnings;
}

function parse(source: string): Body {
  try {
    const body = JSON.parse(source) as Body;
    if (!body || typeof body !== "object" || !Array.isArray(body.widgets))
      throw new FieldError("body", "Needs a widgets list", "format", {
        format: "json",
      });
    return body;
  } catch (e) {
    if (e instanceof FieldError) throw e;
    throw new FieldError("body", "Not valid JSON", "format", {
      format: "json",
    });
  }
}

async function current(name: string): Promise<Body> {
  const out = await (
    await cloudwatch()
  ).send(new GetDashboardCommand({ DashboardName: name }));
  return JSON.parse(out.DashboardBody || '{"widgets":[]}') as Body;
}

const saved = (what: string, warnings: string[]): ActionResult => ({
  ok: true,
  message: warnings.length
    ? `${what} with ${warnings.length} warning${warnings.length > 1 ? "s" : ""}`
    : what,
  detail: warnings.join("\n") || undefined,
});

export async function createDashboard(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const name = required(form, "name", "Name");
      const body = text(form, "body") || '{"widgets":[]}';
      parse(body);
      await put(name, body);
      redirect(href(name));
    },
    { fields: { DashboardName: "name", DashboardBody: "body" } },
  );
}

export async function saveSource(
  name: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const body = required(form, "body", "Source");
      parse(body);
      return saved("Saved", await put(name, body));
    },
    {
      revalidate: ["/dashboards/dashboard", "/dashboards"],
      fields: { DashboardBody: "body" },
    },
  );
}

/** The next free row below every widget, so a new one goes at the bottom. */
const bottom = (body: Body) =>
  body.widgets.reduce(
    (y, w) => Math.max(y, Number(w.y ?? 0) + Number(w.height ?? 6)),
    0,
  );

export async function addMetricWidget(
  name: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const body = await current(name);
      const dims = text(form, "dims")
        .split(/[\n,]+/)
        .map((p) => p.trim())
        .filter(Boolean)
        .flatMap((p) => [
          p.slice(0, p.indexOf("=")).trim(),
          p.slice(p.indexOf("=") + 1).trim(),
        ]);
      if (dims.some((d) => !d))
        throw new FieldError("dims", "Like Name=value", "format", {
          format: "pairs",
        });
      const stat = text(form, "stat") || "Average";
      body.widgets.push({
        type: "metric",
        x: 0,
        y: bottom(body),
        width: Number(text(form, "width") || 12),
        height: 6,
        properties: {
          metrics: [
            [
              required(form, "namespace", "Namespace"),
              required(form, "metric", "Metric"),
              ...dims,
            ],
          ],
          view: text(form, "view") || "timeSeries",
          stat,
          period: Number(text(form, "period") || 300),
          region: await region(),
          title: text(form, "title") || undefined,
        },
      });
      return saved(
        "Added widget",
        await put(name, JSON.stringify(body), "namespace"),
      );
    },
    {
      revalidate: ["/dashboards/dashboard"],
      fields: { DashboardBody: "namespace" },
    },
  );
}

export async function addTextWidget(
  name: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const body = await current(name);
      body.widgets.push({
        type: "text",
        x: 0,
        y: bottom(body),
        width: Number(text(form, "width") || 24),
        height: 3,
        properties: { markdown: required(form, "markdown", "Text") },
      });
      return saved(
        "Added text",
        await put(name, JSON.stringify(body), "markdown"),
      );
    },
    {
      revalidate: ["/dashboards/dashboard"],
      fields: { DashboardBody: "markdown" },
    },
  );
}

export async function addAlarmWidget(
  name: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const body = await current(name);
      const alarms = form.getAll("alarms").map(String).filter(Boolean);
      if (!alarms.length)
        throw new FieldError("alarms", "Pick at least one alarm", "required");
      body.widgets.push({
        type: "alarm",
        x: 0,
        y: bottom(body),
        width: 12,
        height: 4,
        properties: { title: text(form, "title") || "Alarms", alarms },
      });
      return saved(
        "Added alarms",
        await put(name, JSON.stringify(body), "alarms"),
      );
    },
    { revalidate: ["/dashboards/dashboard"] },
  );
}

export async function removeWidget(name: string, index: number) {
  return act(async () => {
    const body = await current(name);
    body.widgets.splice(index, 1);
    await put(name, JSON.stringify(body));
    return "Removed widget";
  }, "/dashboards/dashboard");
}

export async function deleteDashboard(name: string, leave: boolean) {
  return act(async () => {
    await (
      await cloudwatch()
    ).send(new DeleteDashboardsCommand({ DashboardNames: [name] }));
    if (leave) redirect("/dashboards");
    return `Deleted ${name}`;
  }, "/dashboards");
}
