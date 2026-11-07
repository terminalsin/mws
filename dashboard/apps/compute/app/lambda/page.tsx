import { ListRolesCommand } from "@aws-sdk/client-iam";
import { applications, stage } from "@mws-dashboard/ai";
import { ago, collect, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, Page, Pill, Sheet, Status, runtimeIcon } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { ICONS, RUNTIMES, iam } from "../../lib/clients";
import { listFunctions } from "../../lib/lambda";
import { createFunction } from "./actions";

export const metadata: Metadata = { title: "Lambda" };

async function lambdaRoles() {
  const client = await iam();
  const roles = await collect((Marker) => client.send(new ListRolesCommand({ Marker })), (r) => r.Roles, (r) => (r.IsTruncated ? r.Marker : undefined));
  return roles.filter((r) => decodeURIComponent(r.AssumeRolePolicyDocument ?? "").includes("lambda.amazonaws.com"));
}

export default async function Functions() {
  const [functions, roles] = await Promise.all([load(listFunctions), load(lambdaRoles)]);
  const create = (
    <Sheet title="New function" label="Create function" testId="create-function">
      <ActionForm action={createFunction} submit="Create" testId="create-function">
        <Field label="Name">
          <input name="name" required pattern="[a-zA-Z0-9\-_]+" autoFocus />
        </Field>
        <Field label="Runtime">
          <select name="runtime" defaultValue="nodejs22.x">
            {RUNTIMES.map((r) => (
              <option key={r}>{r}</option>
            ))}
          </select>
        </Field>
        <Field label="Architecture">
          <select name="arch" defaultValue="arm64">
            <option>arm64</option>
            <option>x86_64</option>
          </select>
        </Field>
        <Field label="Execution role">
          <input name="role" required list="lambda-roles" defaultValue={roles.ok ? roles.value[0]?.Arn : undefined} />
        </Field>
        <datalist id="lambda-roles">{roles.ok && roles.value.map((r) => <option key={r.Arn} value={r.Arn} />)}</datalist>
      </ActionForm>
    </Sheet>
  );
  if (!functions.ok) {
    return (
      <Page title="Lambda" icon={ICONS.lambda} actions={create}>
        <ErrorNotice error={functions.error} />
      </Page>
    );
  }
  const items = functions.value.map((f) => ({ ...f, name: f.FunctionName!, text: `${f.FunctionName} ${f.Description ?? ""}` }));
  const apps = await applications(items);
  const grouped = new Set(apps.flatMap((a) => a.members.map((m) => m.FunctionArn)));
  const sections = [
    ...apps.map((a) => ({ id: a.name, title: a.name, items: a.members })),
    { id: "rest", title: apps.length ? "Other" : "Functions", items: items.filter((f) => !grouped.has(f.FunctionArn)) },
  ];
  return (
    <Page title="Lambda" icon={ICONS.lambda} actions={create}>
      <Curated
        label="Functions"
        sections={sections}
        empty={<Empty icon={ICONS.fn} />}
        row={(f) => {
          const env = stage(f.FunctionName!, f.tags);
          const logo = runtimeIcon(f.Runtime ?? (f.PackageType === "Image" ? "image" : undefined));
          return {
            key: f.FunctionArn!,
            icon: <AwsIcon icon={logo ?? ICONS.fn} size={22} label={f.Runtime} />,
            title: f.FunctionName,
            subtitle: f.Description,
            href: `/lambda/${encodeURIComponent(f.FunctionName!)}`,
            meta: (
              <>
                {f.State && f.State !== "Active" && <Status tone={f.State === "Failed" ? "bad" : "warn"}>{f.State}</Status>}
                {env && <Pill tone={env === "production" ? "info" : "neutral"}>{env}</Pill>}
                <span>{ago(f.LastModified)}</span>
              </>
            ),
          };
        }}
      />
    </Page>
  );
}
