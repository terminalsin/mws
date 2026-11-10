import { applications, stage } from "@mws-dashboard/ai";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AutoPick, AwsIcon, Curated, Empty, ErrorNotice, Field, Page, Pill, Sheet, Status, runtimeIcon } from "@mws-dashboard/ui";
import { CreateFunction } from "@mws-dashboard/ui/model/lambda";
import type { Metadata } from "next";

import { ICONS, RUNTIMES } from "../../lib/clients";
import { lambdaRoles, listFunctions } from "../../lib/lambda";
import { FUNCTION_NAME } from "../../lib/rules";
import { createFunction } from "./actions";

export const metadata: Metadata = { title: "Lambda" };

export default async function Functions() {
  const [functions, roles] = await Promise.all([load(listFunctions), load(lambdaRoles)]);
  const names = functions.ok ? functions.value.map((f) => f.FunctionName!) : [];
  const create = (
    <Sheet title="New function" label="Create function" testId="create-function">
      <ActionForm action={createFunction} submit="Create" testId="create-function">
        <Field label="Name" rule={FUNCTION_NAME} taken={names} unique>
          <input name="name" required autoFocus />
        </Field>
        <Field label="Runtime" rule={CreateFunction.Runtime}>
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
        <AutoPick name="role" label="Execution role" creates="<function>-role, writes logs" options={roles.ok ? roles.value.map((r) => ({ value: r.Arn!, label: r.RoleName! })) : []} testId="execution-role" />
      </ActionForm>
    </Sheet>
  );
  if (!functions.ok) {
    return (
      <Page title="Functions" actions={create}>
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
    <Page title="Functions" actions={create}>
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
