import { ListDashboardsCommand } from "@aws-sdk/client-cloudwatch";
import { ago, all, bytes, load } from "@mws-dashboard/aws";
import {
  ActionForm,
  Empty,
  ErrorNotice,
  Field,
  List,
  Page,
  Sheet,
  type Rule,
} from "@mws-dashboard/ui";
import { PutDashboard } from "@mws-dashboard/ui/model/cloudwatch";
import { LayoutDashboard, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { cloudwatch } from "../../lib/clients";
import { createDashboard, deleteDashboard } from "./actions";

export const metadata: Metadata = { title: "Dashboards" };

// PutDashboard: "Dashboard names can contain only alphanumerics, dash (-) and underscore (_)."
const NAME: Rule = {
  ...PutDashboard.DashboardName,
  pattern: "^[A-Za-z0-9_-]+$",
  maxLength: 255,
  hint: "Letters, digits, - and _",
};

const STARTER = JSON.stringify(
  {
    widgets: [
      {
        type: "text",
        x: 0,
        y: 0,
        width: 24,
        height: 2,
        properties: { markdown: "# My dashboard" },
      },
    ],
  },
  null,
  2,
);

export default async function Dashboards() {
  const list = await load(async () => {
    const c = await cloudwatch();
    return all(
      (NextToken) => c.send(new ListDashboardsCommand({ NextToken })),
      (r) => r.DashboardEntries,
      (r) => r.NextToken,
    );
  });
  const taken = list.ok ? list.value.map((d) => d.DashboardName!) : [];
  const create = (
    <Sheet
      title="New dashboard"
      label="Create dashboard"
      testId="create-dashboard"
    >
      <ActionForm
        action={createDashboard}
        submit="Create"
        testId="create-dashboard"
      >
        <Field label="Name" rule={NAME} taken={taken} generate="name" unique>
          <input name="name" autoFocus />
        </Field>
        <Field
          label="Source"
          rule={{
            ...PutDashboard.DashboardBody,
            required: false,
            format: "json",
          }}
        >
          <textarea
            name="body"
            rows={8}
            className="code-editor"
            defaultValue={STARTER}
          />
        </Field>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title="Dashboards" actions={create}>
      {list.ok ? (
        <List
          label="Dashboards"
          empty={<Empty icon="service/AmazonCloudWatch" action={create} />}
          rows={list.value.map((d) => ({
            key: d.DashboardArn ?? d.DashboardName!,
            icon: <LayoutDashboard size={20} />,
            title: d.DashboardName,
            href: `/dashboards/dashboard?${new URLSearchParams({ name: d.DashboardName! })}`,
            meta: (
              <>
                {d.Size ? <span>{bytes(d.Size)}</span> : null}
                <span>{ago(d.LastModified)}</span>
              </>
            ),
            actions: (
              <ActionForm
                action={deleteDashboard.bind(null, d.DashboardName!, false)}
                submit={`Delete ${d.DashboardName}`}
                icon={<Trash2 size={15} />}
                tone="danger"
                confirm={`Delete ${d.DashboardName}?`}
              />
            ),
          }))}
        />
      ) : (
        <ErrorNotice error={list.error} />
      )}
    </Page>
  );
}
