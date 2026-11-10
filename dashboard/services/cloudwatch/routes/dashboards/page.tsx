import { ListDashboardsCommand } from "@aws-sdk/client-cloudwatch";
import { ago, all, bytes, load, region } from "@mws-dashboard/aws";
import {
  ActionForm,
  AwsIcon,
  Empty,
  ErrorNotice,
  List,
  Page,
  Sheet,
} from "@mws-dashboard/ui";
import { Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { formOptions } from "../../lib/alarms";
import { cloudwatch } from "../../lib/clients";
import { DashboardFields } from "../../lib/dashboard-fields";
import { createDashboard, deleteDashboard } from "./actions";

export const metadata: Metadata = { title: "Dashboards" };

export default async function Dashboards() {
  const list = await load(async () => {
    const c = await cloudwatch();
    return all(
      (NextToken) => c.send(new ListDashboardsCommand({ NextToken })),
      (r) => r.DashboardEntries,
      (r) => r.NextToken,
    );
  });
  const [here, { namespaces }] = await Promise.all([region(), formOptions()]);
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
        <DashboardFields taken={taken} region={here} namespaces={namespaces} />
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
            icon: <AwsIcon icon="service/AmazonCloudWatch" size={22} />,
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
