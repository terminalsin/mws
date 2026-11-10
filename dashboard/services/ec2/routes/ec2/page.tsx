import { Page } from "@mws-dashboard/ui";
import type { Metadata } from "next";
import type { ReactNode } from "react";

import { GroupsView } from "../../lib/views/groups";
import { ImagesView } from "../../lib/views/images";
import { InstancesView } from "../../lib/views/instances";
import { KeysView } from "../../lib/views/keys";
import { SnapshotsView } from "../../lib/views/snapshots";
import { TemplatesView } from "../../lib/views/templates";
import { VolumesView } from "../../lib/views/volumes";
import { EC2_TABS, Ec2Nav } from "../../lib/widgets";

export const metadata: Metadata = { title: "EC2" };

type Props = { searchParams: Promise<{ tab?: string; owner?: string }> };

export default async function Ec2({ searchParams }: Props) {
  const { tab: asked = "instances", owner = "self" } = await searchParams;
  const tab = EC2_TABS.some((t) => t.id === asked) ? asked : "instances";
  const view: { body: ReactNode; actions?: ReactNode } =
    tab === "images"
      ? await ImagesView({ owner })
      : tab === "keys"
        ? await KeysView()
        : tab === "groups"
          ? await GroupsView()
          : tab === "volumes"
            ? await VolumesView()
            : tab === "snapshots"
              ? await SnapshotsView()
              : tab === "templates"
                ? await TemplatesView()
                : await InstancesView();
  return (
    <Page title={EC2_TABS.find((t) => t.id === tab)!.label} actions={view.actions}>
      <Ec2Nav tab={tab} />
      {view.body}
    </Page>
  );
}
