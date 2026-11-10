import { load } from "@mws-dashboard/aws";
import { ErrorNotice, Page } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { network } from "../../lib/vpc";
import { aclsTab, eipsTab, endpointsTab, igwTab, natTab, peeringTab, routesTab, subnetsTab, vpcsTab, type Tab } from "./tabs";

export const metadata: Metadata = { title: "VPC" };

type Props = { searchParams: Promise<{ tab?: string }> };

const TABS: Record<string, { title: string; render: Tab }> = {
  vpcs: { title: "Your VPCs", render: vpcsTab },
  subnets: { title: "Subnets", render: subnetsTab },
  routes: { title: "Route tables", render: routesTab },
  igw: { title: "Internet gateways", render: igwTab },
  nat: { title: "NAT gateways", render: natTab },
  eips: { title: "Elastic IPs", render: eipsTab },
  endpoints: { title: "Endpoints", render: endpointsTab },
  peering: { title: "Peering connections", render: peeringTab },
  acls: { title: "Network ACLs", render: aclsTab },
};

export default async function Vpcs({ searchParams }: Props) {
  const { tab = "vpcs" } = await searchParams;
  const { title, render } = TABS[tab] ?? TABS.vpcs;
  const net = await load(() => network());
  if (!net.ok) {
    return (
      <Page title={title}>
        <ErrorNotice error={net.error} />
      </Page>
    );
  }
  const { body, actions } = await render(net.value);
  return (
    <Page title={title} actions={actions}>
      {body}
    </Page>
  );
}
