import type { RouteTable } from "@aws-sdk/client-ec2";
import { ActionForm, AwsIcon, List, Sheet, Status } from "@mws-dashboard/ui";
import { Pencil, Plus, Trash2 } from "lucide-react";

import { addRoute, deleteRoute, replaceRoute } from "../routes/vpc/actions";
import { ICONS } from "./clients";
import { RouteFields } from "./network-forms";
import { routeTarget } from "./routes";

const TARGET_ICON: [string, string][] = [
  ["igw-", ICONS.internet],
  ["nat-", ICONS.nat],
  ["vpce-", ICONS.endpoint],
  ["pcx-", ICONS.peering],
  ["tgw-", ICONS.tgw],
  ["vgw-", ICONS.vgw],
  ["eni-", ICONS.eni],
  ["i-", ICONS.instance],
  ["eigw-", ICONS.igw],
  ["cagw-", ICONS.carrier],
];

/** Where a route's target is shown in the console. */
export function targetHref(target: string, vpc: string | undefined) {
  if (target.startsWith("i-")) return `/ec2/instance?id=${target}`;
  if (target.startsWith("vpce-")) return `/vpc/endpoint?id=${target}`;
  if (target.startsWith("pcx-")) return `/vpc/peering?id=${target}`;
  if (target.startsWith("nat-")) return "/vpc?tab=nat";
  if (target.startsWith("igw-")) return "/vpc?tab=igw";
  return vpc ? `/vpc/${vpc}` : undefined;
}

export function AddRoute({ table, targets }: { table: RouteTable; targets: string[] }) {
  const id = table.RouteTableId!;
  const taken = (table.Routes ?? []).flatMap((r) => [r.DestinationCidrBlock, r.DestinationIpv6CidrBlock, r.DestinationPrefixListId].filter((x): x is string => !!x));
  return (
    <Sheet title="Add route" label={`Add route to ${id}`} icon={<Plus size={16} />} testId={`add-route-${id}`}>
      <ActionForm action={addRoute.bind(null, id)} submit="Add route" testId={`add-route-${id}`}>
        <RouteFields taken={taken} targets={targets} />
      </ActionForm>
    </Sheet>
  );
}

/** A table's routes: blackholes flagged, every route but the local one
 * editable (ReplaceRoute) and deletable, whatever its destination kind. */
export function Routes({ table, targets }: { table: RouteTable; targets: string[] }) {
  const id = table.RouteTableId!;
  return (
    <List
      label={`Routes of ${id}`}
      rows={(table.Routes ?? []).map((r) => {
        const dest = r.DestinationCidrBlock ?? r.DestinationIpv6CidrBlock ?? r.DestinationPrefixListId ?? "";
        const target = routeTarget(r);
        const icon = TARGET_ICON.find(([p]) => target.startsWith(p))?.[1] ?? ICONS.vpc;
        // Propagated routes and a gateway endpoint's prefix-list routes are
        // managed by their source, as in AWS.
        const managed = target === "local" || r.Origin === "EnableVgwRoutePropagation" || (target.startsWith("vpce-") && !!r.DestinationPrefixListId);
        return {
          key: dest,
          icon: <AwsIcon icon={icon} size={20} />,
          title: <code>{dest}</code>,
          subtitle: target,
          meta: (
            <>
              {r.Origin === "EnableVgwRoutePropagation" && <span>propagated</span>}
              {r.State === "blackhole" && <Status tone="bad">Blackhole</Status>}
            </>
          ),
          actions: managed ? undefined : (
            <>
              <Sheet title={`Edit route ${dest}`} label={`Edit route ${dest}`} icon={<Pencil size={15} />}>
                <ActionForm action={replaceRoute.bind(null, id, dest)} submit="Save">
                  <RouteFields taken={[]} targets={targets} destination={dest} target={target} />
                </ActionForm>
              </Sheet>
              <ActionForm action={deleteRoute.bind(null, id, dest)} submit={`Delete route ${dest}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete the route to ${dest}?`} />
            </>
          ),
        };
      })}
    />
  );
}
