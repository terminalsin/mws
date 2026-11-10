import { ListSubscriptionsCommand } from "@aws-sdk/client-sns";
import { all, load } from "@mws-dashboard/aws";
import { ActionForm, Empty, ErrorNotice, List, Page, Status } from "@mws-dashboard/ui";
import { CheckCheck } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, sns } from "../../../lib/clients";
import { arnName } from "../../../lib/links";
import { Endpoint, pending, protocolIcon, SnsTabs } from "../../../lib/view";
import { confirmPending } from "../actions";

export const metadata: Metadata = { title: "Subscriptions" };

export default async function Subscriptions() {
  const subs = await load(async () => {
    const client = await sns();
    return all((NextToken) => client.send(new ListSubscriptionsCommand({ NextToken })), (r) => r.Subscriptions, (r) => r.NextToken);
  });
  return (
    <Page title="Subscriptions">
      <SnsTabs active="subscriptions" />
      {subs.ok ? (
        <List
          label="Subscriptions"
          empty={<Empty icon={ICONS.topic} />}
          rows={subs.value.map((s) => {
            const waiting = pending(s);
            return {
              key: `${s.SubscriptionArn}${s.TopicArn}${s.Endpoint}`,
              icon: protocolIcon(s.Protocol),
              title: <Endpoint sub={s} linked={waiting} />,
              subtitle: `${s.Protocol} · ${arnName(s.TopicArn)}`,
              href: waiting ? undefined : `/sns/subscription?arn=${encodeURIComponent(s.SubscriptionArn!)}`,
              meta: waiting ? <Status tone="warn">pending</Status> : <Status tone="good">confirmed</Status>,
              actions: waiting ? (
                <ActionForm action={confirmPending.bind(null, s.TopicArn!, s.Protocol!, s.Endpoint!)} submit={`Confirm ${s.Endpoint}`} icon={<CheckCheck size={16} aria-hidden />} />
              ) : undefined,
            };
          })}
        />
      ) : (
        <ErrorNotice error={subs.error} />
      )}
    </Page>
  );
}
