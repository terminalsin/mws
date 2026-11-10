import { ago, load } from "@mws-dashboard/aws";
import { Empty, ErrorNotice, List, Page, Pill } from "@mws-dashboard/ui";
import { Layers } from "lucide-react";
import type { Metadata } from "next";

import { layers } from "../../../lib/lambda";
import { PublishLayer } from "../../../lib/layers";
import { LambdaTabs } from "../../../lib/tabs";

export const metadata: Metadata = { title: "Layers" };

export default async function LayersPage() {
  const list = await load(layers);
  return (
    <Page title="Layers" actions={<PublishLayer names={list.ok ? list.value.map((l) => l.LayerName!) : []} />}>
      <LambdaTabs active="layers" />
      {list.ok ? (
        <List
          label="Layers"
          empty={<Empty icon="service/AWSLambda" />}
          rows={list.value.map((l) => {
            const v = l.LatestMatchingVersion;
            return {
              key: l.LayerArn!,
              icon: <Layers size={18} aria-hidden />,
              title: l.LayerName,
              subtitle: v?.Description,
              href: `/lambda/layers/${encodeURIComponent(l.LayerName!)}`,
              meta: (
                <>
                  {v?.CompatibleRuntimes?.slice(0, 3).map((r) => (
                    <Pill key={r}>{r}</Pill>
                  ))}
                  <Pill tone="info" title="Latest version">
                    v{v?.Version}
                  </Pill>
                  <span>{ago(v?.CreatedDate)}</span>
                </>
              ),
            };
          })}
        />
      ) : (
        <ErrorNotice error={list.error} />
      )}
    </Page>
  );
}
