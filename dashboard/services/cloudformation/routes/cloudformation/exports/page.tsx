import { ListExportsCommand, ListImportsCommand } from "@aws-sdk/client-cloudformation";
import { all, load } from "@mws-dashboard/aws";
import { Empty, ErrorNotice, List, Page, Pill } from "@mws-dashboard/ui";
import { ArrowUpRight } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, cloudformation } from "../../../lib/clients";
import { CloudFormationNav, stackName } from "../../../lib/nav";

export const metadata: Metadata = { title: "Exports" };

/** Exported outputs and the stacks that import them: an import is what
 * blocks deleting or changing the exporting stack. */
export default async function Exports() {
  const data = await load(async () => {
    const client = await cloudformation();
    const exports = await all(
      (NextToken) => client.send(new ListExportsCommand({ NextToken })),
      (r) => r.Exports,
      (r) => r.NextToken,
    );
    const importers = await Promise.all(
      exports.map((e) =>
        all(
          (NextToken) => client.send(new ListImportsCommand({ ExportName: e.Name!, NextToken })),
          (r) => r.Imports,
          (r) => r.NextToken,
        ).catch(() => [] as string[]),
      ),
    );
    return exports.map((e, i) => ({ ...e, imports: importers[i] }));
  });
  return (
    <Page title="Exports">
      <CloudFormationNav active="exports" />
      {!data.ok ? (
        <ErrorNotice error={data.error} />
      ) : (
        <List
          label="Exports"
          empty={<Empty icon={ICONS.cloudformation} />}
          rows={data.value.map((e) => ({
            key: e.Name!,
            icon: <ArrowUpRight size={18} aria-hidden />,
            title: e.Name,
            subtitle: (
              <>
                <code className="clip">{e.Value}</code> · from {stackName(e.ExportingStackId)}
                {e.imports.length > 0 && <> · imported by {e.imports.join(", ")}</>}
              </>
            ),
            href: `/cloudformation/stack?name=${encodeURIComponent(e.ExportingStackId!)}&tab=outputs`,
            meta: e.imports.length > 0 ? <Pill tone="info">{e.imports.length} imports</Pill> : <Pill>not imported</Pill>,
          }))}
        />
      )}
    </Page>
  );
}
