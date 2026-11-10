import { ListAppsCommand } from "@aws-sdk/client-amplify";
import { ago, all, load } from "@mws-dashboard/aws";
import { roleOptions } from "@mws-dashboard/aws/auto";
import { ActionForm, AwsIcon, Empty, ErrorNotice, List, Page, Pill, Sheet } from "@mws-dashboard/ui";
import { GitBranch } from "lucide-react";
import type { Metadata } from "next";

import { amplify, ICONS } from "../../lib/clients";
import { AppFields } from "../../lib/app-fields";
import { sourceIcon } from "../../lib/presets";
import { createApp } from "./actions";

export const metadata: Metadata = { title: "Amplify" };

export default async function Apps() {
  const apps = await load(async () => {
    const client = await amplify();
    return all((nextToken) => client.send(new ListAppsCommand({ maxResults: 100, nextToken })), (r) => r.apps, (r) => r.nextToken);
  });
  const roles = await roleOptions("amplify.amazonaws.com");
  const create = (
    <Sheet title="Create app" label="Create new app" testId="create-app">
      <ActionForm action={createApp} submit="Create app" testId="create-app">
        <AppFields names={apps.ok ? apps.value.map((a) => a.name!) : []} roles={roles} />
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title="All apps" actions={create}>
      {apps.ok ? (
        <List
          label="Apps"
          empty={<Empty icon={ICONS.amplify} action={create} />}
          rows={apps.value.map((a) => ({
            key: a.appId!,
            icon: <AwsIcon icon={sourceIcon(a.repository) ?? ICONS.amplify} size={22} />,
            title: a.name,
            subtitle: a.repository ? a.repository.replace(/^https:\/\/(www\.)?(github\.com|gitlab\.com|bitbucket\.org)\//, "") : a.defaultDomain,
            href: `/amplify/app?id=${a.appId}`,
            meta: (
              <>
                {a.productionBranch?.branchName && (
                  <Pill icon={<GitBranch size={11} />} tone={a.productionBranch.status === "FAILED" ? "bad" : "neutral"}>
                    {a.productionBranch.branchName}
                  </Pill>
                )}
                {a.platform === "WEB_COMPUTE" ? <Pill>SSR</Pill> : a.platform !== "WEB" && <Pill>{a.platform?.toLowerCase().replace("_", " ")}</Pill>}
                <span>{ago(a.updateTime)}</span>
              </>
            ),
          }))}
        />
      ) : (
        <ErrorNotice error={apps.error} />
      )}
    </Page>
  );
}
