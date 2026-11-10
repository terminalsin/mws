import { ListAppsCommand } from "@aws-sdk/client-amplify";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Sheet } from "@mws-dashboard/ui";
import { GitBranch } from "lucide-react";
import type { Metadata } from "next";

import { amplify, ICONS } from "../../lib/clients";
import { APP_NAME, BRANCH, CreateApp } from "../../lib/rules";
import { createApp } from "./actions";

export const metadata: Metadata = { title: "Amplify" };

export default async function Apps() {
  const apps = await load(async () => ((await (await amplify()).send(new ListAppsCommand({ maxResults: 100 }))).apps ?? []));
  const create = (
    <Sheet title="Create app" label="Create new app" testId="create-app">
      <ActionForm action={createApp} submit="Create app" testId="create-app">
        <Field label="App name" rule={APP_NAME}>
          <input name="name" required autoFocus />
        </Field>
        <Field label="Branch" rule={{ ...BRANCH, required: false }} member="branchName">
          <input name="branch" defaultValue="main" />
        </Field>
        <Field label="Repository" rule={CreateApp.repository} format="url">
          <input name="repository" placeholder="https://github.com/org/site (optional)" />
        </Field>
        <Field label="Access token" rule={CreateApp.accessToken} member="accessToken">
          <input name="token" type="password" autoComplete="off" />
        </Field>
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
            icon: <AwsIcon icon={ICONS.amplify} size={22} />,
            title: a.name,
            subtitle: a.repository ? a.repository.replace(/^https:\/\//, "") : a.defaultDomain,
            href: `/amplify/app?id=${a.appId}`,
            meta: (
              <>
                {a.productionBranch?.branchName && (
                  <Pill icon={<GitBranch size={11} />} tone={a.productionBranch.status === "FAILED" ? "bad" : "neutral"}>
                    {a.productionBranch.branchName}
                  </Pill>
                )}
                {a.platform !== "WEB" && <Pill>{a.platform?.toLowerCase().replace("_", " ")}</Pill>}
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
