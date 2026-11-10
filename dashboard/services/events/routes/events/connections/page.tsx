import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, Empty, ErrorNotice, Field, List, Page, Pill, Sheet, Status, type Tone } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { KeyRound, Trash2, Unplug } from "lucide-react";
import type { Metadata } from "next";

import { ConnectionAuthFields } from "../../../lib/connection-form";
import { API_KEY_NAME, API_KEY_VALUE, CONNECTION_NAME, PASSWORD, USERNAME } from "../../../lib/rules";
import { connections } from "../../../lib/targets";
import { EventsTabs } from "../../../lib/tabs";
import { createConnection, deauthorizeConnection, deleteConnection } from "../actions";

export const metadata: Metadata = { title: "Connections" };

const TONE: Record<string, Tone> = { AUTHORIZED: "good", DEAUTHORIZED: "neutral", AUTHORIZING: "info", DEAUTHORIZING: "info", CREATING: "info", UPDATING: "info", DELETING: "info", ACTIVE: "good" };

export default async function Connections() {
  const list = await load(connections);
  return (
    <Page
      title="Connections"
      actions={
        <Sheet title="New connection" label="Create connection" testId="create-connection">
          <ActionForm action={createConnection} submit="Create" testId="create-connection">
            <Field label="Name" rule={CONNECTION_NAME} taken={list.ok ? list.value.map((c) => c.Name!) : []} unique member="Name">
              <input name="name" required autoFocus spellCheck={false} />
            </Field>
            <Field label="Description">
              <input name="description" maxLength={512} />
            </Field>
            <ConnectionAuthFields rules={{ keyName: API_KEY_NAME, keyValue: API_KEY_VALUE, username: USERNAME, password: PASSWORD }} />
          </ActionForm>
        </Sheet>
      }
    >
      <EventsTabs active="connections" />
      {list.ok ? (
        <>
          <LiveRefresh when={list.value.some((c) => /ING$/.test(c.ConnectionState ?? ""))} />
          <List
            label="Connections"
            empty={<Empty icon="service/AmazonEventBridge" />}
            rows={list.value.map((c) => ({
              key: c.ConnectionArn!,
              icon: <KeyRound size={18} aria-hidden />,
              title: c.Name,
              subtitle: c.StateReason,
              meta: (
                <>
                  <Pill>{c.AuthorizationType}</Pill>
                  <span>{ago(c.CreationTime)}</span>
                  <Status tone={TONE[c.ConnectionState ?? ""] ?? "neutral"}>{c.ConnectionState ?? ""}</Status>
                </>
              ),
              actions: (
                <>
                  {c.ConnectionState === "AUTHORIZED" && (
                    <ActionForm action={deauthorizeConnection.bind(null, c.Name!)} submit={`Deauthorize ${c.Name}`} icon={<Unplug size={15} aria-hidden />} confirm={`Deauthorize ${c.Name}? Its API destinations stop working.`} />
                  )}
                  <ActionForm action={deleteConnection.bind(null, c.Name!)} submit={`Delete ${c.Name}`} icon={<Trash2 size={15} aria-hidden />} tone="danger" confirm={`Delete connection ${c.Name}?`} />
                </>
              ),
            }))}
          />
        </>
      ) : (
        <ErrorNotice error={list.error} />
      )}
    </Page>
  );
}
