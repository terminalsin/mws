import type { ApiDestination, Connection } from "@aws-sdk/client-eventbridge";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, Empty, ErrorNotice, Field, List, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import { Globe, Settings2, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { DESTINATION_NAME, ENDPOINT, RATE } from "../../../lib/rules";
import { apiDestinations, connections } from "../../../lib/targets";
import { EventsTabs } from "../../../lib/tabs";
import { deleteApiDestination, saveApiDestination } from "../actions";

export const metadata: Metadata = { title: "API destinations" };

const METHODS = ["POST", "GET", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE"];

function DestinationFields({ conns, d }: { conns: Connection[]; d?: ApiDestination }) {
  return (
    <>
      <Field label="Connection">
        <select name="connection" required defaultValue={d?.ConnectionArn}>
          {conns.map((c) => (
            <option key={c.ConnectionArn} value={c.ConnectionArn}>
              {c.Name}
            </option>
          ))}
        </select>
      </Field>
      <div className="form-row">
        <Field label="Endpoint" rule={ENDPOINT} member="InvocationEndpoint">
          <input name="endpoint" required placeholder="https://example.com/hooks/{id}" defaultValue={d?.InvocationEndpoint} spellCheck={false} />
        </Field>
        <Field label="Method">
          <select name="method" defaultValue={d?.HttpMethod ?? "POST"}>
            {METHODS.map((m) => (
              <option key={m}>{m}</option>
            ))}
          </select>
        </Field>
      </div>
      <div className="form-row">
        <Field label="Rate limit (per second)" rule={RATE} member="InvocationRateLimitPerSecond">
          <input name="rate" inputMode="numeric" defaultValue={d?.InvocationRateLimitPerSecond} placeholder="300" />
        </Field>
        <Field label="Description">
          <input name="description" maxLength={512} />
        </Field>
      </div>
    </>
  );
}

export default async function ApiDestinations() {
  const [list, conns] = await Promise.all([load(apiDestinations), load(connections)]);
  const connList = conns.ok ? conns.value : [];
  const connName = (arn?: string) => connList.find((c) => c.ConnectionArn === arn)?.Name ?? arn?.split("/")[1];
  return (
    <Page
      title="API destinations"
      actions={
        connList.length > 0 ? (
          <Sheet title="New API destination" label="Create API destination" testId="create-api-destination">
            <ActionForm action={saveApiDestination.bind(null, null)} submit="Create" testId="create-api-destination">
              <Field label="Name" rule={DESTINATION_NAME} taken={list.ok ? list.value.map((d) => d.Name!) : []} unique member="Name">
                <input name="name" required autoFocus spellCheck={false} />
              </Field>
              <DestinationFields conns={connList} />
            </ActionForm>
          </Sheet>
        ) : undefined
      }
    >
      <EventsTabs active="destinations" />
      {list.ok ? (
        <List
          label="API destinations"
          empty={
            <Empty icon="service/AmazonEventBridge">
              {connList.length === 0 && <Link href="/events/connections">Connections</Link>}
            </Empty>
          }
          rows={list.value.map((d) => ({
            key: d.ApiDestinationArn!,
            icon: <Globe size={18} aria-hidden />,
            title: d.Name,
            subtitle: (
              <>
                <code>
                  {d.HttpMethod} {d.InvocationEndpoint}
                </code>{" "}
                · <Link href="/events/connections">{connName(d.ConnectionArn)}</Link>
              </>
            ),
            meta: (
              <>
                {d.InvocationRateLimitPerSecond && <Pill title="Rate limit">{d.InvocationRateLimitPerSecond}/s</Pill>}
                <span>{ago(d.CreationTime)}</span>
                <Status tone={d.ApiDestinationState === "ACTIVE" ? "good" : "neutral"}>{d.ApiDestinationState ?? ""}</Status>
              </>
            ),
            actions: (
              <>
                <Sheet title={`API destination ${d.Name}`} label={`Edit ${d.Name}`} icon={<Settings2 size={15} aria-hidden />} testId="edit-api-destination">
                  <ActionForm action={saveApiDestination.bind(null, d.Name!)} submit="Save" testId="edit-api-destination">
                    <DestinationFields conns={connList} d={d} />
                  </ActionForm>
                </Sheet>
                <ActionForm action={deleteApiDestination.bind(null, d.Name!)} submit={`Delete ${d.Name}`} icon={<Trash2 size={15} aria-hidden />} tone="danger" confirm={`Delete API destination ${d.Name}?`} />
              </>
            ),
          }))}
        />
      ) : (
        <ErrorNotice error={list.error} />
      )}
    </Page>
  );
}
