import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import { Lock } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, engineIcon } from "../../lib/clients";
import { listCaches } from "../../lib/elasticache";
import { createCache } from "./actions";

export const metadata: Metadata = { title: "ElastiCache" };

function CreateCache() {
  return (
    <Sheet title="Create cache" label="Create cache" testId="create-cache">
      <ActionForm action={createCache} submit="Create" testId="create-cache">
        <div className="form-row">
          <Field label="Engine">
            <select name="engine" defaultValue="valkey">
              <option value="valkey">Valkey</option>
              <option value="redis">Redis OSS</option>
              <option value="memcached">Memcached</option>
            </select>
          </Field>
          <Field label="Deployment">
            <select name="mode" defaultValue="serverless">
              <option value="serverless">Serverless</option>
              <option value="nodes">Design your own cache</option>
            </select>
          </Field>
        </div>
        <Field label="Name">
          <input name="name" required pattern="[a-zA-Z][a-zA-Z0-9\-]*" maxLength={40} autoFocus />
        </Field>
        <div className="form-row">
          <Field label="Node type">
            <input name="nodeType" defaultValue="cache.t4g.micro" />
          </Field>
          <Field label="Nodes">
            <input name="nodes" type="number" min={1} max={6} defaultValue={1} />
          </Field>
        </div>
        <label className="check">
          <input type="checkbox" name="tls" /> Encryption in transit
        </label>
      </ActionForm>
    </Sheet>
  );
}

export default async function Caches() {
  const caches = await load(listCaches);
  if (!caches.ok) {
    return (
      <Page title="Caches" actions={<CreateCache />}>
        <ErrorNotice error={caches.error} />
      </Page>
    );
  }
  return (
    <Page title="Caches" actions={<CreateCache />}>
      <Curated
        label="Caches"
        sections={[
          { id: "valkey", title: "Valkey", items: caches.value.filter((c) => c.engine === "valkey") },
          { id: "redis", title: "Redis OSS", items: caches.value.filter((c) => c.engine === "redis") },
          { id: "memcached", title: "Memcached", items: caches.value.filter((c) => c.engine === "memcached") },
        ]}
        empty={<Empty icon={ICONS.elasticache} action={<CreateCache />} />}
        row={(c) => ({
          key: `${c.kind}:${c.name}`,
          icon: <AwsIcon icon={engineIcon(c.engine)} size={24} />,
          title: c.name,
          subtitle: c.endpoint ? <code className="clip">{c.endpoint}</code> : undefined,
          href: c.href,
          meta: (
            <>
              {c.kind === "serverless" ? <Pill tone="info">Serverless</Pill> : <span>{c.nodes} × {c.nodeType}</span>}
              {c.tls && <Lock size={13} aria-label="TLS" />}
              <Status tone={STATUS_TONE(c.status)}>{c.status}</Status>
            </>
          ),
        })}
      />
    </Page>
  );
}
