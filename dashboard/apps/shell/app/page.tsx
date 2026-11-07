import { load, mws, when } from "@mws-dashboard/aws";
import { Badge, Card, ErrorNotice, Grid, PageHeader, Section, Stat, ZONES, zoneHref } from "@mws-dashboard/ui";

interface Health {
  status: string;
  services: string[];
}

interface Clock {
  now: string;
  offsetSeconds: number;
}

const ZONE_BLURBS: Record<string, string> = {
  storage: "Buckets, objects, uploads and downloads.",
  messaging: "Queues, topics, event buses and the mail SES and SNS sent.",
  security: "IAM principals and policies, KMS keys, secrets and parameters.",
  compute: "Lambda functions you can invoke, EC2 instances you can start and stop.",
  observability: "Log groups and events, alarms and metrics.",
};

export default async function Overview() {
  const [health, clock] = await Promise.all([load(() => mws<Health>("/_mws/health")), load(() => mws<Clock>("/_mws/clock"))]);
  return (
    <>
      <PageHeader
        title="Overview"
        description="A console for the local AWS emulator. Every page reads live state through the AWS SDK, so what you see is what your code sees."
      />
      {!health.ok && <ErrorNotice error={health.error} />}
      <Grid>
        <Stat label="Status" value={health.ok ? <Badge tone="good">{health.value.status}</Badge> : <Badge tone="bad">down</Badge>} />
        <Stat label="Emulated services" value={health.ok ? health.value.services.length : "—"} />
        <Stat
          label="Emulated clock"
          value={clock.ok ? when(clock.value.now) : "—"}
          hint={clock.ok && clock.value.offsetSeconds !== 0 ? `${clock.value.offsetSeconds}s ahead of real time` : "real time"}
        />
      </Grid>
      <Section title="Consoles">
        <Grid>
          {ZONES.filter((z) => z.id !== "shell").map((z) => (
            <Card key={z.id} title={z.title} href={zoneHref(z.id, z.nav[0]?.path ?? "/")}>
              {ZONE_BLURBS[z.id]}
            </Card>
          ))}
        </Grid>
      </Section>
      {health.ok && (
        <Section title={`Services (${health.value.services.length})`}>
          <div className="chips" data-testid="services">
            {[...health.value.services].sort().map((s) => (
              <Badge key={s}>{s}</Badge>
            ))}
          </div>
        </Section>
      )}
    </>
  );
}
