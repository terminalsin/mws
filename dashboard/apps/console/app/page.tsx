import { applications } from "@mws-dashboard/ai";
import { AwsIcon, Empty, List, Page, Section, SERVICES, Status } from "@mws-dashboard/ui";
import Link from "next/link";

import { iconOf, inventory, searchText, serviceOf } from "../lib/inventory";

export default async function Home() {
  const items = await inventory();
  const attention = items.filter((i) => i.signal);
  const counts = new Map<string, number>();
  for (const i of items) counts.set(i.service, (counts.get(i.service) ?? 0) + 1);
  const services = SERVICES.filter((s) => counts.has(s.id)).sort((a, b) => counts.get(b.id)! - counts.get(a.id)!);
  const apps = (await applications(items.map((i) => ({ ...i, text: searchText(i) })))).filter(
    // An application spans services (a function, its role, its logs); a run of
    // similarly named resources of one kind is not one.
    (a) => new Set(a.members.map((m) => m.service)).size > 1,
  );

  return (
    <Page title="Home">
      {attention.length > 0 && (
        <Section title="Needs attention" count={attention.length} plain>
          <List
            label="Needs attention"
            rows={attention.map((i) => ({
              key: i.id,
              icon: <AwsIcon icon={iconOf(i)} size={24} label={i.type} />,
              title: i.name,
              href: i.href,
              meta: <Status tone={i.signal!.tone}>{i.signal!.text}</Status>,
            }))}
          />
        </Section>
      )}

      {apps.length > 0 && (
        <Section title="Applications" count={apps.length} plain>
          <div className="tiles apps">
            {apps.slice(0, 12).map((a) => {
              const icons = [...new Set(a.members.map((m) => serviceOf(m)?.icon).filter(Boolean))] as string[];
              return (
                <Link key={a.name} className="tile" href={`/search?q=${encodeURIComponent(a.name)}`}>
                  <span className="icon-stack">
                    {icons.slice(0, 5).map((icon) => (
                      <AwsIcon key={icon} icon={icon} size={26} />
                    ))}
                  </span>
                  <span className="tile-name">{a.name}</span>
                  <span className="muted">{a.members.length}</span>
                </Link>
              );
            })}
          </div>
        </Section>
      )}

      <Section title="Resources" count={items.length} plain>
        {services.length > 0 ? (
          <div className="tiles" data-testid="services">
            {services.map((s) => (
              <Link key={s.id} className="tile" href={s.path ?? "/"}>
                <AwsIcon icon={s.icon} size={32} />
                <span className="tile-name">{s.short}</span>
                <span className="tile-value">{counts.get(s.id)}</span>
              </Link>
            ))}
          </div>
        ) : (
          <Empty icon="service/AWSManagementConsole" />
        )}
      </Section>
    </Page>
  );
}
