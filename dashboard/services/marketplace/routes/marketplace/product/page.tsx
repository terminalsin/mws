import { GetEntitlementsCommand, type GetEntitlementFilterName } from "@aws-sdk/client-marketplace-entitlement-service";
import { ago, all, load, mws, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Field, List, Page, Pill, Section, Segments, Sheet, Specs, Status, Table } from "@mws-dashboard/ui";
import { Building2, Clock, FileSignature, Gauge, KeyRound, Pencil, ScanSearch, Search, Tag, Trash2, UserMinus, UserPlus, Users } from "lucide-react";
import { MoreFields } from "@mws-dashboard/ui/presets";
import type { Metadata } from "next";

import { entitlements as entitlementClient, ICONS } from "../../../lib/clients";
import { ACCOUNT, QUANTITY } from "../../../lib/rules";
import { expired, product, PRODUCT_ICONS, publicKey, records, registrations, subscriptions, valueText, type Product, type Subscription } from "../../../lib/marketplace";
import { deleteProduct, meter, meterUsage, newToken, registerUsage, resolveCustomer, subscribe, unsubscribe, updateEntitlements } from "../actions";
import { Usage } from "../usage";

export const metadata: Metadata = { title: "Product" };

type Props = { searchParams: Promise<{ code?: string; tab?: string; filter?: string; value?: string; customer?: string; dimension?: string }> };

const FILTERS: Record<GetEntitlementFilterName, string> = {
  CUSTOMER_IDENTIFIER: "Customer identifier",
  CUSTOMER_AWS_ACCOUNT_ID: "Customer account",
  LICENSE_ARN: "License ARN",
  DIMENSION: "Dimension",
};

/** A `datetime-local` value for an ISO timestamp (UTC). */
const local = (iso: string | null | undefined) => (iso ? iso.slice(0, 16) : undefined);

async function emulatedNow(): Promise<number> {
  try {
    return new Date((await mws<{ now: string }>("/_mws/clock")).now).getTime();
  } catch {
    return Date.now();
  }
}

function EntitlementFields({ p, sub }: { p: Product; sub?: Subscription }) {
  const current = (d: string) => sub?.entitlements.find((e) => e.dimension === d);
  const expiry = sub?.entitlements.find((e) => e.expirationDate)?.expirationDate;
  return (
    <>
      {p.dimensions.map((d) => (
        <Field key={d.name} label={d.name} hint={d.description ?? undefined}>
          <input name={`dim:${d.name}`} placeholder="10, 2.5, true or text" defaultValue={current(d.name) ? valueText(current(d.name)!.value).replace("✓", "true").replace("✗", "false") : undefined} />
        </Field>
      ))}
      <Field label="Expires (UTC)" hint="Empty: never">
        <input name="expires" type="datetime-local" defaultValue={local(expiry)} />
      </Field>
    </>
  );
}

export default async function ProductPage({ searchParams }: Props) {
  const params = await searchParams;
  const { code = "", tab = "subscriptions" } = params;
  const back = { href: "/marketplace", label: "Products" };
  const data = await load(async () => {
    const [p, subs, usage, now] = await Promise.all([
      product(code),
      subscriptions(code),
      records({ productCode: code, customerIdentifier: params.customer, dimension: params.dimension }),
      emulatedNow(),
    ]);
    return { p, subs, usage, now };
  });
  if (!data.ok) {
    return (
      <Page title={code} icon={ICONS.marketplace} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { p, subs, usage, now } = data.value;
  const active = subs.filter((s) => s.status === "Active");
  const saas = p.productType === "SaaS";
  const tabHref = (t: string) => `/marketplace/product?code=${encodeURIComponent(code)}${t === "subscriptions" ? "" : `&tab=${t}`}`;
  const actions = (
    <>
      <Sheet title="Subscribe a buyer" label="Add subscriber" icon={<UserPlus size={15} />} testId="subscribe">
        <ActionForm action={subscribe.bind(null, p)} submit="Subscribe" testId="subscribe">
          <Field label="Buyer account" rule={ACCOUNT} known={[...new Set(subs.map((s) => s.customerAWSAccountId))]}>
            <input name="account" required autoFocus inputMode="numeric" placeholder="111122223333" />
          </Field>
          <EntitlementFields p={p} />
          <MoreFields label="Identifiers">
            <Field label="Customer identifier" hint="Generated when empty">
              <input name="customer" />
            </Field>
            <Field label="License ARN" format="arn" hint="Generated when empty">
              <input name="license" />
            </Field>
            <Field label="Agreement ID" hint="Generated when empty">
              <input name="agreement" />
            </Field>
            {saas && (
              <Field label="Token lifetime (seconds)" hint="3600 by default; 0 never expires, negative is already expired">
                <input name="tokenTtl" type="number" />
              </Field>
            )}
          </MoreFields>
        </ActionForm>
      </Sheet>
      {saas && (
        <Sheet title="Resolve a registration token" label="ResolveCustomer" icon={<ScanSearch size={15} />} testId="resolve-customer">
          <ActionForm action={resolveCustomer} submit="Resolve" testId="resolve-customer">
            <Field label="Registration token" hint="The x-amzn-marketplace-token your landing page receives">
              <textarea name="token" rows={4} required />
            </Field>
          </ActionForm>
        </Sheet>
      )}
      {active.length > 0 && (
        <Sheet title="BatchMeterUsage" label="Meter usage" icon={<Gauge size={15} />} testId="meter">
          <ActionForm action={meter.bind(null, code)} submit="Send record" testId="meter">
            <Field label="Customer">
              <select name="customer">
                <optgroup label="By customer identifier">
                  {active.map((s) => (
                    <option key={s.customerIdentifier} value={`customer|${s.customerIdentifier}`}>
                      {s.customerAWSAccountId} · {s.customerIdentifier}
                    </option>
                  ))}
                </optgroup>
                <optgroup label="By license (Concurrent Agreements)">
                  {active.map((s) => (
                    <option key={s.licenseArn} value={`license|${s.customerAWSAccountId}@${s.licenseArn}`}>
                      {s.customerAWSAccountId} · {s.licenseArn.split("/").pop()}
                    </option>
                  ))}
                </optgroup>
              </select>
            </Field>
            <div className="form-row">
              <Field label="Dimension">
                <select name="dimension">
                  {p.dimensions.map((d) => (
                    <option key={d.name}>{d.name}</option>
                  ))}
                </select>
              </Field>
              <Field label="Quantity" rule={QUANTITY}>
                <input name="quantity" inputMode="numeric" defaultValue={1} />
              </Field>
            </div>
            <Field label="Usage hour (UTC)" hint="Now when empty; within the last 24 hours">
              <input name="timestamp" type="datetime-local" />
            </Field>
          </ActionForm>
        </Sheet>
      )}
      {!saas && (
        <Sheet title="MeterUsage" label="MeterUsage" icon={<Gauge size={15} />} testId="meter-usage">
          <ActionForm action={meterUsage.bind(null, code)} submit="Send" testId="meter-usage">
            <div className="form-row">
              <Field label="Dimension">
                <select name="dimension">
                  {p.dimensions.map((d) => (
                    <option key={d.name}>{d.name}</option>
                  ))}
                </select>
              </Field>
              <Field label="Quantity" rule={QUANTITY}>
                <input name="quantity" inputMode="numeric" defaultValue={1} />
              </Field>
            </div>
            <Field label="Usage hour (UTC)" hint="Now when empty; within the last 6 hours">
              <input name="timestamp" type="datetime-local" />
            </Field>
            <label className="check">
              <input type="checkbox" name="dryRun" /> Dry run
            </label>
          </ActionForm>
        </Sheet>
      )}
      {p.productType === "Container" && (
        <Sheet title="RegisterUsage" label="RegisterUsage" icon={<FileSignature size={15} />} testId="register-usage">
          <ActionForm action={registerUsage.bind(null, code)} submit="Register" testId="register-usage">
            <div className="form-row">
              <Field label="Public key version">
                <input name="keyVersion" type="number" min={1} defaultValue={1} />
              </Field>
              <Field label="Nonce">
                <input name="nonce" />
              </Field>
            </div>
          </ActionForm>
        </Sheet>
      )}
      <ActionForm action={deleteProduct.bind(null, code)} submit="Delete product" icon={<Trash2 size={16} />} tone="danger" confirm={`Delist ${p.title || code}?`} />
    </>
  );
  return (
    <Page title={p.title || code} icon={PRODUCT_ICONS[p.productType] ?? ICONS.marketplace} back={back} subtitle={code} actions={actions}>
      <Specs
        items={[
          { label: "Type", icon: <AwsIcon icon={PRODUCT_ICONS[p.productType] ?? ICONS.marketplace} size={16} />, value: p.productType },
          { label: "Seller", icon: <Building2 size={15} />, value: p.sellerAccountId },
          { label: "Dimensions", icon: <Tag size={15} />, value: p.dimensions.map((d) => d.name).join(", ") },
          { label: "Subscribers", icon: <Users size={15} />, value: active.length },
        ]}
      />
      <Segments
        items={[
          { label: "Subscriptions", href: tabHref("subscriptions"), active: tab === "subscriptions", count: subs.length },
          { label: "GetEntitlements", href: tabHref("entitlements"), active: tab === "entitlements" },
          { label: "Usage", href: tabHref("usage"), active: tab === "usage", count: usage.length },
          ...(p.productType === "Container" ? [{ label: "Registrations", href: tabHref("registrations"), active: tab === "registrations" }] : []),
        ]}
      />
      {tab === "entitlements" ? (
        <Entitlements code={code} filter={params.filter} value={params.value} />
      ) : tab === "usage" ? (
        <>
          <form className="action-form" action="/marketplace/product" data-testid="filter-records">
            <input type="hidden" name="code" value={code} />
            <input type="hidden" name="tab" value="usage" />
            <div className="form-row">
              <Field label="Customer">
                <select name="customer" defaultValue={params.customer ?? ""}>
                  <option value="">All</option>
                  {subs.map((s) => (
                    <option key={s.customerIdentifier} value={s.customerIdentifier}>
                      {s.customerAWSAccountId} · {s.customerIdentifier}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Dimension">
                <select name="dimension" defaultValue={params.dimension ?? ""}>
                  <option value="">All</option>
                  {p.dimensions.map((d) => (
                    <option key={d.name}>{d.name}</option>
                  ))}
                </select>
              </Field>
            </div>
            <div className="form-actions">
              <button type="submit" className="button primary">
                Filter
                <span className="button-glyph">
                  <Search size={15} aria-hidden />
                </span>
              </button>
            </div>
          </form>
          {usage.length > 0 && (
            <Section title="Usage">
              <Usage records={usage} />
            </Section>
          )}
          <Section title="Records" count={usage.length} plain>
            <List
              label="Metering records"
              empty={<Empty icon={ICONS.marketplace} />}
              rows={[...usage].reverse().map((r) => ({
                key: r.meteringRecordId,
                icon: <Gauge size={18} />,
                title: `${r.quantity.toLocaleString()} × ${r.dimension}`,
                subtitle: [r.customerIdentifier ?? r.customerAWSAccountId, r.reportedBy].filter(Boolean).join(" · "),
                meta: (
                  <>
                    <Pill>{r.operation}</Pill>
                    <span title={`Usage hour ${when(r.timestamp)}`}>{ago(r.timestamp)}</span>
                  </>
                ),
              }))}
            />
          </Section>
        </>
      ) : tab === "registrations" ? (
        <Registrations code={code} />
      ) : (
        <>
        {usage.length > 0 && (
          <Section title="Usage">
            <Usage records={usage} />
          </Section>
        )}
        <Section title="Subscriptions" count={subs.length} plain>
          <List
            label="Subscriptions"
            empty={<Empty icon={ICONS.marketplace} />}
            rows={subs.map((s) => ({
              key: s.customerIdentifier,
              icon: <AwsIcon icon="resource/AWSOrganizationsAccount" size={22} />,
              title: s.customerAWSAccountId,
              subtitle: (
                <>
                  <code>{s.customerIdentifier}</code> · <code title={s.licenseArn}>{s.licenseArn.split("/").pop()}</code>
                </>
              ),
              meta: (
                <>
                  <span className="chips">
                    {s.entitlements.map((e) => (
                      <span key={e.dimension} className="tag" title={e.expirationDate ? `Expires ${when(e.expirationDate)}` : undefined}>
                        {e.dimension} {valueText(e.value)}
                        {e.expirationDate && (expired(e, now) ? <Pill tone="bad">expired</Pill> : <b>until {e.expirationDate.slice(0, 10)}</b>)}
                      </span>
                    ))}
                  </span>
                  {s.status !== "Active" && <Status tone="neutral">unsubscribed</Status>}
                  <span>{ago(s.subscribedAt)}</span>
                </>
              ),
              actions:
                s.status === "Active" ? (
                  <>
                    <Sheet title={`Entitlements of ${s.customerAWSAccountId}`} label={`Edit entitlements of ${s.customerAWSAccountId}`} icon={<Pencil size={15} />} testId="edit-entitlements">
                      <ActionForm action={updateEntitlements.bind(null, p, s.customerIdentifier)} submit="Save" testId="edit-entitlements">
                        <EntitlementFields p={p} sub={s} />
                      </ActionForm>
                    </Sheet>
                    {saas && (
                      <Sheet title="New registration token" label={`New registration token for ${s.customerAWSAccountId}`} icon={<KeyRound size={15} />} testId="new-token">
                        <ActionForm action={newToken.bind(null, s.customerIdentifier)} submit="Create token" testId="new-token">
                          <Field label="Lifetime (seconds)" hint="3600 by default; 0 never expires, negative is already expired">
                            <input name="ttl" type="number" />
                          </Field>
                        </ActionForm>
                      </Sheet>
                    )}
                    <ActionForm action={unsubscribe.bind(null, s.customerIdentifier)} submit={`Unsubscribe ${s.customerAWSAccountId}`} icon={<UserMinus size={15} />} tone="danger" confirm={`Unsubscribe ${s.customerAWSAccountId}?`} />
                  </>
                ) : undefined,
            }))}
          />
        </Section>
        </>
      )}
    </Page>
  );
}

/** What the seller's code sees: GetEntitlements, with its filters. */
async function Entitlements({ code, filter, value }: { code: string; filter?: string; value?: string }) {
  const key = filter && filter in FILTERS ? (filter as GetEntitlementFilterName) : undefined;
  const values = (value ?? "")
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean);
  const list = await load(async () => {
    const c = await entitlementClient();
    return all(
      (NextToken) => c.send(new GetEntitlementsCommand({ ProductCode: code, Filter: key && values.length ? { [key]: values } : undefined, NextToken })),
      (r) => r.Entitlements,
      (r) => r.NextToken,
    );
  });
  return (
    <>
      <form className="action-form" action="/marketplace/product" data-testid="get-entitlements">
        <input type="hidden" name="code" value={code} />
        <input type="hidden" name="tab" value="entitlements" />
        <div className="form-row">
          <Field label="Filter">
            <select name="filter" defaultValue={key ?? ""}>
              <option value="">None</option>
              {Object.entries(FILTERS).map(([k, l]) => (
                <option key={k} value={k}>
                  {l}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Values" hint="Comma separated">
            <input name="value" defaultValue={value} />
          </Field>
        </div>
        <div className="form-actions">
          <button type="submit" className="button primary">
            GetEntitlements
            <span className="button-glyph">
              <Search size={15} aria-hidden />
            </span>
          </button>
        </div>
      </form>
      {list.ok ? (
        <Section title="Entitlements" count={list.value.length} plain>
          <Table
            label="Entitlements"
            rowKey={(e) => `${e.CustomerIdentifier}|${e.LicenseArn}|${e.Dimension}`}
            rows={list.value}
            empty={<Empty icon={ICONS.marketplace} />}
            columns={[
              { header: "Customer account", cell: (e) => e.CustomerAWSAccountId },
              { header: "Customer identifier", cell: (e) => <code>{e.CustomerIdentifier}</code> },
              { header: "Dimension", cell: (e) => e.Dimension },
              {
                header: "Value",
                cell: (e) => (e.Value?.IntegerValue ?? e.Value?.DoubleValue ?? (e.Value?.BooleanValue !== undefined ? String(e.Value.BooleanValue) : e.Value?.StringValue)) as string,
              },
              { header: "Expires", cell: (e) => (e.ExpirationDate ? when(e.ExpirationDate) : "") },
              { header: "License", cell: (e) => <code title={e.LicenseArn}>{e.LicenseArn?.split("/").pop()}</code> },
            ]}
          />
        </Section>
      ) : (
        <ErrorNotice error={list.error} />
      )}
    </>
  );
}

async function Registrations({ code }: { code: string }) {
  const [list, key] = await Promise.all([load(() => registrations(code)), load(publicKey)]);
  return (
    <>
      {list.ok ? (
        <Section title="Registrations" count={list.value.length} plain>
          <List
            label="Registrations"
            empty={<Empty icon={ICONS.marketplace} />}
            rows={[...list.value].reverse().map((r, i) => ({
              key: `${r.registeredAt}-${i}`,
              icon: <FileSignature size={18} />,
              title: r.customerAWSAccountId,
              subtitle: [r.registeredBy, r.nonce && `nonce ${r.nonce}`].filter(Boolean).join(" · "),
              meta: (
                <span title={when(r.registeredAt)}>
                  <Clock size={12} aria-hidden /> {ago(r.registeredAt)}
                </span>
              ),
            }))}
          />
        </Section>
      ) : (
        <ErrorNotice error={list.error} />
      )}
      {key.ok && (
        <Section title="Signing public key">
          <CodeBlock value={key.value} label="Public key" />
        </Section>
      )}
    </>
  );
}
