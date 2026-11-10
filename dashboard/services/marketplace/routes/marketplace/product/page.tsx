import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Section, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { Building2, Gauge, KeyRound, Tag, Trash2, UserMinus, UserPlus, Users } from "lucide-react";
import type { Metadata } from "next";

import { ICONS } from "../../../lib/clients";
import { ACCOUNT, QUANTITY } from "../../../lib/rules";
import { product, PRODUCT_ICONS, records, subscriptions, valueText } from "../../../lib/marketplace";
import { deleteProduct, meter, newToken, subscribe, unsubscribe } from "../actions";
import { Usage } from "../usage";

export const metadata: Metadata = { title: "Product" };

type Props = { searchParams: Promise<{ code?: string }> };

export default async function ProductPage({ searchParams }: Props) {
  const code = (await searchParams).code ?? "";
  const back = { href: "/marketplace", label: "Products" };
  const data = await load(async () => {
    const [p, subs, usage] = await Promise.all([product(code), subscriptions(code), records(code)]);
    return { p, subs, usage };
  });
  if (!data.ok) {
    return (
      <Page title={code} icon={ICONS.marketplace} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { p, subs, usage } = data.value;
  const active = subs.filter((s) => s.status === "Active");
  return (
    <Page
      title={p.title || code}
      icon={PRODUCT_ICONS[p.productType] ?? ICONS.marketplace}
      back={back}
      subtitle={code}
      actions={
        <>
          <Sheet title="Subscribe a buyer" label="Add subscriber" icon={<UserPlus size={15} />} testId="subscribe">
            <ActionForm action={subscribe.bind(null, p)} submit="Subscribe" testId="subscribe">
              <Field label="Buyer account" rule={ACCOUNT} known={[...new Set(subs.map((s) => s.customerAWSAccountId))]}>
                <input name="account" required autoFocus inputMode="numeric" placeholder="111122223333" />
              </Field>
              {p.dimensions.map((d) => (
                <Field key={d.name} label={d.name}>
                  <input name={`dim:${d.name}`} placeholder="10, 2.5, true or text" />
                </Field>
              ))}
            </ActionForm>
          </Sheet>
          {active.length > 0 && (
            <Sheet title="Meter usage" label="Meter usage" icon={<Gauge size={15} />} testId="meter">
              <ActionForm action={meter.bind(null, code)} submit="Send record" testId="meter">
                <Field label="Customer">
                  <select name="customer">
                    {active.map((s) => (
                      <option key={s.customerIdentifier} value={s.customerIdentifier}>
                        {s.customerAWSAccountId} · {s.customerIdentifier}
                      </option>
                    ))}
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
              </ActionForm>
            </Sheet>
          )}
          <ActionForm action={deleteProduct.bind(null, code)} submit="Delete product" icon={<Trash2 size={16} />} tone="danger" confirm={`Delist ${p.title || code}?`} />
        </>
      }
    >
      <Specs
        items={[
          { label: "Type", icon: <AwsIcon icon={PRODUCT_ICONS[p.productType] ?? ICONS.marketplace} size={16} />, value: p.productType },
          { label: "Seller", icon: <Building2 size={15} />, value: p.sellerAccountId },
          { label: "Dimensions", icon: <Tag size={15} />, value: p.dimensions.map((d) => d.name).join(", ") },
          { label: "Subscribers", icon: <Users size={15} />, value: active.length },
        ]}
      />
      {usage.length > 0 && (
        <Section title="Usage" count={usage.length}>
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
            subtitle: <code>{s.customerIdentifier}</code>,
            meta: (
              <>
                <span className="chips">
                  {s.entitlements.map((e) => (
                    <span key={e.dimension} className="tag">
                      {e.dimension} {valueText(e.value)}
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
                  {p.productType === "SaaS" && <ActionForm action={newToken.bind(null, s.customerIdentifier)} submit={`New registration token for ${s.customerAWSAccountId}`} icon={<KeyRound size={15} />} />}
                  <ActionForm action={unsubscribe.bind(null, s.customerIdentifier)} submit={`Unsubscribe ${s.customerAWSAccountId}`} icon={<UserMinus size={15} />} tone="danger" confirm={`Unsubscribe ${s.customerAWSAccountId}?`} />
                </>
              ) : undefined,
          }))}
        />
      </Section>
    </Page>
  );
}
