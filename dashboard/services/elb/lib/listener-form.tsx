import "server-only";

import { ListCertificatesCommand } from "@aws-sdk/client-acm";
import { DescribeSSLPoliciesCommand, DescribeTrustStoresCommand, type Listener, type LoadBalancer, type TargetGroup } from "@aws-sdk/client-elastic-load-balancing-v2";
import { all } from "@mws-dashboard/aws";
import { Field } from "@mws-dashboard/ui";
import { CreateListener } from "@mws-dashboard/ui/model/elbv2";
import Link from "next/link";

import { ActionFields } from "./action-fields";
import { acm, elb } from "./clients";
import { actionDefaults, actionKinds } from "./listener";
import { LISTENER_PORT, forwardsTo } from "./rules";

export interface ListenerChoices {
  certs: { arn: string; domain: string }[];
  policies: string[];
  stores: { arn: string; name: string }[];
}

/** Certificates, security policies and trust stores a listener can use
 * (suggestions: a failed lookup offers nothing). */
export async function listenerChoices(): Promise<ListenerChoices> {
  const client = await elb();
  const [certs, policies, stores] = await Promise.all([
    acm()
      .then((c) => c.send(new ListCertificatesCommand({ CertificateStatuses: ["ISSUED"] })))
      .then((r) => (r.CertificateSummaryList ?? []).map((c) => ({ arn: c.CertificateArn!, domain: c.DomainName ?? c.CertificateArn! })))
      .catch(() => []),
    client
      .send(new DescribeSSLPoliciesCommand({}))
      .then((r) => (r.SslPolicies ?? []).map((p) => p.Name!))
      .catch(() => [] as string[]),
    all(
      (Marker) => client.send(new DescribeTrustStoresCommand({ Marker })),
      (r) => r.TrustStores,
      (r) => r.NextMarker,
    )
      .then((s) => s.map((t) => ({ arn: t.TrustStoreArn!, name: t.Name! })))
      .catch(() => []),
  ]);
  return { certs, policies, stores };
}

/** The groups a listener of this load balancer can forward to: its VPC's
 * (or Lambda's), with a protocol it speaks. */
export function compatibleGroups(lb: LoadBalancer, groups: TargetGroup[]) {
  return groups
    .filter((g) => (g.VpcId === lb.VpcId || g.TargetType === "lambda") && forwardsTo(lb.Type, g))
    .map((g) => ({ arn: g.TargetGroupArn!, name: g.TargetGroupName!, detail: g.Protocol ? `${g.Protocol}:${g.Port}` : (g.TargetType ?? "") }));
}

/** A listener's fields: protocol and port, its default action (forward
 * only for Network and Gateway Load Balancers), and TLS settings. */
export function ListenerFields({
  lb,
  groups,
  choices,
  listener,
  taken,
}: {
  lb: LoadBalancer;
  groups: TargetGroup[];
  choices: ListenerChoices;
  listener?: Listener;
  taken: string[];
}) {
  const application = lb.Type === "application";
  const gateway = lb.Type === "gateway";
  const freePort = [application ? 80 : 443, 443, 8080, 8443].find((p) => !taken.includes(String(p))) ?? 8081;
  const protocols = application ? ["HTTP", "HTTPS"] : ["TCP", "TLS", "UDP", "TCP_UDP"];
  return (
    <>
      {!gateway && (
        <div className="form-row">
          <Field label="Protocol" rule={CreateListener.Protocol}>
            <select name="protocol" defaultValue={listener?.Protocol ?? (application ? "HTTP" : "TCP")}>
              {protocols.map((p) => (
                <option key={p}>{p}</option>
              ))}
            </select>
          </Field>
          <Field label="Port" rule={LISTENER_PORT} format="port" taken={taken}>
            <input name="port" type="number" defaultValue={listener?.Port ?? freePort} required />
          </Field>
        </div>
      )}
      <ActionFields groups={compatibleGroups(lb, groups)} kinds={actionKinds(lb.Type)} defaults={actionDefaults(listener?.DefaultActions)} />
      {!gateway && (
        <>
          <div className="form-row">
            <Field label="Certificate (HTTPS, TLS)" member="Certificates" hint={choices.certs.length ? undefined : <Link href="/acm">Request a certificate</Link>}>
              <select name="certificate" defaultValue={listener?.Certificates?.find((c) => c.IsDefault !== false)?.CertificateArn ?? ""}>
                <option value="">—</option>
                {choices.certs.map((c) => (
                  <option key={c.arn} value={c.arn}>
                    {c.domain}
                  </option>
                ))}
              </select>
            </Field>
            {choices.policies.length > 0 && (
              <Field label="Security policy" member="SslPolicy">
                <select name="sslPolicy" defaultValue={listener?.SslPolicy ?? ""}>
                  <option value="">Default</option>
                  {choices.policies.map((p) => (
                    <option key={p}>{p}</option>
                  ))}
                </select>
              </Field>
            )}
          </div>
          {application ? (
            <div className="form-row">
              <Field label="Mutual TLS (HTTPS)" member="MutualAuthentication.Mode">
                <select name="mtls" defaultValue={listener?.MutualAuthentication?.Mode ?? ""}>
                  <option value="">Off</option>
                  <option value="passthrough">Passthrough</option>
                  <option value="verify">Verify with trust store</option>
                </select>
              </Field>
              <Field label="Trust store" member="MutualAuthentication.TrustStoreArn">
                <select name="trustStore" defaultValue={listener?.MutualAuthentication?.TrustStoreArn ?? ""}>
                  <option value="">—</option>
                  {choices.stores.map((s) => (
                    <option key={s.arn} value={s.arn}>
                      {s.name}
                    </option>
                  ))}
                </select>
              </Field>
            </div>
          ) : (
            <Field label="ALPN policy (TLS)" member="AlpnPolicy">
              <select name="alpn" defaultValue={listener?.AlpnPolicy?.[0] ?? ""}>
                <option value="">None</option>
                {["HTTP1Only", "HTTP2Only", "HTTP2Optional", "HTTP2Preferred"].map((p) => (
                  <option key={p}>{p}</option>
                ))}
              </select>
            </Field>
          )}
        </>
      )}
    </>
  );
}
