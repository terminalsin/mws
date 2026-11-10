import "server-only";

import { ACMClient } from "@aws-sdk/client-acm";
import { ACMPCAClient } from "@aws-sdk/client-acm-pca";
import { client } from "@mws-dashboard/aws";

export const acm = () => client(ACMClient);
export const pca = () => client(ACMPCAClient);

export const ICONS = {
  alb: "resource/ElasticLoadBalancingApplicationLoadBalancer",
  acm: "service/AWSCertificateManager",
  ca: "resource/AWSCertificateManagerCertificateAuthority",
};

/** Days until a date, rounded down (negative once past). */
export function daysUntil(d: Date | undefined) {
  return d ? Math.floor((d.getTime() - Date.now()) / 86_400_000) : undefined;
}
