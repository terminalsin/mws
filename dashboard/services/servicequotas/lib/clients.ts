import "server-only";

import { ServiceQuotasClient } from "@aws-sdk/client-service-quotas";
import { client } from "@mws-dashboard/aws";

export const quotas = () => client(ServiceQuotasClient);

export const ICONS = {
  quotas: "service/AWSTrustedAdvisor",
};
