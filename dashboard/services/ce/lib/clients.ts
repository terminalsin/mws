import "server-only";

import { CostExplorerClient } from "@aws-sdk/client-cost-explorer";
import { client } from "@mws-dashboard/aws";

export const ce = () => client(CostExplorerClient);

export const ICONS = {
  ce: "service/AWSCostExplorer",
};
