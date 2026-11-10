import "server-only";

import { GlobalAcceleratorClient } from "@aws-sdk/client-global-accelerator";
import { client } from "@mws-dashboard/aws";

export const ga = () => client(GlobalAcceleratorClient);

export const ICONS = {
  ga: "service/AWSGlobalAccelerator",
};
