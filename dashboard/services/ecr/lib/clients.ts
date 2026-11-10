import "server-only";

import { ECRClient } from "@aws-sdk/client-ecr";
import { client } from "@mws-dashboard/aws";

export const ecr = () => client(ECRClient);

export const ICONS = {
  ecr: "service/AmazonElasticContainerRegistry",
  repo: "resource/AmazonElasticContainerRegistryRegistry",
  image: "resource/AmazonElasticContainerRegistryImage",
};
