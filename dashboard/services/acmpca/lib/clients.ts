import "server-only";

import { ACMPCAClient } from "@aws-sdk/client-acm-pca";
import { PcaConnectorScepClient } from "@aws-sdk/client-pca-connector-scep";
import { client } from "@mws-dashboard/aws";

export const pca = () => client(ACMPCAClient);
export const scep = () => client(PcaConnectorScepClient);

export const ICONS = {
  ca: "resource/AWSCertificateManagerCertificateAuthority",
  pca: "service/AWSPrivateCertificateAuthority",
};
