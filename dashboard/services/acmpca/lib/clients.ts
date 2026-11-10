import "server-only";

import { ACMPCAClient } from "@aws-sdk/client-acm-pca";
import { client } from "@mws-dashboard/aws";

export const pca = () => client(ACMPCAClient);

export const ICONS = {
  ca: "resource/AWSCertificateManagerCertificateAuthority",
  pca: "service/AWSPrivateCertificateAuthority",
};
