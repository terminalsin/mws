import "server-only";

import { CloudTrailClient, type Trail } from "@aws-sdk/client-cloudtrail";
import { client } from "@mws-dashboard/aws";

export const cloudtrail = () => client(CloudTrailClient);

export const ICONS = {
  cloudtrail: "service/AWSCloudTrail",
  trail: "resource/AWSCloudTrailCloudTrailLake",
};

export const trailHref = (arn: string) => `/cloudtrail/trail?arn=${encodeURIComponent(arn)}`;
export const eventHref = (id: string) => `/cloudtrail/event?id=${encodeURIComponent(id)}`;

/** The account in an ARN (`arn:aws:svc:region:account:...`). */
export const arnAccount = (arn: string | undefined) => arn?.split(":")[4] ?? "";

/** Why a trail can't be changed from here: a shadow of a multi-Region trail
 * whose home is another Region, or an organization trail another account
 * owns. AWS answers InvalidHomeRegion or NotOrganizationMasterAccount to
 * any change made from a shadow, so the console offers none. */
export function shadowOf(t: Trail, region: string, account: string | null): string | null {
  if (account && arnAccount(t.TrailARN) && arnAccount(t.TrailARN) !== account) return `Owned by ${arnAccount(t.TrailARN)}`;
  if (t.HomeRegion && t.HomeRegion !== region) return `Home Region ${t.HomeRegion}`;
  return null;
}

/** Console pages of the resources a trail delivers to. */
export const links = {
  bucket: (name: string) => `/s3/${encodeURIComponent(name)}`,
  topic: (arn: string) => `/sns/topic?arn=${encodeURIComponent(arn)}`,
  logGroup: (arn: string) => `/logs/group?name=${encodeURIComponent(arn.split(":log-group:")[1]?.replace(/:\*$/, "") ?? arn)}`,
  role: (arn: string) => `/iam/roles/${encodeURIComponent(arn.split("/").pop() ?? arn)}`,
  key: (id: string) => `/kms/key?id=${encodeURIComponent(id)}`,
};
