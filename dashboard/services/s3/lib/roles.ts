import type { RoleSpec } from "@mws-dashboard/aws/auto";

/** The role Batch Operations jobs run as, made by "create automatically". */
export const BATCH_ROLE: RoleSpec = {
  name: "S3BatchOperationsRole",
  service: "batchoperations.s3.amazonaws.com",
  statements: [{ Effect: "Allow", Action: ["s3:GetObject*", "s3:PutObject*", "s3:DeleteObject*", "s3:ListBucket", "s3:RestoreObject", "s3:GetBucketLocation", "lambda:InvokeFunction"], Resource: "*" }],
};

/** The role Access Grants assumes to vend credentials for a location. */
export const GRANTS_ROLE: RoleSpec = {
  name: "S3AccessGrantsLocationRole",
  service: "access-grants.s3.amazonaws.com",
  statements: [{ Effect: "Allow", Action: ["s3:GetObject*", "s3:PutObject*", "s3:DeleteObject*", "s3:ListBucket*", "s3:ListMultipartUploadParts", "s3:AbortMultipartUpload"], Resource: "*" }],
};
