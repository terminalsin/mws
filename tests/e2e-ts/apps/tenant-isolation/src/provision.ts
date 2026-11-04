// Run once by an administrator (here: the account root user):
//
// - a shared bucket with one prefix per tenant: tenants/<tenant-id>/...
// - an IAM user for the backend service, allowed only to assume one role
// - the role "tenant-data-access", whose single ABAC policy grants access
//   to tenants/${aws:PrincipalTag/tenant}/*: the tenant comes from the STS
//   session tag, so one role serves every tenant.
import {
  CreateAccessKeyCommand,
  CreateRoleCommand,
  CreateUserCommand,
  IAMClient,
  PutRolePolicyCommand,
  PutUserPolicyCommand,
} from "@aws-sdk/client-iam";
import { CreateBucketCommand, S3Client } from "@aws-sdk/client-s3";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";

export interface Deployment {
  accountId: string;
  bucket: string;
  roleArn: string;
  backendCredentials: { accessKeyId: string; secretAccessKey: string };
}

export async function provision(name: string): Promise<Deployment> {
  const iam = new IAMClient({});
  const { Account } = await new STSClient({}).send(new GetCallerIdentityCommand({}));
  const accountId = Account!;

  const bucket = `${name}-tenant-data`;
  await new S3Client({ forcePathStyle: true }).send(new CreateBucketCommand({ Bucket: bucket }));

  const userName = `${name}-backend`;
  await iam.send(new CreateUserCommand({ UserName: userName }));
  const backendArn = `arn:aws:iam::${accountId}:user/${userName}`;

  const roleName = `${name}-tenant-data-access`;
  const { Role } = await iam.send(
    new CreateRoleCommand({
      RoleName: roleName,
      MaxSessionDuration: 3600,
      AssumeRolePolicyDocument: JSON.stringify({
        Version: "2012-10-17",
        Statement: [
          {
            // Only the backend may assume the role, and only with a tenant tag.
            Effect: "Allow",
            Principal: { AWS: backendArn },
            Action: ["sts:AssumeRole", "sts:TagSession"],
            Condition: { StringLike: { "aws:RequestTag/tenant": "?*" } },
          },
        ],
      }),
    }),
  );
  await iam.send(
    new PutRolePolicyCommand({
      RoleName: roleName,
      PolicyName: "tenant-prefix",
      PolicyDocument: JSON.stringify({
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Allow",
            Action: ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
            Resource: `arn:aws:s3:::${bucket}/tenants/\${aws:PrincipalTag/tenant}/*`,
          },
          {
            Effect: "Allow",
            Action: "s3:ListBucket",
            Resource: `arn:aws:s3:::${bucket}`,
            Condition: { StringLike: { "s3:prefix": "tenants/${aws:PrincipalTag/tenant}/*" } },
          },
        ],
      }),
    }),
  );

  await iam.send(
    new PutUserPolicyCommand({
      UserName: userName,
      PolicyName: "assume-tenant-role",
      PolicyDocument: JSON.stringify({
        Version: "2012-10-17",
        Statement: [{ Effect: "Allow", Action: ["sts:AssumeRole", "sts:TagSession"], Resource: Role!.Arn }],
      }),
    }),
  );
  const { AccessKey } = await iam.send(new CreateAccessKeyCommand({ UserName: userName }));

  return {
    accountId,
    bucket,
    roleArn: Role!.Arn!,
    backendCredentials: { accessKeyId: AccessKey!.AccessKeyId!, secretAccessKey: AccessKey!.SecretAccessKey! },
  };
}
