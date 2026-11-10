// "Create automatically": the prerequisites a create form needs (service
// roles, buckets, log groups, networks), made on submit when the user picks
// the automatic option instead of an existing resource. Each helper is
// idempotent: it reuses what it made last time.
import "server-only";

import { CreateLogGroupCommand, CloudWatchLogsClient, ResourceAlreadyExistsException } from "@aws-sdk/client-cloudwatch-logs";
import { DescribeSecurityGroupsCommand, DescribeSubnetsCommand, DescribeVpcsCommand, EC2Client } from "@aws-sdk/client-ec2";
import {
  AddRoleToInstanceProfileCommand,
  CreateInstanceProfileCommand,
  CreateRoleCommand,
  GetInstanceProfileCommand,
  GetRoleCommand,
  IAMClient,
  ListRolesCommand,
  NoSuchEntityException,
  PutRolePolicyCommand,
} from "@aws-sdk/client-iam";
import { CreateBucketCommand, HeadBucketCommand, ListBucketsCommand, PutBucketPolicyCommand, S3Client } from "@aws-sdk/client-s3";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";

import { AUTO } from "@mws-dashboard/ui/constants";

import { client, collect, region, text } from "./index";

export { AUTO };

/** Is the field set to the automatic option (or left empty)? */
export function wantsAuto(form: FormData, name: string): boolean {
  const v = text(form, name);
  return !v || v === AUTO;
}

export interface RoleSpec {
  name: string;
  /** Service principals that may assume the role. */
  service: string | string[];
  /** Inline permissions, as policy statements. */
  statements: object[];
  /** Also make an instance profile of the same name (EC2 roles). */
  instanceProfile?: boolean;
}

/** Role templates for the console's create forms. */
export const ROLES = {
  eksCluster: {
    name: "AmazonEKSClusterRole",
    service: "eks.amazonaws.com",
    statements: [{ Effect: "Allow", Action: ["ec2:*", "elasticloadbalancing:*", "autoscaling:Describe*", "kms:DescribeKey", "iam:CreateServiceLinkedRole"], Resource: "*" }],
  },
  eksNode: {
    name: "AmazonEKSNodeRole",
    service: "ec2.amazonaws.com",
    statements: [{ Effect: "Allow", Action: ["ec2:Describe*", "ec2:AssignPrivateIpAddresses", "ec2:AttachNetworkInterface", "ec2:CreateNetworkInterface", "ec2:DeleteNetworkInterface", "ec2:ModifyNetworkInterfaceAttribute", "ec2:CreateTags", "eks:DescribeCluster", "ecr:GetAuthorizationToken", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"], Resource: "*" }],
    instanceProfile: true,
  },
  lambda: (fn: string): RoleSpec => ({
    name: `${fn}-role`.slice(0, 64),
    service: "lambda.amazonaws.com",
    statements: [{ Effect: "Allow", Action: ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], Resource: "*" }],
  }),
  firehose: (stream: string, bucket: string): RoleSpec => ({
    name: `KinesisFirehoseServiceRole-${stream}`.slice(0, 64),
    service: "firehose.amazonaws.com",
    statements: [
      { Effect: "Allow", Action: ["s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject"], Resource: [`arn:aws:s3:::${bucket}`, `arn:aws:s3:::${bucket}/*`] },
      { Effect: "Allow", Action: ["logs:PutLogEvents", "kinesis:DescribeStream", "kinesis:GetShardIterator", "kinesis:GetRecords", "kinesis:ListShards", "kms:Decrypt", "kms:GenerateDataKey"], Resource: "*" },
    ],
  }),
  imageBuilderInstance: {
    name: "EC2InstanceProfileForImageBuilder",
    service: "ec2.amazonaws.com",
    statements: [{ Effect: "Allow", Action: ["imagebuilder:GetComponent", "ssm:*", "ssmmessages:*", "ec2messages:*", "s3:GetObject", "s3:PutObject", "logs:CreateLogStream", "logs:CreateLogGroup", "logs:PutLogEvents", "kms:Decrypt"], Resource: "*" }],
    instanceProfile: true,
  },
  bedrockLogging: {
    name: "AmazonBedrockInvocationLoggingRole",
    service: "bedrock.amazonaws.com",
    statements: [{ Effect: "Allow", Action: ["logs:CreateLogStream", "logs:PutLogEvents"], Resource: "*" }],
  },
} satisfies Record<string, RoleSpec | ((...a: string[]) => RoleSpec)>;

const trust = (service: string | string[]) =>
  JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { Service: service }, Action: "sts:AssumeRole" }] });

/** The role `spec` describes: the existing one, or a new one. Returns its ARN. */
export async function ensureRole(spec: RoleSpec): Promise<string> {
  const iam = await client(IAMClient);
  let arn: string;
  try {
    arn = (await iam.send(new GetRoleCommand({ RoleName: spec.name }))).Role!.Arn!;
  } catch (e) {
    if (!(e instanceof NoSuchEntityException)) throw e;
    const made = await iam.send(new CreateRoleCommand({ RoleName: spec.name, AssumeRolePolicyDocument: trust(spec.service), Description: "Created by the MWS console", Tags: [{ Key: "mws:console", Value: "auto" }] }));
    arn = made.Role!.Arn!;
  }
  await iam.send(new PutRolePolicyCommand({ RoleName: spec.name, PolicyName: "console-permissions", PolicyDocument: JSON.stringify({ Version: "2012-10-17", Statement: spec.statements }) }));
  if (spec.instanceProfile) {
    try {
      await iam.send(new GetInstanceProfileCommand({ InstanceProfileName: spec.name }));
    } catch (e) {
      if (!(e instanceof NoSuchEntityException)) throw e;
      await iam.send(new CreateInstanceProfileCommand({ InstanceProfileName: spec.name }));
      await iam.send(new AddRoleToInstanceProfileCommand({ InstanceProfileName: spec.name, RoleName: spec.name }));
    }
  }
  return arn;
}

/** The role named in `form[name]`, or the one `spec` describes when the
 * automatic option is picked. */
export async function roleFrom(form: FormData, name: string, spec: RoleSpec): Promise<string> {
  return wantsAuto(form, name) ? ensureRole(spec) : text(form, name);
}

async function account(): Promise<string> {
  return (await (await client(STSClient)).send(new GetCallerIdentityCommand({}))).Account!;
}

/** A bucket for `purpose` in this account and region (`purpose-<account>-<region>`),
 * with `policy(bucket, account)` as its bucket policy when given. */
export async function ensureBucket(purpose: string, policy?: (bucket: string, account: string) => object): Promise<string> {
  const [acct, r] = await Promise.all([account(), region()]);
  const bucket = `${purpose}-${acct}-${r}`.toLowerCase().slice(0, 63);
  const s3 = await client(S3Client, { forcePathStyle: true });
  try {
    await s3.send(new HeadBucketCommand({ Bucket: bucket }));
  } catch {
    await s3.send(new CreateBucketCommand({ Bucket: bucket, ...(r === "us-east-1" ? {} : { CreateBucketConfiguration: { LocationConstraint: r as never } }) }));
  }
  if (policy) await s3.send(new PutBucketPolicyCommand({ Bucket: bucket, Policy: JSON.stringify(policy(bucket, acct)) }));
  return bucket;
}

/** A log group, created when missing. */
export async function ensureLogGroup(name: string): Promise<string> {
  try {
    await (await client(CloudWatchLogsClient)).send(new CreateLogGroupCommand({ logGroupName: name }));
  } catch (e) {
    if (!(e instanceof ResourceAlreadyExistsException)) throw e;
  }
  return name;
}

/** The default VPC (else the first one) with its subnets and default security group. */
export async function defaultNetwork() {
  const ec2 = await client(EC2Client);
  const vpcs = (await ec2.send(new DescribeVpcsCommand({}))).Vpcs ?? [];
  const vpc = vpcs.find((v) => v.IsDefault) ?? vpcs[0];
  if (!vpc) throw new Error("This Region has no VPC");
  const filter = [{ Name: "vpc-id", Values: [vpc.VpcId!] }];
  const [subnets, groups] = await Promise.all([
    ec2.send(new DescribeSubnetsCommand({ Filters: filter })).then((r) => r.Subnets ?? []),
    ec2.send(new DescribeSecurityGroupsCommand({ Filters: [...filter, { Name: "group-name", Values: ["default"] }] })).then((r) => r.SecurityGroups ?? []),
  ]);
  return { vpcId: vpc.VpcId!, subnetIds: subnets.map((s) => s.SubnetId!), securityGroupIds: groups.map((g) => g.GroupId!) };
}

export interface Option {
  value: string;
  label: string;
}

/** Roles `service` may assume, as `AutoPick` options (empty when IAM fails). */
export async function roleOptions(service: string): Promise<Option[]> {
  try {
    const iam = await client(IAMClient);
    const roles = await collect(
      (Marker) => iam.send(new ListRolesCommand({ Marker })),
      (r) => r.Roles,
      (r) => (r.IsTruncated ? r.Marker : undefined),
    );
    return roles.filter((r) => decodeURIComponent(r.AssumeRolePolicyDocument ?? "").includes(service)).map((r) => ({ value: r.Arn!, label: r.RoleName! }));
  } catch {
    return [];
  }
}

/** Buckets, as `AutoPick` options. */
export async function bucketOptions(): Promise<Option[]> {
  try {
    const out = await (await client(S3Client, { forcePathStyle: true })).send(new ListBucketsCommand({}));
    return (out.Buckets ?? []).map((b) => ({ value: b.Name!, label: b.Name! }));
  } catch {
    return [];
  }
}

/** The bucket named in `form[name]`, or a new one for `purpose`. */
export async function bucketFrom(form: FormData, name: string, purpose: string, policy?: (bucket: string, account: string) => object): Promise<string> {
  return wantsAuto(form, name) ? ensureBucket(purpose, policy) : text(form, name);
}

/** The bucket policy CloudTrail needs to deliver logs. */
export function cloudTrailBucketPolicy(bucket: string, account: string) {
  return {
    Version: "2012-10-17",
    Statement: [
      { Sid: "AWSCloudTrailAclCheck", Effect: "Allow", Principal: { Service: "cloudtrail.amazonaws.com" }, Action: "s3:GetBucketAcl", Resource: `arn:aws:s3:::${bucket}` },
      { Sid: "AWSCloudTrailWrite", Effect: "Allow", Principal: { Service: "cloudtrail.amazonaws.com" }, Action: "s3:PutObject", Resource: `arn:aws:s3:::${bucket}/AWSLogs/${account}/*`, Condition: { StringEquals: { "s3:x-amz-acl": "bucket-owner-full-control" } } },
    ],
  };
}

/** The bucket policy Bedrock invocation logging needs. */
export function bedrockLoggingBucketPolicy(bucket: string, account: string) {
  return {
    Version: "2012-10-17",
    Statement: [{ Sid: "AmazonBedrockLogsWrite", Effect: "Allow", Principal: { Service: "bedrock.amazonaws.com" }, Action: "s3:PutObject", Resource: `arn:aws:s3:::${bucket}/*`, Condition: { StringEquals: { "aws:SourceAccount": account } } }],
  };
}
