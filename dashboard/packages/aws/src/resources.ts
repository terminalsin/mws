// The resources the console's pickers offer (`ResourcePicker`, served by
// the console's `/api/resources`): every kind in RESOURCE_KINDS listed the
// way an application would, through the SDK, plus the few the picker can
// create in place from a name. A kind that fails to list returns nothing,
// so a picker still takes free text.
import "server-only";

import { ListCertificatesCommand, ACMClient } from "@aws-sdk/client-acm";
import { ACMPCAClient, ListCertificateAuthoritiesCommand } from "@aws-sdk/client-acm-pca";
import { CloudWatchLogsClient, CreateLogGroupCommand, DescribeLogGroupsCommand } from "@aws-sdk/client-cloudwatch-logs";
import { DescribeInstancesCommand, DescribeSecurityGroupsCommand, DescribeSubnetsCommand, DescribeVpcsCommand, EC2Client, type Tag } from "@aws-sdk/client-ec2";
import { DescribeRepositoriesCommand, ECRClient } from "@aws-sdk/client-ecr";
import { DescribeLoadBalancersCommand, DescribeTargetGroupsCommand, ElasticLoadBalancingV2Client } from "@aws-sdk/client-elastic-load-balancing-v2";
import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import { ECSClient, ListClustersCommand } from "@aws-sdk/client-ecs";
import { DescribeFileSystemsCommand, EFSClient } from "@aws-sdk/client-efs";
import { CreateEventBusCommand, EventBridgeClient, ListEventBusesCommand, ListRulesCommand } from "@aws-sdk/client-eventbridge";
import { FirehoseClient, ListDeliveryStreamsCommand } from "@aws-sdk/client-firehose";
import {
  CreateRoleCommand,
  IAMClient,
  ListGroupsCommand,
  ListInstanceProfilesCommand,
  ListPoliciesCommand,
  ListRolesCommand,
  ListUsersCommand,
  type Role,
} from "@aws-sdk/client-iam";
import { CreateStreamCommand, KinesisClient, ListStreamsCommand } from "@aws-sdk/client-kinesis";
import { CreateAliasCommand, CreateKeyCommand, KMSClient, ListAliasesCommand, ListKeysCommand } from "@aws-sdk/client-kms";
import { LambdaClient, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import { DescribeDBInstancesCommand, RDSClient } from "@aws-sdk/client-rds";
import { CreateBucketCommand, ListBucketsCommand, S3Client } from "@aws-sdk/client-s3";
import { ListSecretsCommand, SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import { CreateTopicCommand, ListTopicsCommand, SNSClient } from "@aws-sdk/client-sns";
import { CreateQueueCommand, ListQueuesCommand, SQSClient } from "@aws-sdk/client-sqs";
import { DescribeParametersCommand, SSMClient } from "@aws-sdk/client-ssm";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import { RESOURCE_KINDS, type ResourceKind, type ResourceOption } from "@mws-dashboard/ui/resources";

import { client, collect, region } from "./index";

export { RESOURCE_KINDS, type ResourceKind, type ResourceOption };

const nameTag = (tags: Tag[] | undefined) => tags?.find((t) => t.Key === "Name")?.Value;

async function account(): Promise<string> {
  return (await (await client(STSClient)).send(new GetCallerIdentityCommand({}))).Account ?? "000000000000";
}

/** The service principals a role's trust policy names. */
function trusted(role: Role): string[] {
  try {
    const doc = JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument ?? "{}"));
    const statements = Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement];
    return statements.flatMap((s: { Principal?: { Service?: string | string[] } }) => {
      const svc = s?.Principal?.Service;
      return svc ? (Array.isArray(svc) ? svc : [svc]) : [];
    });
  } catch {
    return [];
  }
}

const LISTERS: Record<ResourceKind, () => Promise<Omit<ResourceOption, "kind">[]>> = {
  "iam-role": async () => {
    const iam = await client(IAMClient);
    const roles = await collect((Marker) => iam.send(new ListRolesCommand({ Marker })), (r) => r.Roles, (r) => (r.IsTruncated ? r.Marker : undefined));
    return roles
      .filter((r) => !r.Path?.startsWith("/aws-service-role/"))
      .map((r) => {
        const services = trusted(r);
        return { name: r.RoleName!, arn: r.Arn, id: r.RoleId, detail: services.join(", ") || r.Description, services };
      });
  },
  "iam-policy": async () => {
    const iam = await client(IAMClient);
    const [local, aws] = await Promise.all(
      (["Local", "AWS"] as const).map((Scope) => collect((Marker) => iam.send(new ListPoliciesCommand({ Marker, Scope })), (r) => r.Policies, (r) => (r.IsTruncated ? r.Marker : undefined), 5000)),
    );
    return [
      ...local.map((p) => ({ name: p.PolicyName!, arn: p.Arn, detail: p.Description, group: "Customer managed" })),
      ...aws.map((p) => ({ name: p.PolicyName!, arn: p.Arn, detail: p.Description, group: "AWS managed", also: [p.Path ?? ""] })),
    ];
  },
  "iam-user": async () => {
    const iam = await client(IAMClient);
    const users = await collect((Marker) => iam.send(new ListUsersCommand({ Marker })), (r) => r.Users, (r) => (r.IsTruncated ? r.Marker : undefined));
    return users.map((u) => ({ name: u.UserName!, arn: u.Arn, id: u.UserId }));
  },
  "iam-group": async () => {
    const iam = await client(IAMClient);
    const groups = await collect((Marker) => iam.send(new ListGroupsCommand({ Marker })), (r) => r.Groups, (r) => (r.IsTruncated ? r.Marker : undefined));
    return groups.map((g) => ({ name: g.GroupName!, arn: g.Arn, id: g.GroupId }));
  },
  "iam-instance-profile": async () => {
    const iam = await client(IAMClient);
    const profiles = await collect((Marker) => iam.send(new ListInstanceProfilesCommand({ Marker })), (r) => r.InstanceProfiles, (r) => (r.IsTruncated ? r.Marker : undefined));
    return profiles.map((p) => ({ name: p.InstanceProfileName!, arn: p.Arn, id: p.InstanceProfileId, detail: p.Roles?.map((r) => r.RoleName).join(", ") }));
  },
  "kms-key": async () => {
    const kms = await client(KMSClient);
    const [keys, aliases] = await Promise.all([
      collect((Marker) => kms.send(new ListKeysCommand({ Marker })), (r) => r.Keys, (r) => (r.Truncated ? r.NextMarker : undefined)),
      collect((Marker) => kms.send(new ListAliasesCommand({ Marker })), (r) => r.Aliases, (r) => (r.Truncated ? r.NextMarker : undefined)),
    ]);
    const named = new Map<string, string[]>();
    for (const a of aliases) if (a.TargetKeyId) named.set(a.TargetKeyId, [...(named.get(a.TargetKeyId) ?? []), a.AliasName!]);
    const own = keys.map((k) => {
      const names = named.get(k.KeyId!) ?? [];
      const managed = names.some((n) => n.startsWith("alias/aws/"));
      return { name: names[0] ?? k.KeyId!, arn: k.KeyArn, id: k.KeyId, detail: names.length ? k.KeyId : undefined, also: names, group: managed ? "AWS managed" : "Customer managed" };
    });
    // AWS managed aliases a service creates on first use: offered even before
    // the key exists, as AWS's console does.
    const pending = aliases.filter((a) => !a.TargetKeyId && a.AliasName?.startsWith("alias/aws/")).map((a) => ({ name: a.AliasName!, arn: a.AliasArn, id: a.AliasName, group: "AWS managed" }));
    return [...own, ...pending];
  },
  "sns-topic": async () => {
    const sns = await client(SNSClient);
    const topics = await collect((NextToken) => sns.send(new ListTopicsCommand({ NextToken })), (r) => r.Topics, (r) => r.NextToken);
    return topics.map((t) => ({ name: t.TopicArn!.split(":").pop()!, arn: t.TopicArn }));
  },
  "sqs-queue": async () => {
    const [sqs, acct, r] = await Promise.all([client(SQSClient), account(), region()]);
    const urls = await collect((NextToken) => sqs.send(new ListQueuesCommand({ NextToken, MaxResults: 1000 })), (r) => r.QueueUrls, (r) => r.NextToken);
    return urls.map((url) => {
      const parts = url.split("/");
      const name = parts.pop()!;
      const owner = parts.pop() || acct;
      return { name, url, arn: `arn:aws:sqs:${r}:${owner}:${name}`, detail: name.endsWith(".fifo") ? "FIFO" : undefined };
    });
  },
  "s3-bucket": async () => {
    const out = await (await client(S3Client, { forcePathStyle: true })).send(new ListBucketsCommand({}));
    return (out.Buckets ?? []).map((b) => ({ name: b.Name!, arn: `arn:aws:s3:::${b.Name}`, detail: b.BucketRegion }));
  },
  "lambda-function": async () => {
    const lambda = await client(LambdaClient);
    const fns = await collect((Marker) => lambda.send(new ListFunctionsCommand({ Marker })), (r) => r.Functions, (r) => r.NextMarker);
    return fns.map((f) => ({ name: f.FunctionName!, arn: f.FunctionArn, detail: f.Runtime ?? f.PackageType }));
  },
  "log-group": async () => {
    const logs = await client(CloudWatchLogsClient);
    const groups = await collect((nextToken) => logs.send(new DescribeLogGroupsCommand({ nextToken })), (r) => r.logGroups, (r) => r.nextToken);
    return groups.map((g) => ({ name: g.logGroupName!, arn: g.logGroupArn ?? g.arn?.replace(/:\*$/, ""), also: g.arn ? [g.arn] : [], detail: g.retentionInDays ? `${g.retentionInDays} days` : undefined }));
  },
  "kinesis-stream": async () => {
    const kinesis = await client(KinesisClient);
    const streams = await collect((NextToken) => kinesis.send(new ListStreamsCommand({ NextToken })), (r) => r.StreamSummaries, (r) => (r.HasMoreStreams ? r.NextToken : undefined));
    return streams.map((s) => ({ name: s.StreamName!, arn: s.StreamARN, detail: s.StreamModeDetails?.StreamMode === "ON_DEMAND" ? "On-demand" : s.StreamStatus }));
  },
  "firehose-stream": async () => {
    const [firehose, acct, r] = await Promise.all([client(FirehoseClient), account(), region()]);
    const names: string[] = [];
    let start: string | undefined;
    for (;;) {
      const out = await firehose.send(new ListDeliveryStreamsCommand({ ExclusiveStartDeliveryStreamName: start, Limit: 100 }));
      names.push(...(out.DeliveryStreamNames ?? []));
      if (!out.HasMoreDeliveryStreams || !out.DeliveryStreamNames?.length) break;
      start = out.DeliveryStreamNames.at(-1);
    }
    return names.map((name) => ({ name, arn: `arn:aws:firehose:${r}:${acct}:deliverystream/${name}` }));
  },
  secret: async () => {
    const sm = await client(SecretsManagerClient);
    const secrets = await collect((NextToken) => sm.send(new ListSecretsCommand({ NextToken })), (r) => r.SecretList, (r) => r.NextToken);
    return secrets.map((s) => ({ name: s.Name!, arn: s.ARN, detail: s.Description }));
  },
  "ssm-parameter": async () => {
    const ssm = await client(SSMClient);
    const params = await collect((NextToken) => ssm.send(new DescribeParametersCommand({ NextToken })), (r) => r.Parameters, (r) => r.NextToken);
    return params.map((p) => ({ name: p.Name!, arn: p.ARN, detail: p.Type }));
  },
  "private-ca": async () => {
    const pca = await client(ACMPCAClient);
    const cas = await collect((NextToken) => pca.send(new ListCertificateAuthoritiesCommand({ NextToken })), (r) => r.CertificateAuthorities, (r) => r.NextToken);
    return cas.map((c) => ({
      name: c.CertificateAuthorityConfiguration?.Subject?.CommonName ?? c.Arn!.split("/").pop()!,
      arn: c.Arn,
      detail: [c.Type === "ROOT" ? "Root" : "Subordinate", c.Status?.toLowerCase()].filter(Boolean).join(" · "),
      group: c.Status === "ACTIVE" ? undefined : "Not active",
    }));
  },
  certificate: async () => {
    const acm = await client(ACMClient);
    const certs = await collect((NextToken) => acm.send(new ListCertificatesCommand({ NextToken })), (r) => r.CertificateSummaryList, (r) => r.NextToken);
    return certs.map((c) => ({ name: c.DomainName ?? c.CertificateArn!.split("/").pop()!, arn: c.CertificateArn, detail: c.Status?.toLowerCase().replace(/_/g, " "), group: c.Status === "ISSUED" ? undefined : "Not issued" }));
  },
  "event-bus": async () => {
    const events = await client(EventBridgeClient);
    const buses = await collect((NextToken) => events.send(new ListEventBusesCommand({ NextToken })), (r) => r.EventBuses, (r) => r.NextToken);
    return buses.map((b) => ({ name: b.Name!, arn: b.Arn, detail: b.Description }));
  },
  vpc: async () => {
    const ec2 = await client(EC2Client);
    const vpcs = await collect((NextToken) => ec2.send(new DescribeVpcsCommand({ NextToken })), (r) => r.Vpcs, (r) => r.NextToken);
    return vpcs.map((v) => ({ name: nameTag(v.Tags) ?? (v.IsDefault ? "Default VPC" : v.VpcId!), id: v.VpcId, detail: [v.CidrBlock, nameTag(v.Tags) || v.IsDefault ? v.VpcId : undefined].filter(Boolean).join(" · "), also: [v.VpcId!] }));
  },
  subnet: async () => {
    const ec2 = await client(EC2Client);
    const subnets = await collect((NextToken) => ec2.send(new DescribeSubnetsCommand({ NextToken })), (r) => r.Subnets, (r) => r.NextToken);
    return subnets.map((s) => ({
      name: nameTag(s.Tags) ?? s.SubnetId!,
      id: s.SubnetId,
      arn: s.SubnetArn,
      vpc: s.VpcId,
      detail: [s.AvailabilityZone, s.CidrBlock, s.MapPublicIpOnLaunch ? "public" : undefined].filter(Boolean).join(" · "),
      group: s.VpcId,
      also: [s.SubnetId!],
    }));
  },
  "security-group": async () => {
    const ec2 = await client(EC2Client);
    const groups = await collect((NextToken) => ec2.send(new DescribeSecurityGroupsCommand({ NextToken })), (r) => r.SecurityGroups, (r) => r.NextToken);
    return groups.map((g) => ({ name: g.GroupName!, id: g.GroupId, arn: g.SecurityGroupArn, vpc: g.VpcId, detail: [g.GroupId, g.Description].filter(Boolean).join(" · "), group: g.VpcId, also: [g.GroupId!] }));
  },
  "ec2-instance": async () => {
    const ec2 = await client(EC2Client);
    const reservations = await collect((NextToken) => ec2.send(new DescribeInstancesCommand({ NextToken })), (r) => r.Reservations, (r) => r.NextToken);
    return reservations
      .flatMap((r) => r.Instances ?? [])
      .filter((i) => i.State?.Name !== "terminated")
      .map((i) => ({ name: nameTag(i.Tags) ?? i.InstanceId!, id: i.InstanceId, vpc: i.VpcId, detail: [i.InstanceType, i.State?.Name, nameTag(i.Tags) ? i.InstanceId : undefined].filter(Boolean).join(" · "), also: [i.InstanceId!] }));
  },
  "ecr-repository": async () => {
    const ecr = await client(ECRClient);
    const repos = await collect((nextToken) => ecr.send(new DescribeRepositoriesCommand({ nextToken })), (r) => r.repositories, (r) => r.nextToken);
    return repos.map((r) => ({ name: r.repositoryName!, arn: r.repositoryArn, url: r.repositoryUri }));
  },
  "target-group": async () => {
    const elb = await client(ElasticLoadBalancingV2Client);
    const groups = await collect((Marker) => elb.send(new DescribeTargetGroupsCommand({ Marker })), (r) => r.TargetGroups, (r) => r.NextMarker);
    return groups.map((g) => ({ name: g.TargetGroupName!, arn: g.TargetGroupArn, vpc: g.VpcId, detail: [g.TargetType, g.Protocol && `${g.Protocol}:${g.Port ?? ""}`].filter(Boolean).join(" · ") }));
  },
  "load-balancer": async () => {
    const elb = await client(ElasticLoadBalancingV2Client);
    const lbs = await collect((Marker) => elb.send(new DescribeLoadBalancersCommand({ Marker })), (r) => r.LoadBalancers, (r) => r.NextMarker);
    return lbs.map((l) => ({ name: l.LoadBalancerName!, arn: l.LoadBalancerArn, vpc: l.VpcId, detail: [l.Type, l.Scheme].filter(Boolean).join(" · ") }));
  },
  "event-rule": async () => {
    const events = await client(EventBridgeClient);
    const buses = await collect((NextToken) => events.send(new ListEventBusesCommand({ NextToken })), (r) => r.EventBuses, (r) => r.NextToken);
    const rules = await Promise.all(
      buses.map((b) => collect((NextToken) => events.send(new ListRulesCommand({ NextToken, EventBusName: b.Name })), (r) => r.Rules, (r) => r.NextToken)),
    );
    return rules.flat().map((r) => ({
      name: r.Name!,
      arn: r.Arn,
      detail: r.ScheduleExpression ?? (r.State === "DISABLED" ? "disabled" : undefined),
      group: r.EventBusName && r.EventBusName !== "default" ? r.EventBusName : undefined,
    }));
  },
  "cloudwatch-alarm": async () => {
    const cw = await client(CloudWatchClient);
    const out = await collect((NextToken) => cw.send(new DescribeAlarmsCommand({ NextToken, AlarmTypes: ["MetricAlarm", "CompositeAlarm"] })), (r) => [...(r.MetricAlarms ?? []), ...(r.CompositeAlarms ?? [])], (r) => r.NextToken);
    return out.map((a) => ({ name: a.AlarmName!, arn: a.AlarmArn, detail: a.StateValue?.toLowerCase() }));
  },
  "ecs-cluster": async () => {
    const ecs = await client(ECSClient);
    const arns = await collect((nextToken) => ecs.send(new ListClustersCommand({ nextToken })), (r) => r.clusterArns, (r) => r.nextToken);
    return arns.map((arn) => ({ name: arn.split("/").pop()!, arn }));
  },
  "rds-instance": async () => {
    const rds = await client(RDSClient);
    const dbs = await collect((Marker) => rds.send(new DescribeDBInstancesCommand({ Marker })), (r) => r.DBInstances, (r) => r.Marker);
    return dbs.map((d) => ({ name: d.DBInstanceIdentifier!, arn: d.DBInstanceArn, id: d.DbiResourceId, detail: [d.Engine, d.DBInstanceStatus].filter(Boolean).join(" · ") }));
  },
  "efs-file-system": async () => {
    const efs = await client(EFSClient);
    const fss = await collect((Marker) => efs.send(new DescribeFileSystemsCommand({ Marker })), (r) => r.FileSystems, (r) => r.NextMarker);
    return fss.map((f) => ({ name: f.Name ?? f.FileSystemId!, id: f.FileSystemId, arn: f.FileSystemArn, detail: f.Name ? f.FileSystemId : f.LifeCycleState, also: [f.FileSystemId!] }));
  },
};

/** The resources of one kind in the selected region (empty when listing fails). */
export async function listResources(kind: ResourceKind): Promise<ResourceOption[]> {
  try {
    return (await LISTERS[kind]()).map((o) => ({ ...o, kind }));
  } catch (e) {
    console.warn(`resources: ${kind}: ${e instanceof Error ? e.message : e}`);
    return [];
  }
}

const trustFor = (service: string) =>
  JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { Service: service.split(",").map((s) => s.trim()).filter(Boolean) }, Action: "sts:AssumeRole" }] });

/** Make a resource of `kind` from just a name, as the picker's "New ..."
 * row does. `service` is the principal a new role trusts. Throws the SDK's
 * error (shown in the picker) when AWS refuses. */
export async function createResource(kind: ResourceKind, name: string, opts: { service?: string } = {}): Promise<ResourceOption> {
  const [acct, r] = await Promise.all([account(), region()]);
  switch (kind) {
    case "iam-role": {
      const service = opts.service || "lambda.amazonaws.com";
      const out = await (await client(IAMClient)).send(new CreateRoleCommand({ RoleName: name, AssumeRolePolicyDocument: trustFor(service), Description: `Assumed by ${service}`, Tags: [{ Key: "mws:console", Value: "picker" }] }));
      return { kind, name, arn: out.Role!.Arn, id: out.Role!.RoleId, services: service.split(","), detail: service };
    }
    case "kms-key": {
      const kms = await client(KMSClient);
      const key = (await kms.send(new CreateKeyCommand({ Description: `Created from the console for ${name}` }))).KeyMetadata!;
      const alias = name.startsWith("alias/") ? name : `alias/${name}`;
      await kms.send(new CreateAliasCommand({ AliasName: alias, TargetKeyId: key.KeyId! }));
      return { kind, name: alias, arn: key.Arn, id: key.KeyId, also: [alias], group: "Customer managed" };
    }
    case "sns-topic": {
      const out = await (await client(SNSClient)).send(new CreateTopicCommand({ Name: name, ...(name.endsWith(".fifo") ? { Attributes: { FifoTopic: "true" } } : {}) }));
      return { kind, name, arn: out.TopicArn };
    }
    case "sqs-queue": {
      const out = await (await client(SQSClient)).send(new CreateQueueCommand({ QueueName: name, ...(name.endsWith(".fifo") ? { Attributes: { FifoQueue: "true" } } : {}) }));
      return { kind, name, url: out.QueueUrl, arn: `arn:aws:sqs:${r}:${acct}:${name}` };
    }
    case "s3-bucket": {
      await (await client(S3Client, { forcePathStyle: true })).send(new CreateBucketCommand({ Bucket: name, ...(r === "us-east-1" ? {} : { CreateBucketConfiguration: { LocationConstraint: r as never } }) }));
      return { kind, name, arn: `arn:aws:s3:::${name}` };
    }
    case "log-group": {
      await (await client(CloudWatchLogsClient)).send(new CreateLogGroupCommand({ logGroupName: name }));
      return { kind, name, arn: `arn:aws:logs:${r}:${acct}:log-group:${name}` };
    }
    case "kinesis-stream": {
      await (await client(KinesisClient)).send(new CreateStreamCommand({ StreamName: name, StreamModeDetails: { StreamMode: "ON_DEMAND" } }));
      return { kind, name, arn: `arn:aws:kinesis:${r}:${acct}:stream/${name}`, detail: "On-demand" };
    }
    case "event-bus": {
      const out = await (await client(EventBridgeClient)).send(new CreateEventBusCommand({ Name: name }));
      return { kind, name, arn: out.EventBusArn };
    }
    default:
      throw new Error(`The console cannot create a ${RESOURCE_KINDS[kind].noun} from a name`);
  }
}
