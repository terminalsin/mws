import "server-only";

import { DescribeAddressesCommand, DescribeInstancesCommand, EC2Client } from "@aws-sdk/client-ec2";
import { DescribeLoadBalancersCommand, ElasticLoadBalancingV2Client } from "@aws-sdk/client-elastic-load-balancing-v2";
import { GlobalAcceleratorClient } from "@aws-sdk/client-global-accelerator";
import { client } from "@mws-dashboard/aws";

export const ga = () => client(GlobalAcceleratorClient);

export const ICONS = {
  ga: "service/AWSGlobalAccelerator",
};

/** What an endpoint group can point at in the console's region: load
 * balancer ARNs, instance ids and EIP allocations (suggestions only, so a
 * failed lookup just offers nothing). */
export async function endpointCandidates(): Promise<string[]> {
  const quiet = <T,>(p: Promise<T[]>) => p.catch(() => [] as T[]);
  const [ec2, elb] = await Promise.all([client(EC2Client), client(ElasticLoadBalancingV2Client)]);
  const [lbs, instances, eips] = await Promise.all([
    quiet(elb.send(new DescribeLoadBalancersCommand({})).then((r) => (r.LoadBalancers ?? []).filter((l) => l.Type !== "gateway").map((l) => l.LoadBalancerArn!))),
    quiet(
      ec2
        .send(new DescribeInstancesCommand({ Filters: [{ Name: "instance-state-name", Values: ["pending", "running", "stopped"] }] }))
        .then((r) => (r.Reservations ?? []).flatMap((x) => x.Instances ?? []).map((i) => i.InstanceId!)),
    ),
    quiet(ec2.send(new DescribeAddressesCommand({})).then((r) => (r.Addresses ?? []).flatMap((a) => (a.AllocationId ? [a.AllocationId] : [])))),
  ]);
  return [...lbs, ...instances, ...eips];
}
