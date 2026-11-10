"use client";

// The create forms open on a choice of tiles: the load balancer's type, the
// target group's target type. Each fills a free name and the values that
// type takes (a Lambda group has no protocol, port or VPC; an ALB target is
// TCP), and folds the rarely changed settings under More.

import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import { CreateLoadBalancer, CreateTargetGroup } from "@mws-dashboard/ui/model/elbv2";
import { MoreFields, PresetGallery, freeName, type PresetItem } from "@mws-dashboard/ui/presets";
import { useState } from "react";

import { HEALTH_PATH, LB_NAME, PORT, TG_NAME } from "./rules";

export interface VpcChoice {
  id: string;
  label: string;
  isDefault?: boolean;
}

function VpcSelect({ vpcs, member }: { vpcs: VpcChoice[]; member: string }) {
  return (
    <Field label="VPC" member={member}>
      <select name="vpc" required defaultValue={(vpcs.find((v) => v.isDefault) ?? vpcs[0])?.id}>
        {vpcs.map((v) => (
          <option key={v.id} value={v.id}>
            {v.label}
          </option>
        ))}
      </select>
    </Field>
  );
}

interface LbType extends PresetItem {
  id: "application" | "network" | "gateway";
  base: string;
}

const LB_TYPES: LbType[] = [
  { id: "application", base: "alb", label: "Application", icon: "resource/ElasticLoadBalancingApplicationLoadBalancer", title: "HTTP and HTTPS, routed by host and path" },
  { id: "network", base: "nlb", label: "Network", icon: "resource/ElasticLoadBalancingNetworkLoadBalancer", title: "TCP, UDP and TLS at very low latency" },
  { id: "gateway", base: "gwlb", label: "Gateway", icon: "resource/ElasticLoadBalancingGatewayLoadBalancer", title: "Third-party appliances over GENEVE" },
];

export function LoadBalancerFields({ names, vpcs }: { names: string[]; vpcs: VpcChoice[] }) {
  const [type, setType] = useState(LB_TYPES[0]);
  return (
    <>
      <PresetGallery presets={LB_TYPES} chosen={type.id} choose={setType} label="Type" testId="lb-type" />
      <input type="hidden" name="type" value={type.id} />
      <div key={type.id} className="preset-fields">
        <Field label="Name" rule={LB_NAME} taken={names} unique>
          <input name="name" required maxLength={32} autoFocus defaultValue={freeName(type.base, names)} />
        </Field>
        <div className="form-row">
          <VpcSelect vpcs={vpcs} member="Subnets" />
          {type.id !== "gateway" && (
            <Field label="Scheme" rule={CreateLoadBalancer.Scheme}>
              <select name="scheme" defaultValue="internet-facing">
                <option value="internet-facing">Internet-facing</option>
                <option value="internal">Internal</option>
              </select>
            </Field>
          )}
        </div>
        <MoreFields>
          <Field label="IP address type" rule={CreateLoadBalancer.IpAddressType}>
            <select name="ipType" defaultValue="">
              <option value="">IPv4</option>
              <option value="dualstack">Dualstack</option>
            </select>
          </Field>
        </MoreFields>
      </div>
    </>
  );
}

interface TargetType extends PresetItem {
  id: "instance" | "ip" | "lambda" | "alb";
  base: string;
  protocol?: string;
}

const TARGET_TYPES: TargetType[] = [
  { id: "instance", base: "web", protocol: "HTTP", label: "Instances", icon: "resource/AmazonEC2Instance" },
  { id: "ip", base: "web", protocol: "HTTP", label: "IP addresses", icon: "resource/AmazonVPCElasticNetworkInterface" },
  { id: "lambda", base: "lambda", label: "Lambda", icon: "resource/AWSLambdaLambdaFunction", title: "One Lambda function" },
  { id: "alb", base: "alb-targets", protocol: "TCP", label: "ALB", icon: "resource/ElasticLoadBalancingApplicationLoadBalancer", title: "An Application Load Balancer behind a Network Load Balancer" },
];

const PROTOCOLS = ["HTTP", "HTTPS", "TCP", "UDP", "TLS", "TCP_UDP", "GENEVE"];

export function TargetGroupFields({ names, vpcs }: { names: string[]; vpcs: VpcChoice[] }) {
  const [type, setType] = useState(TARGET_TYPES[0]);
  const lambda = type.id === "lambda";
  return (
    <>
      <PresetGallery presets={TARGET_TYPES} chosen={type.id} choose={setType} label="Target type" testId="tg-type" />
      <input type="hidden" name="targetType" value={type.id} />
      <div key={type.id} className="preset-fields">
        <Field label="Name" rule={TG_NAME} taken={names} unique>
          <input name="name" required maxLength={32} autoFocus defaultValue={freeName(type.base, names)} />
        </Field>
        {!lambda && (
          <>
            <div className="form-row">
              <Field label="Protocol" rule={CreateTargetGroup.Protocol}>
                <select name="protocol" defaultValue={type.protocol}>
                  {(type.id === "alb" ? ["TCP"] : PROTOCOLS).map((p) => (
                    <option key={p}>{p}</option>
                  ))}
                </select>
              </Field>
              <Field label="Port" rule={PORT} format="port">
                <input name="port" type="number" defaultValue={80} />
              </Field>
            </div>
            <VpcSelect vpcs={vpcs} member="VpcId" />
          </>
        )}
        <Field label="Health check path" rule={HEALTH_PATH}>
          <input name="healthPath" placeholder="/" />
        </Field>
        <MoreFields>
          <Field label="Success codes" rule={{ pattern: "^\\d{1,3}([,-]\\d{1,3})*$", hint: "Like 200 or 200-299" }} member="Matcher.HttpCode">
            <input name="matcher" placeholder="200" />
          </Field>
          {!lambda && (
            <div className="form-row">
              <Field label="Protocol version (HTTP/HTTPS)" rule={CreateTargetGroup.ProtocolVersion}>
                <select name="protocolVersion" defaultValue="">
                  <option value="">HTTP1</option>
                  <option value="HTTP2">HTTP2</option>
                  <option value="GRPC">gRPC</option>
                </select>
              </Field>
              <Field label="IP address type" rule={CreateTargetGroup.IpAddressType}>
                <select name="ipType" defaultValue="">
                  <option value="">IPv4</option>
                  <option value="ipv6">IPv6</option>
                </select>
              </Field>
            </div>
          )}
        </MoreFields>
      </div>
    </>
  );
}
