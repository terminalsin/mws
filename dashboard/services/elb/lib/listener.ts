// Listener and rule actions and conditions: read from the forms, and
// described for rows.
import type { Action, RuleCondition } from "@aws-sdk/client-elastic-load-balancing-v2";

import type { ActionDefaults, ActionKind, ConditionDefaults } from "./action-fields";

const get = (form: FormData, name: string) => {
  const v = form.get(name);
  return typeof v === "string" ? v.trim() : "";
};
const list = (v: string) => v.split(",").map((s) => s.trim()).filter(Boolean);

/** What a load balancer type's listeners may do: Network and Gateway Load
 * Balancers only forward. */
export function actionKinds(lbType: string | undefined): ActionKind[] {
  return lbType === "application" || !lbType ? ["forward", "redirect", "fixed-response"] : ["forward"];
}

/** The action the form describes, or a message naming the field it needs. */
export function actionFrom(form: FormData): Action[] | { field: string; message: string } {
  const type = (get(form, "actionType") || "forward") as ActionKind;
  if (type === "redirect") {
    return [
      {
        Type: "redirect",
        RedirectConfig: {
          Protocol: get(form, "rProtocol") || undefined,
          Port: get(form, "rPort") || undefined,
          Host: get(form, "rHost") || undefined,
          Path: get(form, "rPath") || undefined,
          Query: get(form, "rQuery") || undefined,
          StatusCode: (get(form, "rStatus") || "HTTP_301") as "HTTP_301" | "HTTP_302",
        },
      },
    ];
  }
  if (type === "fixed-response") {
    return [{ Type: "fixed-response", FixedResponseConfig: { StatusCode: get(form, "fStatus") || "404", ContentType: get(form, "fType") || undefined, MessageBody: get(form, "fBody") || undefined } }];
  }
  const groups = form.getAll("group").filter((v): v is string => typeof v === "string" && !!v);
  if (!groups.length) return { field: "group", message: "Choose a target group" };
  if (groups.length === 1) return [{ Type: "forward", TargetGroupArn: groups[0] }];
  const stick = Number(get(form, "stickiness") || 0);
  return [
    {
      Type: "forward",
      ForwardConfig: {
        TargetGroups: groups.map((TargetGroupArn) => ({ TargetGroupArn, Weight: Number(get(form, `weight:${TargetGroupArn}`) || 1) })),
        TargetGroupStickinessConfig: stick > 0 ? { Enabled: true, DurationSeconds: stick } : undefined,
      },
    },
  ];
}

/** The conditions the form describes (at least one is needed). */
export function conditionsFrom(form: FormData): RuleCondition[] {
  const out: RuleCondition[] = [];
  const host = list(get(form, "host"));
  if (host.length) out.push({ Field: "host-header", HostHeaderConfig: { Values: host } });
  const path = list(get(form, "path"));
  if (path.length) out.push({ Field: "path-pattern", PathPatternConfig: { Values: path } });
  const method = list(get(form, "method")).map((m) => m.toUpperCase());
  if (method.length) out.push({ Field: "http-request-method", HttpRequestMethodConfig: { Values: method } });
  const ips = list(get(form, "sourceIp"));
  if (ips.length) out.push({ Field: "source-ip", SourceIpConfig: { Values: ips } });
  const header = get(form, "headerName");
  if (header) out.push({ Field: "http-header", HttpHeaderConfig: { HttpHeaderName: header, Values: list(get(form, "headerValues")) } });
  const query = list(get(form, "query"));
  if (query.length)
    out.push({
      Field: "query-string",
      QueryStringConfig: {
        Values: query.map((q) => {
          const [k, ...v] = q.split("=");
          return v.length ? { Key: k, Value: v.join("=") } : { Value: k };
        }),
      },
    });
  return out;
}

export function actionDefaults(actions: Action[] | undefined): ActionDefaults {
  const a = actions?.find((x) => x.Type === "forward" || x.Type === "redirect" || x.Type === "fixed-response");
  if (!a) return { type: "forward" };
  if (a.Type === "redirect") {
    const r = a.RedirectConfig;
    return { type: "redirect", redirect: { protocol: r?.Protocol, host: r?.Host, port: r?.Port, path: r?.Path, query: r?.Query, status: r?.StatusCode } };
  }
  if (a.Type === "fixed-response") return { type: "fixed-response", fixed: { status: a.FixedResponseConfig?.StatusCode, contentType: a.FixedResponseConfig?.ContentType, body: a.FixedResponseConfig?.MessageBody } };
  const groups = a.ForwardConfig?.TargetGroups?.length
    ? Object.fromEntries(a.ForwardConfig.TargetGroups.map((g) => [g.TargetGroupArn!, g.Weight ?? 1]))
    : a.TargetGroupArn
      ? { [a.TargetGroupArn]: 1 }
      : {};
  const stick = a.ForwardConfig?.TargetGroupStickinessConfig;
  return { type: "forward", groups, stickiness: stick?.Enabled ? stick.DurationSeconds : 0 };
}

export function conditionDefaults(conditions: RuleCondition[] | undefined): ConditionDefaults {
  const find = (f: string) => conditions?.find((c) => c.Field === f);
  const join = (v: string[] | undefined) => v?.join(", ") || undefined;
  const header = find("http-header");
  return {
    host: join(find("host-header")?.HostHeaderConfig?.Values ?? find("host-header")?.Values),
    path: join(find("path-pattern")?.PathPatternConfig?.Values ?? find("path-pattern")?.Values),
    method: join(find("http-request-method")?.HttpRequestMethodConfig?.Values),
    sourceIp: join(find("source-ip")?.SourceIpConfig?.Values),
    headerName: header?.HttpHeaderConfig?.HttpHeaderName,
    headerValues: join(header?.HttpHeaderConfig?.Values),
    query: join(find("query-string")?.QueryStringConfig?.Values?.map((q) => (q.Key ? `${q.Key}=${q.Value}` : (q.Value ?? "")))),
  };
}

/** "→ api (80%), web (20%)", "↪ HTTPS:443 301", "404 Not found". */
export function describeAction(a: Action, groupName: (arn: string | undefined) => string | undefined) {
  if (a.Type === "forward") {
    const groups = a.ForwardConfig?.TargetGroups?.length ? a.ForwardConfig.TargetGroups : [{ TargetGroupArn: a.TargetGroupArn, Weight: undefined }];
    const total = groups.reduce((n, g) => n + (g.Weight ?? 1), 0);
    return `→ ${groups.map((g) => (groups.length > 1 ? `${groupName(g.TargetGroupArn)} (${Math.round(((g.Weight ?? 1) / (total || 1)) * 100)}%)` : groupName(g.TargetGroupArn))).join(", ")}`;
  }
  if (a.Type === "redirect") {
    const r = a.RedirectConfig;
    return `↪ ${r?.Protocol ?? "#{protocol}"}://${r?.Host ?? "#{host}"}:${r?.Port ?? "#{port}"}${r?.Path ?? "/#{path}"} ${r?.StatusCode?.replace("HTTP_", "") ?? ""}`;
  }
  if (a.Type === "fixed-response") return `${a.FixedResponseConfig?.StatusCode} ${a.FixedResponseConfig?.MessageBody ?? ""}`;
  if (a.Type === "authenticate-oidc") return `OIDC ${a.AuthenticateOidcConfig?.Issuer ?? ""}`;
  if (a.Type === "authenticate-cognito") return `Cognito ${a.AuthenticateCognitoConfig?.UserPoolDomain ?? ""}`;
  return a.Type ?? "";
}

/** "Host api.example.com · Path /v1/*". */
export function describeConditions(conditions: RuleCondition[] | undefined): string {
  return (conditions ?? [])
    .map((c) => {
      switch (c.Field) {
        case "host-header":
          return `Host ${(c.HostHeaderConfig?.Values ?? c.Values ?? []).join(", ")}`;
        case "path-pattern":
          return `Path ${(c.PathPatternConfig?.Values ?? c.Values ?? []).join(", ")}`;
        case "http-request-method":
          return `Method ${c.HttpRequestMethodConfig?.Values?.join(", ")}`;
        case "source-ip":
          return `Source ${c.SourceIpConfig?.Values?.join(", ")}`;
        case "http-header":
          return `${c.HttpHeaderConfig?.HttpHeaderName}: ${c.HttpHeaderConfig?.Values?.join(", ")}`;
        case "query-string":
          return `?${c.QueryStringConfig?.Values?.map((q) => (q.Key ? `${q.Key}=${q.Value}` : q.Value)).join("&")}`;
        default:
          return c.Field ?? "";
      }
    })
    .join(" · ");
}

/** The target groups an action forwards to. */
export function forwardGroups(actions: Action[] | undefined): string[] {
  return (actions ?? []).flatMap((a) => (a.Type !== "forward" ? [] : a.ForwardConfig?.TargetGroups?.length ? a.ForwardConfig.TargetGroups.map((g) => g.TargetGroupArn!) : a.TargetGroupArn ? [a.TargetGroupArn] : []));
}
