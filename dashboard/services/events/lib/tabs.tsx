import { Segments } from "@mws-dashboard/ui";

/** EventBridge's sections, as the AWS console's sidebar has them. */
export function EventsTabs({ active }: { active: "rules" | "archives" | "replays" | "destinations" | "connections" }) {
  return (
    <Segments
      label="EventBridge"
      items={[
        { label: "Rules", href: "/events", active: active === "rules" },
        { label: "Archives", href: "/events/archives", active: active === "archives" },
        { label: "Replays", href: "/events/replays", active: active === "replays" },
        { label: "API destinations", href: "/events/api-destinations", active: active === "destinations" },
        { label: "Connections", href: "/events/connections", active: active === "connections" },
      ]}
    />
  );
}
