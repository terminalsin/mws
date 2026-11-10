import { Segments } from "@mws-dashboard/ui";

/** Systems Manager's sections. The catalog gives the service one sidebar
 * entry, so the sections are line tabs under each page's title. */
export const SECTIONS = [
  { id: "parameters", label: "Parameter Store", href: "/ssm" },
  { id: "nodes", label: "Fleet Manager", href: "/ssm/nodes" },
  { id: "commands", label: "Run Command", href: "/ssm/commands" },
  { id: "documents", label: "Documents", href: "/ssm/documents" },
  { id: "automation", label: "Automation", href: "/ssm/automation" },
  { id: "associations", label: "State Manager", href: "/ssm/associations" },
  { id: "windows", label: "Maintenance Windows", href: "/ssm/windows" },
  { id: "sessions", label: "Session Manager", href: "/ssm/sessions" },
  { id: "opsitems", label: "OpsCenter", href: "/ssm/opsitems" },
] as const;

export function SsmNav({ active }: { active: (typeof SECTIONS)[number]["id"] }) {
  return <Segments label="Systems Manager" items={SECTIONS.map((s) => ({ label: s.label, href: s.href, active: s.id === active }))} />;
}
