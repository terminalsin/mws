import { Segments } from "@mws-dashboard/ui";

type Section = "findings" | "malware" | "lists" | "suppression" | "settings";

/** GuardDuty's sections, as AWS's sidebar names them. */
export function GuardDutyNav({ active }: { active: Section }) {
  const items: [Section, string, string][] = [
    ["findings", "Findings", "/guardduty"],
    ["malware", "Malware Protection for S3", "/guardduty/malware"],
    ["lists", "Lists", "/guardduty/lists"],
    ["suppression", "Suppression rules", "/guardduty/suppression"],
    ["settings", "Settings", "/guardduty/settings"],
  ];
  return <Segments label="GuardDuty" items={items.map(([id, label, href]) => ({ label, href, active: id === active }))} />;
}
