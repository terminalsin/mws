import { Segments } from "@mws-dashboard/ui";

/** CloudFormation's sections, as AWS's sidebar names them. */
export function CloudFormationNav({ active }: { active: "stacks" | "stacksets" | "exports" }) {
  return (
    <Segments
      items={[
        { label: "Stacks", href: "/cloudformation", active: active === "stacks" },
        { label: "StackSets", href: "/cloudformation/stacksets", active: active === "stacksets" },
        { label: "Exports", href: "/cloudformation/exports", active: active === "exports" },
      ]}
    />
  );
}

/** A stack's name from its ARN (`arn:aws:cloudformation:...:stack/<name>/<id>`). */
export const stackName = (arn: string | undefined) => (arn?.startsWith("arn:") ? (arn.split(":")[5]?.split("/")[1] ?? arn) : (arn ?? ""));
