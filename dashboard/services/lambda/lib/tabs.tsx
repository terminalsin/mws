import { Segments } from "@mws-dashboard/ui";

/** Functions and Layers, as the AWS console's Lambda sidebar has them. */
export function LambdaTabs({ active }: { active: "functions" | "layers" }) {
  return (
    <Segments
      label="Lambda"
      items={[
        { label: "Functions", href: "/lambda", active: active === "functions" },
        { label: "Layers", href: "/lambda/layers", active: active === "layers" },
      ]}
    />
  );
}
