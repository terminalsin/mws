// Field rules for the Global Accelerator forms, from the model plus what
// the service itself enforces.
import type { Rule } from "@mws-dashboard/ui";
import { CreateAccelerator, UpdateEndpointGroup } from "@mws-dashboard/ui/model/global-accelerator";

// The model allows any 255 characters; Global Accelerator itself takes 64
// letters, digits and inner hyphens.
export const NAME: Rule = { ...CreateAccelerator.Name, maxLength: 64, pattern: "^[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?$", hint: "Letters, digits and inner hyphens" };

const ID = "(arn:aws:elasticloadbalancing:[a-z0-9-]+:\\d{12}:loadbalancer/(app|net)/.+|i-[0-9a-f]{8,17}|eipalloc-[0-9a-f]{8,17})";

/** One endpoint: a load balancer ARN, instance or EIP allocation, with an optional =weight. */
export const ENDPOINT: Rule = {
  type: "string",
  pattern: `^${ID}(=\\d{1,3})?$`,
  hint: "A load balancer ARN, i-… or eipalloc-…",
};

/** Endpoints, one per line (or comma-separated). */
export const ENDPOINTS: Rule = { type: "list", maxLength: 10, item: ENDPOINT, hint: "A load balancer ARN, i-… or eipalloc-…" };

export const GROUP_RULES = UpdateEndpointGroup;
