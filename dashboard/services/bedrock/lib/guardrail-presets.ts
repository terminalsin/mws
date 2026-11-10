// Guardrail policies and the templates the create sheet opens on. Plain
// data, shared by the server actions and the client form.

export const FILTERS = ["HATE", "INSULTS", "SEXUAL", "VIOLENCE", "MISCONDUCT", "PROMPT_ATTACK"] as const;
export const PII = ["EMAIL", "PHONE", "NAME", "ADDRESS", "AGE", "US_SOCIAL_SECURITY_NUMBER", "CREDIT_DEBIT_CARD_NUMBER", "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "IP_ADDRESS", "PASSWORD", "URL", "USERNAME"];

export type Strength = "NONE" | "LOW" | "MEDIUM" | "HIGH";

export interface GuardrailTemplate {
  id: string;
  label: string;
  title: string;
  /** Every content filter's strength (prompts and responses). */
  strength: Strength;
  topics?: string;
  profanity?: boolean;
  pii?: Record<string, "ANONYMIZE" | "BLOCK">;
  grounding?: number;
  relevance?: number;
}

const SECRETS = { CREDIT_DEBIT_CARD_NUMBER: "BLOCK", US_SOCIAL_SECURITY_NUMBER: "BLOCK", AWS_ACCESS_KEY: "BLOCK", AWS_SECRET_KEY: "BLOCK", PASSWORD: "BLOCK" } as const;
const CONTACT = { EMAIL: "ANONYMIZE", PHONE: "ANONYMIZE", NAME: "ANONYMIZE", ADDRESS: "ANONYMIZE" } as const;

export const GUARDRAIL_TEMPLATES: GuardrailTemplate[] = [
  { id: "balanced", label: "Balanced", title: "Medium content filters and prompt attack detection", strength: "MEDIUM" },
  { id: "strict", label: "Strict", title: "High content filters, profanity, secrets blocked and contact details masked", strength: "HIGH", profanity: true, pii: { ...SECRETS, ...CONTACT } },
  {
    id: "support",
    label: "Support bot",
    title: "Stays off financial and legal advice, masks customers' contact details",
    strength: "MEDIUM",
    profanity: true,
    topics: "Investment advice: recommendations about stocks, funds or other investments\nLegal advice: guidance on legal rights, contracts or disputes",
    pii: { ...CONTACT },
  },
  { id: "privacy", label: "Privacy", title: "Masks personal data and blocks secrets, no content filters", strength: "NONE", pii: { ...SECRETS, ...CONTACT, IP_ADDRESS: "ANONYMIZE", USERNAME: "ANONYMIZE" } },
  { id: "grounded", label: "Grounded", title: "Checks answers against the source (RAG) and the question", strength: "MEDIUM", grounding: 0.75, relevance: 0.75 },
  { id: "custom", label: "Custom", title: "Everything off: choose each policy", strength: "NONE" },
];
