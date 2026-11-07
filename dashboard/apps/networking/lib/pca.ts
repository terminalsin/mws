export const CA_TONE: Record<string, "good" | "warn" | "bad" | "neutral"> = {
  ACTIVE: "good",
  PENDING_CERTIFICATE: "warn",
  CREATING: "warn",
  DISABLED: "neutral",
  DELETED: "bad",
  EXPIRED: "bad",
  FAILED: "bad",
};
