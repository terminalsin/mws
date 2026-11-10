/** AWS managed policies people usually give a permission set. */
export const POLICIES = [
  "arn:aws:iam::aws:policy/AdministratorAccess",
  "arn:aws:iam::aws:policy/PowerUserAccess",
  "arn:aws:iam::aws:policy/ReadOnlyAccess",
  "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess",
  "arn:aws:iam::aws:policy/job-function/Billing",
];

/** AWS's predefined permission sets: a name, the one policy, a session length. */
export interface SetPreset {
  id: string;
  label: string;
  icon: string;
  policy?: string;
  description?: string;
  hours: number;
}

export const SET_PRESETS: SetPreset[] = [
  { id: "AdministratorAccess", label: "Administrator", icon: "category/SecurityIdentity", policy: POLICIES[0], description: "Full access to AWS services and resources", hours: 1 },
  { id: "PowerUserAccess", label: "Power user", icon: "resource/AWSIdentityAccessManagementPermissions", policy: POLICIES[1], description: "Full access except IAM and Organizations", hours: 4 },
  { id: "ReadOnlyAccess", label: "Read only", icon: "resource/AWSIdentityAccessManagementIAMAccessAnalyzer", policy: POLICIES[2], description: "Read access to all services and resources", hours: 4 },
  { id: "ViewOnlyAccess", label: "View only", icon: "category/ManagementTools", policy: POLICIES[3], description: "View resources and basic metadata", hours: 4 },
  { id: "Billing", label: "Billing", icon: "category/CloudFinancialManagement", policy: POLICIES[4], description: "View and manage billing", hours: 1 },
  { id: "custom", label: "Custom", icon: "resource/AWSIdentityAccessManagementAddon", hours: 1 },
];
