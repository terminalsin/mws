import { ActionForm } from "@mws-dashboard/ui";

import { putParameter } from "../routes/ssm/actions";
import { ParameterFields } from "./parameter-fields";

export interface ParameterDefaults {
  name?: string;
  value?: string;
  type?: string;
  tier?: string;
  keyId?: string;
  description?: string;
  allowedPattern?: string;
  dataType?: string;
  policies?: string;
  /** Saving over an existing parameter (its name is fixed). */
  overwrite?: boolean;
  /** A SecureString whose value is hidden: an empty value keeps it. */
  keepValue?: boolean;
  path?: string;
  taken?: string[];
}

/** Every PutParameter input: a new one starts from what it holds. */
export function ParameterForm({ defaults, keys, testId }: { defaults: ParameterDefaults; keys: string[]; testId?: string }) {
  return (
    <ActionForm action={putParameter} submit="Save" testId={testId}>
      <ParameterFields defaults={defaults} keys={keys} />
      {defaults.overwrite && <input type="hidden" name="overwrite" value="on" />}
    </ActionForm>
  );
}
