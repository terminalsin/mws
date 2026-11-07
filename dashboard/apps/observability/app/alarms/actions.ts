"use server";

import { SetAlarmStateCommand, type StateValue } from "@aws-sdk/client-cloudwatch";
import { act, type ActionResult } from "@mws-dashboard/aws";

import { cloudwatch } from "../../lib/clients";

/** Force an alarm into a state, as `aws cloudwatch set-alarm-state` does, to test its actions. */
export async function setState(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const state = (form.get("state") as StateValue) ?? "ALARM";
    await (await cloudwatch()).send(
      new SetAlarmStateCommand({ AlarmName: name, StateValue: state, StateReason: "Set from the MWS console" }),
    );
    return `${name} is now ${state}`;
  }, "/alarms");
}
