//! Message move tasks: redrive messages out of a dead-letter queue, back
//! to the queues they came from or to one destination. Tasks run at
//! `MaxNumberOfMessagesPerSecond` (all at once when unset) and advance
//! whenever SQS is called, against the emulated clock.

use base64::Engine;
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::names::{authorize_queue, b64, invalid_parameter, parse_queue_arn};
use crate::state::{MoveTask, State};
use crate::Sqs;

fn not_found(message: &str) -> ServiceError {
    errors::resource_not_found(message.to_string())
}

impl Sqs {
    /// Advance running move tasks to `now`.
    pub(crate) fn progress(&self, st: &mut State, now: i64) {
        let mut moved_any = false;
        for i in 0..st.move_tasks.len() {
            if st.move_tasks[i].status != "RUNNING" {
                continue;
            }
            let task = st.move_tasks[i].clone();
            let budget = match task.max_per_second {
                Some(rate) => {
                    let elapsed = (now - task.started_at).max(0);
                    (i64::from(rate) * elapsed / 1000 - task.moved).max(0) as usize
                }
                None => usize::MAX,
            };
            let mut moved = 0usize;
            while moved < budget {
                let Some(source) = st.queues.get_mut(&task.source_arn) else {
                    st.move_tasks[i].status = "FAILED".into();
                    st.move_tasks[i].failure_reason = Some("AWS.SimpleQueueService.NonExistentQueue".into());
                    break;
                };
                source.expire(now);
                let Some(pos) = source.messages.iter().position(|m| m.visible(now)) else { break };
                let destination =
                    task.destination_arn.clone().or_else(|| source.messages[pos].dead_letter_source_arn.clone());
                let Some(dest) = destination.filter(|d| st.queues.contains_key(d)) else {
                    st.move_tasks[i].status = "FAILED".into();
                    st.move_tasks[i].failure_reason = Some("AWS.SimpleQueueService.NonExistentQueue".into());
                    break;
                };
                let source = st.queues.get_mut(&task.source_arn).expect("checked above");
                let mut m = source.messages.remove(pos);
                let target = st.queues.get_mut(&dest).expect("checked above");
                m.receipt_handle = None;
                m.receive_count = 0;
                m.first_receive_at = None;
                m.dead_letter_source_arn = None;
                m.visible_at = now;
                if target.fifo {
                    target.next_sequence += 1;
                    m.sequence_number =
                        Some((18_000_000_000_000_000_000u128 + target.next_sequence as u128).to_string());
                }
                target.messages.push(m);
                moved += 1;
                moved_any = true;
            }
            let t = &mut st.move_tasks[i];
            t.moved += moved as i64;
            if t.status == "RUNNING" && t.moved >= t.to_move {
                t.status = "COMPLETED".into();
            }
        }
        if moved_any {
            self.arrivals.notify_waiters();
        }
    }

    pub fn start_message_move_task(
        &self,
        ctx: &RequestContext,
        input: types::StartMessageMoveTaskRequest,
    ) -> Result<types::StartMessageMoveTaskResult, ServiceError> {
        if let Some(rate) = input.max_number_of_messages_per_second {
            if !(1..=500).contains(&rate) {
                return Err(invalid_parameter(
                    "MaxNumberOfMessagesPerSecond",
                    rate,
                    "Must be between 1 and 500, if provided.",
                ));
            }
        }
        let now = crate::names::now_ms(ctx);
        let mut st = self.lock();
        self.progress(&mut st, now);
        let source = st
            .queues
            .get(&input.source_arn)
            .ok_or_else(|| not_found("The resource that you specified for the SourceArn parameter doesn't exist."))?;
        authorize_queue(ctx, "sqs:StartMessageMoveTask", source)?;
        for action in ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"] {
            authorize_queue(ctx, action, source)?;
        }
        let is_dlq = st.queues.values().any(|q| q.redrive().is_some_and(|(t, _)| t == input.source_arn));
        if !is_dlq {
            return Err(errors::unsupported_operation("Source queue must be configured as a Dead Letter Queue."));
        }
        if let Some(dest) = &input.destination_arn {
            if parse_queue_arn(dest).is_none() || !st.queues.contains_key(dest) {
                return Err(not_found(
                    "The resource that you specified for the DestinationArn parameter doesn't exist.",
                ));
            }
            if dest == &input.source_arn {
                return Err(errors::unsupported_operation("The source and destination queues must be different."));
            }
            authorize_queue(ctx, "sqs:SendMessage", &st.queues[dest])?;
        }
        if st.move_tasks.iter().any(|t| t.source_arn == input.source_arn && t.status == "RUNNING") {
            return Err(errors::unsupported_operation(
                "There is already a task running. Only one active task is allowed for a source queue arn at a given time.",
            ));
        }
        let source = &st.queues[&input.source_arn];
        let to_move = source.messages.iter().filter(|m| m.visible(now)).count() as i64;
        let task_id = uuid::Uuid::new_v4().to_string();
        let handle = b64().encode(serde_json::json!({ "taskId": task_id, "sourceArn": input.source_arn }).to_string());
        st.move_tasks.push(MoveTask {
            task_handle: handle.clone(),
            source_arn: input.source_arn,
            destination_arn: input.destination_arn,
            max_per_second: input.max_number_of_messages_per_second,
            status: "RUNNING".into(),
            moved: 0,
            to_move,
            failure_reason: None,
            started_at: now,
        });
        self.progress(&mut st, now);
        Ok(types::StartMessageMoveTaskResult { task_handle: Some(handle) })
    }

    pub fn cancel_message_move_task(
        &self,
        ctx: &RequestContext,
        input: types::CancelMessageMoveTaskRequest,
    ) -> Result<types::CancelMessageMoveTaskResult, ServiceError> {
        let now = crate::names::now_ms(ctx);
        let mut st = self.lock();
        self.progress(&mut st, now);
        let missing = || not_found("Task does not exist.");
        let i = st.move_tasks.iter().position(|t| t.task_handle == input.task_handle).ok_or_else(missing)?;
        let source_arn = st.move_tasks[i].source_arn.clone();
        match st.queues.get(&source_arn) {
            Some(q) => authorize_queue(ctx, "sqs:CancelMessageMoveTask", q)?,
            None => ctx.authorize("sqs:CancelMessageMoveTask", &source_arn, ConditionContext::new())?,
        }
        let t = &mut st.move_tasks[i];
        if t.status != "RUNNING" {
            return Err(errors::unsupported_operation(format!(
                "The task is in {} status and can't be cancelled. Only RUNNING tasks can be cancelled.",
                t.status
            )));
        }
        t.status = "CANCELLED".into();
        Ok(types::CancelMessageMoveTaskResult { approximate_number_of_messages_moved: t.moved })
    }

    pub fn list_message_move_tasks(
        &self,
        ctx: &RequestContext,
        input: types::ListMessageMoveTasksRequest,
    ) -> Result<types::ListMessageMoveTasksResult, ServiceError> {
        let max = input.max_results.unwrap_or(1);
        if !(1..=10).contains(&max) {
            return Err(invalid_parameter("MaxResults", max, "Must be between 1 and 10, if provided."));
        }
        let now = crate::names::now_ms(ctx);
        let mut st = self.lock();
        self.progress(&mut st, now);
        let source = st
            .queues
            .get(&input.source_arn)
            .ok_or_else(|| not_found("The resource that you specified for the SourceArn parameter doesn't exist."))?;
        authorize_queue(ctx, "sqs:ListMessageMoveTasks", source)?;
        let results: Vec<types::ListMessageMoveTasksResultEntry> = st
            .move_tasks
            .iter()
            .rev()
            .filter(|t| t.source_arn == input.source_arn)
            .take(max as usize)
            .map(|t| types::ListMessageMoveTasksResultEntry {
                task_handle: (t.status == "RUNNING").then(|| t.task_handle.clone()),
                status: Some(t.status.clone()),
                source_arn: Some(t.source_arn.clone()),
                destination_arn: t.destination_arn.clone(),
                max_number_of_messages_per_second: t.max_per_second,
                approximate_number_of_messages_moved: t.moved,
                approximate_number_of_messages_to_move: Some(t.to_move),
                failure_reason: t.failure_reason.clone(),
                started_timestamp: t.started_at,
            })
            .collect();
        Ok(types::ListMessageMoveTasksResult { results: Some(results) })
    }
}
