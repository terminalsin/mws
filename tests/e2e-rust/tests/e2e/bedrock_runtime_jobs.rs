//! Bedrock jobs that read S3 as their service role, through the official
//! Rust SDK: model customization (PassRole, missing and malformed training
//! data, metrics written to the output location), model import, and batch
//! inference limits and states.

use std::time::Duration;

use aws_sdk_bedrock::types::*;
use aws_sdk_bedrock::Client;
use mws_e2e::Mws;
use serde_json::json;

use crate::bedrock::{advance, code, jobs_role, message, put, ACCOUNT};

const HAIKU: &str = "anthropic.claude-3-haiku-20240307-v1:0";
const LINE: &str = r#"{"messages": [{"role": "user", "content": "Hi"}, {"role": "assistant", "content": "Hello!"}]}"#;

fn tune(
    b: &Client,
    name: &str,
    role: &str,
    training: &str,
) -> aws_sdk_bedrock::operation::create_model_customization_job::builders::CreateModelCustomizationJobFluentBuilder {
    b.create_model_customization_job()
        .job_name(name)
        .custom_model_name(format!("{name}-model"))
        .role_arn(role)
        .base_model_identifier(HAIKU)
        .training_data_config(TrainingDataConfig::builder().s3_uri(training).build())
        .output_data_config(OutputDataConfig::builder().s3_uri("s3://tuning/out/").build().unwrap())
        .hyper_parameters("epochCount", "1")
}

#[tokio::test]
async fn customization_jobs_read_their_data_as_the_role() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let b = Client::new(&cfg);
    let s3 = Mws::s3(&cfg);
    s3.create_bucket().bucket("tuning").send().await.unwrap();
    let role = jobs_role(&cfg, &["tuning"]).await;
    put(&s3, "tuning", "good.jsonl", format!("{LINE}\n{LINE}\n{LINE}\n")).await;
    put(&s3, "tuning", "bad.jsonl", format!("{LINE}\nnot json\n")).await;

    // Passing the role needs iam:PassRole.
    let no_pass = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"bedrock:*","Resource":"*"}]}"#;
    let (_, user_cfg) = mws_e2e::user_with_policy(&mws, "no-pass-role", Some(no_pass)).await;
    let e = tune(&Client::new(&user_cfg), "denied", &role, "s3://tuning/good.jsonl").send().await.unwrap_err();
    let e = e.as_service_error().unwrap();
    assert_eq!(code(e), "AccessDeniedException");
    assert!(message(e).contains("iam:PassRole"), "{}", message(e));
    // A role Bedrock cannot assume is rejected.
    let missing = format!("arn:aws:iam::{ACCOUNT}:role/does-not-exist");
    let e = tune(&b, "no-role", &missing, "s3://tuning/good.jsonl").send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "ValidationException");

    let ok = tune(&b, "good", &role, "s3://tuning/good.jsonl").send().await.unwrap();
    let absent = tune(&b, "absent", &role, "s3://tuning/missing.jsonl").send().await.unwrap();
    let bad = tune(&b, "bad", &role, "s3://tuning/bad.jsonl").send().await.unwrap();
    let got = b.get_model_customization_job().job_identifier(ok.job_arn()).send().await.unwrap();
    assert_eq!(got.status(), Some(&ModelCustomizationJobStatus::InProgress));
    let details = got.status_details().unwrap();
    assert_eq!(details.validation_details().unwrap().status(), Some(&JobStatusDetails::InProgress));
    assert_eq!(details.training_details().unwrap().status(), Some(&JobStatusDetails::NotStarted));
    advance(&mws, 3).await;

    let got = b.get_model_customization_job().job_identifier(ok.job_arn()).send().await.unwrap();
    assert_eq!(got.status(), Some(&ModelCustomizationJobStatus::Completed));
    assert!(got.training_metrics().unwrap().training_loss().unwrap() > 0.0);
    assert_eq!(got.status_details().unwrap().training_details().unwrap().status(), Some(&JobStatusDetails::Completed));
    let id = ok.job_arn().rsplit('/').next().unwrap();
    let metrics = s3
        .get_object()
        .bucket("tuning")
        .key(format!("out/model-customization-job-{id}/training_artifacts/step_wise_training_metrics.csv"))
        .send()
        .await
        .unwrap();
    let csv = String::from_utf8(metrics.body.collect().await.unwrap().to_vec()).unwrap();
    assert!(csv.starts_with("step_number,epoch_number,training_loss,perplexity\n"));
    assert_eq!(csv.lines().count(), 4);
    b.get_custom_model().model_identifier("good-model").send().await.unwrap();

    let got = b.get_model_customization_job().job_identifier(absent.job_arn()).send().await.unwrap();
    assert_eq!(got.status(), Some(&ModelCustomizationJobStatus::Failed));
    let failure = got.failure_message().unwrap();
    assert!(failure.starts_with("Unable to read the training data at s3://tuning/missing.jsonl"), "{failure}");
    assert_eq!(got.status_details().unwrap().validation_details().unwrap().status(), Some(&JobStatusDetails::Failed));
    // No custom model comes of a failed job.
    let e = b.get_custom_model().model_identifier("absent-model").send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "ResourceNotFoundException");

    let got = b.get_model_customization_job().job_identifier(bad.job_arn()).send().await.unwrap();
    assert_eq!(got.status(), Some(&ModelCustomizationJobStatus::Failed));
    assert_eq!(
        got.failure_message(),
        Some("Malformed training data at s3://tuning/bad.jsonl: line 2 is not a valid JSON object.")
    );

    // Model import checks the weights.
    put(&s3, "tuning", "weights/config.json", r#"{"model_type": "llama"}"#).await;
    let import = b
        .create_model_import_job()
        .job_name("import-no-weights")
        .imported_model_name("no-weights")
        .role_arn(&role)
        .model_data_source(ModelDataSource::S3DataSource(
            S3DataSource::builder().s3_uri("s3://tuning/weights/").build().unwrap(),
        ))
        .send()
        .await
        .unwrap();
    advance(&mws, 3).await;
    let got = b.get_model_import_job().job_identifier(import.job_arn()).send().await.unwrap();
    assert_eq!(got.status(), Some(&ModelImportJobStatus::Failed));
    assert_eq!(
        got.failure_message(),
        Some("The model data at s3://tuning/weights/ doesn't contain model weights in the .safetensors format.")
    );

    // Evaluation jobs read custom datasets and write each model's records.
    put(&s3, "tuning", "eval/good.jsonl", r#"{"prompt": "What is 2+2?", "referenceResponse": "4"}"#).await;
    put(&s3, "tuning", "eval/bad.jsonl", r#"{"question": "What is 2+2?"}"#).await;
    let evaluate = |name: &str, dataset: &str| {
        b.create_evaluation_job()
            .job_name(name)
            .role_arn(&role)
            .evaluation_config(EvaluationConfig::Automated(
                AutomatedEvaluationConfig::builder()
                    .dataset_metric_configs(
                        EvaluationDatasetMetricConfig::builder()
                            .task_type(EvaluationTaskType::QuestionAndAnswer)
                            .dataset(
                                EvaluationDataset::builder()
                                    .name("mine")
                                    .dataset_location(EvaluationDatasetLocation::S3Uri(dataset.into()))
                                    .build()
                                    .unwrap(),
                            )
                            .metric_names("Builtin.Accuracy")
                            .build()
                            .unwrap(),
                    )
                    .build()
                    .unwrap(),
            ))
            .inference_config(EvaluationInferenceConfig::Models(vec![EvaluationModelConfig::BedrockModel(
                EvaluationBedrockModel::builder().model_identifier(HAIKU).build().unwrap(),
            )]))
            .output_data_config(EvaluationOutputDataConfig::builder().s3_uri("s3://tuning/evals/").build().unwrap())
            .send()
    };
    let good = evaluate("eval-good", "s3://tuning/eval/good.jsonl").await.unwrap();
    let bad = evaluate("eval-bad", "s3://tuning/eval/bad.jsonl").await.unwrap();
    advance(&mws, 3).await;
    let got = b.get_evaluation_job().job_identifier(good.job_arn()).send().await.unwrap();
    assert_eq!(got.status(), &EvaluationJobStatus::Completed);
    let id = good.job_arn().rsplit('/').next().unwrap();
    let key =
        format!("evals/eval-good/{id}/models/{HAIKU}/taskTypes/QuestionAndAnswer/datasets/mine/{id}_output.jsonl");
    s3.get_object().bucket("tuning").key(key).send().await.unwrap();
    let got = b.get_evaluation_job().job_identifier(bad.job_arn()).send().await.unwrap();
    assert_eq!(got.status(), &EvaluationJobStatus::Failed);
    assert_eq!(
        got.failure_messages(),
        ["Malformed dataset at s3://tuning/eval/bad.jsonl: line 1 must have a \"prompt\" string.".to_string()]
    );
    mws.stop().await;
}

#[tokio::test]
async fn batch_inference_limits_and_states() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let b = Client::new(&cfg);
    let s3 = Mws::s3(&cfg);
    s3.create_bucket().bucket("batch").send().await.unwrap();
    let role = jobs_role(&cfg, &["batch"]).await;
    let record = |n: usize| {
        json!({"recordId": format!("r{n}"), "modelInput": {"anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 20, "messages": [{"role": "user", "content": format!("record {n}")}]}})
        .to_string()
    };
    let lines = |n: usize| (1..=n).map(record).collect::<Vec<_>>().join("\n");
    put(&s3, "batch", "few/in.jsonl", lines(3)).await;
    put(&s3, "batch", "many/in.jsonl", lines(100)).await;
    let job = |name: &str, model: &str, input: &str| {
        b.create_model_invocation_job()
            .job_name(name)
            .role_arn(&role)
            .model_id(model)
            .input_data_config(ModelInvocationJobInputDataConfig::S3InputDataConfig(
                ModelInvocationJobS3InputDataConfig::builder().s3_uri(input).build().unwrap(),
            ))
            .output_data_config(ModelInvocationJobOutputDataConfig::S3OutputDataConfig(
                ModelInvocationJobS3OutputDataConfig::builder().s3_uri("s3://batch/out/").build().unwrap(),
            ))
            .send()
    };

    // Only some models support batch inference.
    let e = job("unsupported", "cohere.command-r-v1:0", "s3://batch/many/").await.unwrap_err();
    let e = e.as_service_error().unwrap();
    assert_eq!(code(e), "ValidationException");
    assert!(message(e).contains("doesn't support batch inference"), "{}", message(e));

    let wait = |arn: String| {
        let b = b.clone();
        async move {
            let mut seen = Vec::new();
            for _ in 0..200 {
                let got = b.get_model_invocation_job().job_identifier(&arn).send().await.unwrap();
                let status = got.status().cloned().unwrap();
                if seen.last() != Some(&status) {
                    seen.push(status.clone());
                }
                if matches!(
                    status,
                    ModelInvocationJobStatus::Completed
                        | ModelInvocationJobStatus::Failed
                        | ModelInvocationJobStatus::PartiallyCompleted
                ) {
                    return (seen, got);
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            panic!("job did not finish: {seen:?}");
        }
    };

    // Fewer than the minimum of 100 records fails validation.
    let few = job("few", HAIKU, "s3://batch/few/").await.unwrap();
    let (_, got) = wait(few.job_arn().to_string()).await;
    assert_eq!(got.status(), Some(&ModelInvocationJobStatus::Failed));
    let m = got.message().unwrap();
    assert!(m.contains("(3) is less than the minimum number of records per batch inference job (100)"), "{m}");

    let many = job("many", HAIKU, "s3://batch/many/").await.unwrap();
    let (seen, got) = wait(many.job_arn().to_string()).await;
    assert_eq!(got.status(), Some(&ModelInvocationJobStatus::Completed), "{seen:?}");
    assert_eq!(got.success_record_count(), Some(100));
    // The job passes through the queue states on its way.
    let order = [
        ModelInvocationJobStatus::Submitted,
        ModelInvocationJobStatus::Validating,
        ModelInvocationJobStatus::Scheduled,
        ModelInvocationJobStatus::InProgress,
        ModelInvocationJobStatus::Completed,
    ];
    let positions: Vec<usize> = seen.iter().map(|s| order.iter().position(|o| o == s).unwrap()).collect();
    assert!(positions.windows(2).all(|w| w[0] < w[1]), "{seen:?}");
    assert!(seen.len() >= 2, "{seen:?}");
    mws.stop().await;
}
