//! Amazon Bedrock (control plane) through the official Rust SDK: the model
//! catalog, inference profiles, guardrails, Provisioned Throughput, model
//! customization and import, batch inference, evaluation, prompt routers,
//! Marketplace endpoints, Automated Reasoning, settings and tags.

use aws_sdk_bedrock::error::ProvideErrorMetadata;
use aws_sdk_bedrock::primitives::Blob;
use aws_sdk_bedrock::types::*;
use aws_sdk_bedrock::Client;
use mws_e2e::Mws;

pub(crate) const ACCOUNT: &str = "123456789012";
const HAIKU: &str = "anthropic.claude-3-haiku-20240307-v1:0";
const NOVA_MICRO: &str = "amazon.nova-micro-v1:0";
const ROLE: &str = "arn:aws:iam::123456789012:role/bedrock-jobs";

pub(crate) fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

pub(crate) fn message<E: ProvideErrorMetadata>(e: &E) -> String {
    e.message().unwrap_or_default().to_string()
}

pub(crate) fn fm_arn(id: &str) -> String {
    format!("arn:aws:bedrock:us-east-1::foundation-model/{id}")
}

pub(crate) async fn advance(mws: &Mws, seconds: u64) {
    let body = format!(r#"{{"advanceSeconds": {seconds}}}"#);
    let (status, _) = mws.control("POST", "/_mws/clock", Some(&body)).await;
    assert_eq!(status, 200);
}

fn tag(k: &str, v: &str) -> Tag {
    Tag::builder().key(k).value(v).build().unwrap()
}

/// A guardrail that denies a topic, filters a word, and masks emails.
pub(crate) async fn guardrail(b: &Client, name: &str) -> (String, String) {
    let g = b
        .create_guardrail()
        .name(name)
        .description("test guardrail")
        .blocked_input_messaging("Sorry, I can't help with that.")
        .blocked_outputs_messaging("Sorry, the answer was blocked.")
        .topic_policy_config(
            GuardrailTopicPolicyConfig::builder()
                .topics_config(
                    GuardrailTopicConfig::builder()
                        .name("Investments")
                        .definition("Advice about investing money in stocks or crypto.")
                        .examples("Which stocks should I buy?")
                        .r#type(GuardrailTopicType::Deny)
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .word_policy_config(
            GuardrailWordPolicyConfig::builder()
                .words_config(GuardrailWordConfig::builder().text("frobnicate").build().unwrap())
                .build(),
        )
        .sensitive_information_policy_config(
            GuardrailSensitiveInformationPolicyConfig::builder()
                .pii_entities_config(
                    GuardrailPiiEntityConfig::builder()
                        .r#type(GuardrailPiiEntityType::Email)
                        .action(GuardrailSensitiveInformationAction::Anonymize)
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .tags(tag("team", "ml"))
        .send()
        .await
        .unwrap();
    (g.guardrail_id().to_string(), g.guardrail_arn().to_string())
}

#[tokio::test]
async fn foundation_model_catalog() {
    let mws = Mws::start().await;
    let b = Client::new(&mws.root_sdk_config().await);

    let all = b.list_foundation_models().send().await.unwrap();
    assert!(all.model_summaries().len() > 30);
    let anthropic = b.list_foundation_models().by_provider("Anthropic").send().await.unwrap();
    assert!(anthropic.model_summaries().iter().all(|m| m.provider_name() == Some("Anthropic")));
    let embeddings = b.list_foundation_models().by_output_modality(ModelModality::Embedding).send().await.unwrap();
    assert!(embeddings.model_summaries().iter().any(|m| m.model_id() == "amazon.titan-embed-text-v2:0"));
    let tunable =
        b.list_foundation_models().by_customization_type(ModelCustomization::FineTuning).send().await.unwrap();
    assert!(tunable.model_summaries().iter().any(|m| m.model_id() == HAIKU));

    let m = b.get_foundation_model().model_identifier(HAIKU).send().await.unwrap();
    let d = m.model_details().unwrap();
    assert_eq!(d.model_arn(), fm_arn(HAIKU));
    assert_eq!(d.response_streaming_supported(), Some(true));
    assert!(d.inference_types_supported().contains(&InferenceType::OnDemand));
    let by_arn = b.get_foundation_model().model_identifier(fm_arn(HAIKU)).send().await.unwrap();
    assert_eq!(by_arn.model_details().unwrap().model_id(), HAIKU);
    let e = b.get_foundation_model().model_identifier("acme.nope-v1").send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "ResourceNotFoundException");

    // Access: availability, agreements and the use case form.
    let a = b.get_foundation_model_availability().model_id(HAIKU).send().await.unwrap();
    assert_eq!(a.model_id(), HAIKU);
    assert_eq!(a.authorization_status(), &AuthorizationStatus::Authorized);
    assert_eq!(a.agreement_availability().unwrap().status(), &AgreementStatus::NotAvailable);
    let offers = b.list_foundation_model_agreement_offers().model_id(HAIKU).send().await.unwrap();
    let token = offers.offers()[0].offer_token().to_string();
    let created = b.create_foundation_model_agreement().model_id(HAIKU).offer_token(&token).send().await.unwrap();
    assert_eq!(created.model_id(), HAIKU);
    let a = b.get_foundation_model_availability().model_id(HAIKU).send().await.unwrap();
    assert_eq!(a.agreement_availability().unwrap().status(), &AgreementStatus::Available);
    b.delete_foundation_model_agreement().model_id(HAIKU).send().await.unwrap();
    let a = b.get_foundation_model_availability().model_id(HAIKU).send().await.unwrap();
    assert_eq!(a.agreement_availability().unwrap().status(), &AgreementStatus::NotAvailable);

    let form = br#"{"companyName":"Example","companyWebsite":"https://example.com","intendedUsers":"0","industryOption":"Tech","otherIndustryOption":"","useCases":"Testing"}"#;
    b.put_use_case_for_model_access().form_data(Blob::new(form.to_vec())).send().await.unwrap();
    let got = b.get_use_case_for_model_access().send().await.unwrap();
    assert_eq!(got.form_data().as_ref(), form);

    let r = b.get_account_data_retention().send().await.unwrap();
    assert_eq!(r.mode().as_str(), "default");
    let r = b.put_account_data_retention().mode(DataRetentionMode::from("none")).send().await.unwrap();
    assert_eq!(r.mode().as_str(), "none");
    mws.stop().await;
}

#[tokio::test]
async fn inference_profiles() {
    let mws = Mws::start().await;
    let b = Client::new(&mws.root_sdk_config().await);

    // System-defined cross-Region profiles.
    let system = b.list_inference_profiles().send().await.unwrap();
    let us_haiku = system
        .inference_profile_summaries()
        .iter()
        .find(|p| p.inference_profile_id() == format!("us.{HAIKU}"))
        .expect("us. profile for Claude 3 Haiku");
    assert_eq!(us_haiku.r#type(), &InferenceProfileType::SystemDefined);
    assert!(us_haiku.models().len() >= 2);
    let got = b.get_inference_profile().inference_profile_identifier(format!("us.{HAIKU}")).send().await.unwrap();
    assert_eq!(
        got.inference_profile_arn(),
        format!("arn:aws:bedrock:us-east-1:{ACCOUNT}:inference-profile/us.{HAIKU}")
    );

    // Application profiles copy a model or a system profile.
    let app = b
        .create_inference_profile()
        .inference_profile_name("chat-app")
        .description("cost tracking for the chat app")
        .model_source(InferenceProfileModelSource::CopyFrom(us_haiku.inference_profile_arn().to_string()))
        .tags(tag("costCenter", "42"))
        .send()
        .await
        .unwrap();
    let arn = app.inference_profile_arn().to_string();
    assert!(arn.starts_with(&format!("arn:aws:bedrock:us-east-1:{ACCOUNT}:application-inference-profile/")));
    let single = b
        .create_inference_profile()
        .inference_profile_name("single-region")
        .model_source(InferenceProfileModelSource::CopyFrom(fm_arn(NOVA_MICRO)))
        .send()
        .await
        .unwrap();
    let got = b.get_inference_profile().inference_profile_identifier(&arn).send().await.unwrap();
    assert_eq!(got.r#type(), &InferenceProfileType::Application);
    assert_eq!(got.models().len(), us_haiku.models().len());
    assert_eq!(got.status(), &InferenceProfileStatus::Active);
    let apps = b.list_inference_profiles().type_equals(InferenceProfileType::Application).send().await.unwrap();
    assert_eq!(apps.inference_profile_summaries().len(), 2);
    let dup = b
        .create_inference_profile()
        .inference_profile_name("chat-app")
        .model_source(InferenceProfileModelSource::CopyFrom(fm_arn(HAIKU)))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(dup.as_service_error().unwrap()), "ConflictException");

    let tags = b.list_tags_for_resource().resource_arn(&arn).send().await.unwrap();
    assert_eq!(tags.tags()[0].key(), "costCenter");
    b.delete_inference_profile().inference_profile_identifier(single.inference_profile_arn()).send().await.unwrap();
    b.delete_inference_profile().inference_profile_identifier(&arn).send().await.unwrap();
    let e = b.get_inference_profile().inference_profile_identifier(&arn).send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "ResourceNotFoundException");
    mws.stop().await;
}

#[tokio::test]
async fn guardrails_and_versions() {
    let mws = Mws::start().await;
    let b = Client::new(&mws.root_sdk_config().await);
    let (id, arn) = guardrail(&b, "support-bot").await;

    let g = b.get_guardrail().guardrail_identifier(&id).send().await.unwrap();
    assert_eq!(g.version(), "DRAFT");
    assert_eq!(g.status(), &GuardrailStatus::Ready);
    assert_eq!(g.topic_policy().unwrap().topics()[0].name(), "Investments");
    assert_eq!(g.word_policy().unwrap().words()[0].text(), "frobnicate");

    let v1 = b.create_guardrail_version().guardrail_identifier(&arn).description("first").send().await.unwrap();
    assert_eq!(v1.version(), "1");
    b.update_guardrail()
        .guardrail_identifier(&id)
        .name("support-bot")
        .blocked_input_messaging("No.")
        .blocked_outputs_messaging("No!")
        .send()
        .await
        .unwrap();
    let draft = b.get_guardrail().guardrail_identifier(&id).send().await.unwrap();
    assert_eq!(draft.blocked_input_messaging(), "No.");
    assert!(draft.topic_policy().is_none());
    let one = b.get_guardrail().guardrail_identifier(&id).guardrail_version("1").send().await.unwrap();
    assert_eq!(one.blocked_input_messaging(), "Sorry, I can't help with that.");

    let list = b.list_guardrails().send().await.unwrap();
    assert_eq!(list.guardrails().len(), 1);
    let versions = b.list_guardrails().guardrail_identifier(&id).send().await.unwrap();
    assert_eq!(versions.guardrails().len(), 2);

    // Account-level enforced guardrails.
    let put = b
        .put_enforced_guardrail_configuration()
        .guardrail_inference_config(
            AccountEnforcedGuardrailInferenceInputConfiguration::builder()
                .guardrail_identifier(&id)
                .guardrail_version("1")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let configs = b.list_enforced_guardrails_configuration().send().await.unwrap();
    assert_eq!(configs.guardrails_config().len(), 1);
    b.delete_enforced_guardrail_configuration().config_id(put.config_id().unwrap()).send().await.unwrap();
    assert!(b.list_enforced_guardrails_configuration().send().await.unwrap().guardrails_config().is_empty());

    b.delete_guardrail().guardrail_identifier(&id).guardrail_version("1").send().await.unwrap();
    b.delete_guardrail().guardrail_identifier(&id).send().await.unwrap();
    let e = b.get_guardrail().guardrail_identifier(&id).send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "ResourceNotFoundException");
    mws.stop().await;
}

#[tokio::test]
async fn provisioned_throughput_and_prompt_routers() {
    let mws = Mws::start().await;
    let b = Client::new(&mws.root_sdk_config().await);

    let pt = b
        .create_provisioned_model_throughput()
        .provisioned_model_name("haiku-pt")
        .model_id(HAIKU)
        .model_units(1)
        .send()
        .await
        .unwrap();
    let arn = pt.provisioned_model_arn().to_string();
    let got = b.get_provisioned_model_throughput().provisioned_model_id(&arn).send().await.unwrap();
    assert_eq!(got.status(), &ProvisionedModelStatus::Creating);
    advance(&mws, 5).await;
    let got = b.get_provisioned_model_throughput().provisioned_model_id(&arn).send().await.unwrap();
    assert_eq!(got.status(), &ProvisionedModelStatus::InService);
    assert_eq!(got.foundation_model_arn(), fm_arn(HAIKU));
    b.update_provisioned_model_throughput()
        .provisioned_model_id(&arn)
        .desired_provisioned_model_name("haiku-pt-2")
        .send()
        .await
        .unwrap();
    let list = b.list_provisioned_model_throughputs().send().await.unwrap();
    assert_eq!(list.provisioned_model_summaries()[0].provisioned_model_name(), "haiku-pt-2");
    b.delete_provisioned_model_throughput().provisioned_model_id(&arn).send().await.unwrap();

    // Default routers exist; custom ones route between two models.
    let routers = b.list_prompt_routers().send().await.unwrap();
    assert!(!routers.prompt_router_summaries().is_empty());
    let a = format!("arn:aws:bedrock:us-east-1:{ACCOUNT}:inference-profile/us.anthropic.claude-3-haiku-20240307-v1:0");
    let c =
        format!("arn:aws:bedrock:us-east-1:{ACCOUNT}:inference-profile/us.anthropic.claude-3-5-sonnet-20240620-v1:0");
    let r = b
        .create_prompt_router()
        .prompt_router_name("cheap-first")
        .models(PromptRouterTargetModel::builder().model_arn(&a).build())
        .models(PromptRouterTargetModel::builder().model_arn(&c).build())
        .fallback_model(PromptRouterTargetModel::builder().model_arn(&a).build())
        .routing_criteria(RoutingCriteria::builder().response_quality_difference(25.0).build().unwrap())
        .send()
        .await
        .unwrap();
    let got = b.get_prompt_router().prompt_router_arn(r.prompt_router_arn().unwrap()).send().await.unwrap();
    assert_eq!(got.r#type(), &PromptRouterType::Custom);
    assert_eq!(got.models().len(), 2);
    b.delete_prompt_router().prompt_router_arn(r.prompt_router_arn().unwrap()).send().await.unwrap();
    mws.stop().await;
}

#[tokio::test]
async fn customization_import_and_deployments() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let b = Client::new(&cfg);
    Mws::s3(&cfg).create_bucket().bucket("training").send().await.unwrap();

    let job = b
        .create_model_customization_job()
        .job_name("tune-1")
        .custom_model_name("haiku-tuned")
        .role_arn(ROLE)
        .base_model_identifier(HAIKU)
        .customization_type(CustomizationType::FineTuning)
        .training_data_config(TrainingDataConfig::builder().s3_uri("s3://training/train.jsonl").build())
        .output_data_config(OutputDataConfig::builder().s3_uri("s3://training/out/").build().unwrap())
        .hyper_parameters("epochCount", "2")
        .send()
        .await
        .unwrap();
    let got = b.get_model_customization_job().job_identifier(job.job_arn()).send().await.unwrap();
    assert_eq!(got.status(), Some(&ModelCustomizationJobStatus::InProgress));
    let bad = b
        .create_model_customization_job()
        .job_name("tune-2")
        .custom_model_name("titan-tuned")
        .role_arn(ROLE)
        .base_model_identifier("amazon.titan-embed-text-v2:0")
        .training_data_config(TrainingDataConfig::builder().s3_uri("s3://training/train.jsonl").build())
        .output_data_config(OutputDataConfig::builder().s3_uri("s3://training/out/").build().unwrap())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(bad.as_service_error().unwrap()), "ValidationException");
    advance(&mws, 10).await;
    let got = b.get_model_customization_job().job_identifier("tune-1").send().await.unwrap();
    assert_eq!(got.status(), Some(&ModelCustomizationJobStatus::Completed));
    let jobs = b.list_model_customization_jobs().send().await.unwrap();
    assert_eq!(jobs.model_customization_job_summaries().len(), 1);

    let model = b.get_custom_model().model_identifier("haiku-tuned").send().await.unwrap();
    assert_eq!(model.base_model_arn(), Some(fm_arn(HAIKU).as_str()));
    assert_eq!(model.model_status(), Some(&ModelStatus::Active));
    let models = b.list_custom_models().send().await.unwrap();
    assert_eq!(models.model_summaries().len(), 1);

    // A second job, stopped while it runs.
    let stop = b
        .create_model_customization_job()
        .job_name("tune-3")
        .custom_model_name("haiku-tuned-3")
        .role_arn(ROLE)
        .base_model_identifier(HAIKU)
        .training_data_config(TrainingDataConfig::builder().s3_uri("s3://training/train.jsonl").build())
        .output_data_config(OutputDataConfig::builder().s3_uri("s3://training/out/").build().unwrap())
        .send()
        .await
        .unwrap();
    b.stop_model_customization_job().job_identifier(stop.job_arn()).send().await.unwrap();
    let got = b.get_model_customization_job().job_identifier(stop.job_arn()).send().await.unwrap();
    assert!(matches!(got.status(), Some(ModelCustomizationJobStatus::Stopping | ModelCustomizationJobStatus::Stopped)));

    // On-demand deployments of the custom model.
    let d = b
        .create_custom_model_deployment()
        .model_deployment_name("tuned-od")
        .model_arn(model.model_arn())
        .send()
        .await
        .unwrap();
    advance(&mws, 5).await;
    let got = b
        .get_custom_model_deployment()
        .custom_model_deployment_identifier(d.custom_model_deployment_arn())
        .send()
        .await
        .unwrap();
    assert_eq!(got.status(), &CustomModelDeploymentStatus::Active);
    b.update_custom_model_deployment()
        .custom_model_deployment_identifier(d.custom_model_deployment_arn())
        .model_arn(model.model_arn())
        .send()
        .await
        .unwrap();
    let list = b.list_custom_model_deployments().send().await.unwrap();
    assert_eq!(list.model_deployment_summaries().len(), 1);
    b.delete_custom_model_deployment()
        .custom_model_deployment_identifier(d.custom_model_deployment_arn())
        .send()
        .await
        .unwrap();

    // Copy the model; create one from S3 weights; import an open model.
    let copy = b
        .create_model_copy_job()
        .source_model_arn(model.model_arn())
        .target_model_name("haiku-tuned-copy")
        .send()
        .await
        .unwrap();
    let got = b.get_model_copy_job().job_arn(copy.job_arn()).send().await.unwrap();
    assert_eq!(got.target_model_name(), Some("haiku-tuned-copy"));
    assert_eq!(b.list_model_copy_jobs().send().await.unwrap().model_copy_job_summaries().len(), 1);
    let created = b
        .create_custom_model()
        .model_name("from-weights")
        .model_source_config(ModelDataSource::S3DataSource(
            S3DataSource::builder().s3_uri("s3://training/weights/").build().unwrap(),
        ))
        .send()
        .await
        .unwrap();
    let imp = b
        .create_model_import_job()
        .job_name("import-llama")
        .imported_model_name("my-llama")
        .role_arn(ROLE)
        .model_data_source(ModelDataSource::S3DataSource(
            S3DataSource::builder().s3_uri("s3://training/llama/").build().unwrap(),
        ))
        .send()
        .await
        .unwrap();
    advance(&mws, 10).await;
    let got = b.get_model_import_job().job_identifier(imp.job_arn()).send().await.unwrap();
    assert_eq!(got.status(), Some(&ModelImportJobStatus::Completed));
    assert_eq!(b.list_model_import_jobs().send().await.unwrap().model_import_job_summaries().len(), 1);
    let imported = b.get_imported_model().model_identifier("my-llama").send().await.unwrap();
    assert!(imported.model_arn().unwrap().contains(":imported-model/"));
    assert_eq!(b.list_imported_models().send().await.unwrap().model_summaries().len(), 1);
    b.delete_imported_model().model_identifier("my-llama").send().await.unwrap();
    b.delete_custom_model().model_identifier(created.model_arn()).send().await.unwrap();
    b.delete_custom_model().model_identifier("haiku-tuned-copy").send().await.unwrap();
    mws.stop().await;
}

#[tokio::test]
async fn evaluation_and_prompt_optimization_jobs() {
    let mws = Mws::start().await;
    let b = Client::new(&mws.root_sdk_config().await);
    let dataset = EvaluationDataset::builder().name("Builtin.BoolQ").build().unwrap();
    let job = b
        .create_evaluation_job()
        .job_name("eval-1")
        .role_arn(ROLE)
        .evaluation_config(EvaluationConfig::Automated(
            AutomatedEvaluationConfig::builder()
                .dataset_metric_configs(
                    EvaluationDatasetMetricConfig::builder()
                        .task_type(EvaluationTaskType::QuestionAndAnswer)
                        .dataset(dataset)
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
        .output_data_config(EvaluationOutputDataConfig::builder().s3_uri("s3://evals/out/").build().unwrap())
        .send()
        .await
        .unwrap();
    let got = b.get_evaluation_job().job_identifier(job.job_arn()).send().await.unwrap();
    assert_eq!(got.status(), &EvaluationJobStatus::InProgress);
    assert_eq!(b.list_evaluation_jobs().send().await.unwrap().job_summaries().len(), 1);
    b.stop_evaluation_job().job_identifier(job.job_arn()).send().await.unwrap();
    let got = b.get_evaluation_job().job_identifier(job.job_arn()).send().await.unwrap();
    assert!(matches!(got.status(), EvaluationJobStatus::Stopping | EvaluationJobStatus::Stopped));
    advance(&mws, 5).await;
    let deleted = b.batch_delete_evaluation_job().job_identifiers(job.job_arn()).send().await.unwrap();
    assert_eq!(deleted.evaluation_jobs().len(), 1);
    assert!(deleted.errors().is_empty());

    let opt = b
        .create_advanced_prompt_optimization_job()
        .job_name("optimize-1")
        .input_config(AdvancedPromptOptimizationInputConfig::builder().s3_uri("s3://prompts/in.jsonl").build().unwrap())
        .output_config(AdvancedPromptOptimizationOutputConfig::builder().s3_uri("s3://prompts/out/").build().unwrap())
        .model_configurations(ModelConfiguration::builder().model_id(NOVA_MICRO).build().unwrap())
        .send()
        .await
        .unwrap();
    let got = b.get_advanced_prompt_optimization_job().job_identifier(opt.job_arn()).send().await.unwrap();
    assert_eq!(got.job_name(), "optimize-1");
    assert_eq!(b.list_advanced_prompt_optimization_jobs().send().await.unwrap().job_summaries().len(), 1);
    b.stop_advanced_prompt_optimization_job().job_identifier(opt.job_arn()).send().await.unwrap();
    advance(&mws, 5).await;
    let deleted =
        b.batch_delete_advanced_prompt_optimization_job().job_identifiers(opt.job_arn()).send().await.unwrap();
    assert!(deleted.errors().is_empty());
    mws.stop().await;
}

#[tokio::test]
async fn settings_policies_and_tags() {
    let mws = Mws::start().await;
    let b = Client::new(&mws.root_sdk_config().await);

    assert!(b.get_model_invocation_logging_configuration().send().await.unwrap().logging_config().is_none());
    b.put_model_invocation_logging_configuration()
        .logging_config(
            LoggingConfig::builder()
                .cloud_watch_config(
                    CloudWatchConfig::builder().log_group_name("/bedrock/invocations").role_arn(ROLE).build().unwrap(),
                )
                .text_data_delivery_enabled(true)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let got = b.get_model_invocation_logging_configuration().send().await.unwrap();
    assert_eq!(got.logging_config().unwrap().cloud_watch_config().unwrap().log_group_name(), "/bedrock/invocations");
    b.delete_model_invocation_logging_configuration().send().await.unwrap();
    assert!(b.get_model_invocation_logging_configuration().send().await.unwrap().logging_config().is_none());

    let (_, arn) = guardrail(&b, "policy-target").await;
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{ACCOUNT}:root"}},"Action":"bedrock:ApplyGuardrail","Resource":"{arn}"}}]}}"#
    );
    b.put_resource_policy().resource_arn(&arn).resource_policy(&policy).send().await.unwrap();
    let got = b.get_resource_policy().resource_arn(&arn).send().await.unwrap();
    assert_eq!(got.resource_policy(), Some(policy.as_str()));
    b.delete_resource_policy().resource_arn(&arn).send().await.unwrap();
    let e = b.get_resource_policy().resource_arn(&arn).send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "ResourceNotFoundException");

    b.tag_resource().resource_arn(&arn).tags(tag("env", "test")).send().await.unwrap();
    let tags = b.list_tags_for_resource().resource_arn(&arn).send().await.unwrap();
    assert_eq!(tags.tags().len(), 2);
    b.untag_resource().resource_arn(&arn).tag_keys("team").send().await.unwrap();
    let tags = b.list_tags_for_resource().resource_arn(&arn).send().await.unwrap();
    assert_eq!(tags.tags().len(), 1);
    assert_eq!(tags.tags()[0].key(), "env");
    mws.stop().await;
}

#[tokio::test]
async fn marketplace_endpoints() {
    let mws = Mws::start().await;
    let b = Client::new(&mws.root_sdk_config().await);
    let source = "arn:aws:sagemaker:us-east-1:aws:hub-content/SageMakerPublicHub/Model/example-model/1.0.0";
    let e = b
        .create_marketplace_model_endpoint()
        .model_source_identifier(source)
        .endpoint_name("market-1")
        .accept_eula(true)
        .endpoint_config(EndpointConfig::SageMaker(
            SageMakerEndpoint::builder()
                .initial_instance_count(1)
                .instance_type("ml.g5.xlarge")
                .execution_role(ROLE)
                .build()
                .unwrap(),
        ))
        .send()
        .await
        .unwrap();
    let ep = e.marketplace_model_endpoint().unwrap();
    let arn = ep.endpoint_arn().to_string();
    assert!(arn.starts_with("arn:aws:sagemaker:us-east-1:"));
    let got = b.get_marketplace_model_endpoint().endpoint_arn(&arn).send().await.unwrap();
    assert_eq!(got.marketplace_model_endpoint().unwrap().model_source_identifier(), source);
    b.update_marketplace_model_endpoint()
        .endpoint_arn(&arn)
        .endpoint_config(EndpointConfig::SageMaker(
            SageMakerEndpoint::builder()
                .initial_instance_count(2)
                .instance_type("ml.g5.xlarge")
                .execution_role(ROLE)
                .build()
                .unwrap(),
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(b.list_marketplace_model_endpoints().send().await.unwrap().marketplace_model_endpoints().len(), 1);
    b.deregister_marketplace_model_endpoint().endpoint_arn(&arn).send().await.unwrap();
    b.register_marketplace_model_endpoint()
        .endpoint_identifier(&arn)
        .model_source_identifier(source)
        .send()
        .await
        .unwrap();
    b.delete_marketplace_model_endpoint().endpoint_arn(&arn).send().await.unwrap();
    assert!(b.list_marketplace_model_endpoints().send().await.unwrap().marketplace_model_endpoints().is_empty());
    mws.stop().await;
}

#[tokio::test]
async fn automated_reasoning_policies() {
    let mws = Mws::start().await;
    let b = Client::new(&mws.root_sdk_config().await);
    let definition = AutomatedReasoningPolicyDefinition::builder()
        .version("1.0")
        .variables(
            AutomatedReasoningPolicyDefinitionVariable::builder()
                .name("age")
                .r#type("INT")
                .description("The applicant's age in years.")
                .build()
                .unwrap(),
        )
        .rules(
            AutomatedReasoningPolicyDefinitionRule::builder()
                .id("A1B2C3D4E5F6")
                .expression("(>= age 18)")
                .build()
                .unwrap(),
        )
        .build();
    let p = b
        .create_automated_reasoning_policy()
        .name("eligibility")
        .description("who may apply")
        .policy_definition(definition.clone())
        .send()
        .await
        .unwrap();
    let arn = p.policy_arn().to_string();
    let got = b.get_automated_reasoning_policy().policy_arn(&arn).send().await.unwrap();
    assert_eq!(got.name(), "eligibility");
    let hash = got.definition_hash().to_string();
    assert_eq!(hash.len(), 128);
    assert_eq!(
        b.list_automated_reasoning_policies().send().await.unwrap().automated_reasoning_policy_summaries().len(),
        1
    );
    let updated = b
        .update_automated_reasoning_policy()
        .policy_arn(&arn)
        .policy_definition(definition.clone())
        .description("updated")
        .send()
        .await
        .unwrap();
    let v = b
        .create_automated_reasoning_policy_version()
        .policy_arn(&arn)
        .last_updated_definition_hash(updated.definition_hash())
        .send()
        .await
        .unwrap();
    assert_eq!(v.version(), "1");
    let exported = b.export_automated_reasoning_policy_version().policy_arn(v.policy_arn()).send().await.unwrap();
    assert_eq!(exported.policy_definition().unwrap().rules().len(), 1);

    // A build workflow that ingests a document.
    let wf = b
        .start_automated_reasoning_policy_build_workflow()
        .policy_arn(&arn)
        .build_workflow_type(AutomatedReasoningPolicyBuildWorkflowType::IngestContent)
        .source_content(
            AutomatedReasoningPolicyBuildWorkflowSource::builder()
                .policy_definition(definition.clone())
                .workflow_content(AutomatedReasoningPolicyWorkflowTypeContent::Documents(vec![
                    AutomatedReasoningPolicyBuildWorkflowDocument::builder()
                        .document(Blob::new(b"Applicants must be 18 or older.".to_vec()))
                        .document_content_type(AutomatedReasoningPolicyBuildDocumentContentType::Text)
                        .document_name("rules.txt")
                        .build()
                        .unwrap(),
                ]))
                .build(),
        )
        .send()
        .await
        .unwrap();
    let wf_id = wf.build_workflow_id().to_string();
    let e = b
        .get_automated_reasoning_policy_build_workflow_result_assets()
        .policy_arn(&arn)
        .build_workflow_id(&wf_id)
        .asset_type(AutomatedReasoningPolicyBuildResultAssetType::PolicyDefinition)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "ValidationException");
    advance(&mws, 5).await;
    let got = b
        .get_automated_reasoning_policy_build_workflow()
        .policy_arn(&arn)
        .build_workflow_id(&wf_id)
        .send()
        .await
        .unwrap();
    assert_eq!(got.status(), &AutomatedReasoningPolicyBuildWorkflowStatus::Completed);
    let listed = b.list_automated_reasoning_policy_build_workflows().policy_arn(&arn).send().await.unwrap();
    assert_eq!(listed.automated_reasoning_policy_build_workflow_summaries().len(), 1);
    let assets = b
        .get_automated_reasoning_policy_build_workflow_result_assets()
        .policy_arn(&arn)
        .build_workflow_id(&wf_id)
        .asset_type(AutomatedReasoningPolicyBuildResultAssetType::PolicyDefinition)
        .send()
        .await
        .unwrap();
    assert!(assets.build_workflow_assets().is_some());
    let scenario = b
        .get_automated_reasoning_policy_next_scenario()
        .policy_arn(&arn)
        .build_workflow_id(&wf_id)
        .send()
        .await
        .unwrap();
    assert!(scenario.scenario().is_some());
    let ann =
        b.get_automated_reasoning_policy_annotations().policy_arn(&arn).build_workflow_id(&wf_id).send().await.unwrap();
    b.update_automated_reasoning_policy_annotations()
        .policy_arn(&arn)
        .build_workflow_id(&wf_id)
        .annotations(AutomatedReasoningPolicyAnnotation::AddRule(
            AutomatedReasoningPolicyAddRuleAnnotation::builder().expression("(<= age 120)").build().unwrap(),
        ))
        .last_updated_annotation_set_hash(ann.annotation_set_hash())
        .send()
        .await
        .unwrap();
    let ann2 =
        b.get_automated_reasoning_policy_annotations().policy_arn(&arn).build_workflow_id(&wf_id).send().await.unwrap();
    assert_eq!(ann2.annotations().len(), 1);

    // Test cases, run against the completed build.
    let tc = b
        .create_automated_reasoning_policy_test_case()
        .policy_arn(&arn)
        .guard_content("The applicant is 30, so they may apply.")
        .query_content("May a 30 year old apply?")
        .expected_aggregated_findings_result(AutomatedReasoningCheckResult::Valid)
        .send()
        .await
        .unwrap();
    let got = b
        .get_automated_reasoning_policy_test_case()
        .policy_arn(&arn)
        .test_case_id(tc.test_case_id())
        .send()
        .await
        .unwrap();
    let test_case = got.test_case().unwrap();
    b.update_automated_reasoning_policy_test_case()
        .policy_arn(&arn)
        .test_case_id(tc.test_case_id())
        .guard_content("The applicant is 31, so they may apply.")
        .expected_aggregated_findings_result(AutomatedReasoningCheckResult::Valid)
        .last_updated_at(*test_case.updated_at())
        .send()
        .await
        .unwrap();
    assert_eq!(
        b.list_automated_reasoning_policy_test_cases().policy_arn(&arn).send().await.unwrap().test_cases().len(),
        1
    );
    b.start_automated_reasoning_policy_test_workflow().policy_arn(&arn).build_workflow_id(&wf_id).send().await.unwrap();
    let result = b
        .get_automated_reasoning_policy_test_result()
        .policy_arn(&arn)
        .build_workflow_id(&wf_id)
        .test_case_id(tc.test_case_id())
        .send()
        .await
        .unwrap();
    assert_eq!(result.test_result().unwrap().test_run_status(), &AutomatedReasoningPolicyTestRunStatus::Completed);
    let results = b
        .list_automated_reasoning_policy_test_results()
        .policy_arn(&arn)
        .build_workflow_id(&wf_id)
        .send()
        .await
        .unwrap();
    assert_eq!(results.test_results().len(), 1);
    let got = b
        .get_automated_reasoning_policy_test_case()
        .policy_arn(&arn)
        .test_case_id(tc.test_case_id())
        .send()
        .await
        .unwrap();
    b.delete_automated_reasoning_policy_test_case()
        .policy_arn(&arn)
        .test_case_id(tc.test_case_id())
        .last_updated_at(*got.test_case().unwrap().updated_at())
        .send()
        .await
        .unwrap();

    // A second workflow, cancelled; then clean up.
    let wf2 = b
        .start_automated_reasoning_policy_build_workflow()
        .policy_arn(&arn)
        .build_workflow_type(AutomatedReasoningPolicyBuildWorkflowType::RefinePolicy)
        .source_content(AutomatedReasoningPolicyBuildWorkflowSource::builder().policy_definition(definition).build())
        .send()
        .await
        .unwrap();
    b.cancel_automated_reasoning_policy_build_workflow()
        .policy_arn(&arn)
        .build_workflow_id(wf2.build_workflow_id())
        .send()
        .await
        .unwrap();
    let w = b
        .get_automated_reasoning_policy_build_workflow()
        .policy_arn(&arn)
        .build_workflow_id(&wf_id)
        .send()
        .await
        .unwrap();
    b.delete_automated_reasoning_policy_build_workflow()
        .policy_arn(&arn)
        .build_workflow_id(&wf_id)
        .last_updated_at(*w.updated_at())
        .send()
        .await
        .unwrap();
    b.delete_automated_reasoning_policy().policy_arn(&arn).send().await.unwrap();
    let e = b.get_automated_reasoning_policy().policy_arn(&arn).send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "ResourceNotFoundException");
    let _ = message(e.as_service_error().unwrap());
    mws.stop().await;
}
