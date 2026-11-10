//! S3 Batch Operations through the official Rust SDK: jobs really run, as
//! their role, and write completion reports.

use aws_sdk_lambda::primitives::Blob;
use aws_sdk_lambda::types::{FunctionCode, Runtime};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3control::error::ProvideErrorMetadata;
use aws_sdk_s3control::types::{
    GeneratedManifestFormat, JobManifest, JobManifestFieldName, JobManifestFormat, JobManifestGenerator,
    JobManifestGeneratorFilter, JobManifestLocation, JobManifestSpec, JobOperation, JobReport, JobReportFormat,
    JobReportScope, JobStatus, KeyNameConstraint, LambdaInvokeOperation, RequestedJobStatus, S3CopyObjectOperation,
    S3JobManifestGenerator, S3ManifestOutputLocation, S3SetObjectTaggingOperation, S3Tag,
};
use mws_e2e::Mws;

const ACCOUNT: &str = "123456789012";

const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
    "Principal":{"Service":"batchoperations.s3.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

async fn batch_role(mws: &Mws, name: &str, trust: &str) -> String {
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let role = iam.create_role().role_name(name).assume_role_policy_document(trust).send().await.unwrap();
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*","lambda:InvokeFunction"],"Resource":"*"}]}"#;
    iam.put_role_policy().role_name(name).policy_name("batch").policy_document(policy).send().await.unwrap();
    role.role().unwrap().arn().to_string()
}

async fn wait(
    control: &aws_sdk_s3control::Client,
    id: &str,
    want: JobStatus,
) -> aws_sdk_s3control::types::JobDescriptor {
    for _ in 0..200 {
        let job = control.describe_job().account_id(ACCOUNT).job_id(id).send().await.unwrap().job.unwrap();
        if job.status() == Some(&want) {
            return job;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("job {id} never reached {want:?}");
}

fn report(prefix: &str) -> JobReport {
    JobReport::builder()
        .enabled(true)
        .bucket("arn:aws:s3:::reports")
        .format(JobReportFormat::ReportCsv20180820)
        .prefix(prefix)
        .report_scope(JobReportScope::AllTasks)
        .build()
}

async fn text(s3: &aws_sdk_s3::Client, bucket: &str, key: &str) -> String {
    let out = s3.get_object().bucket(bucket).key(key).send().await.unwrap();
    String::from_utf8(out.body.collect().await.unwrap().into_bytes().to_vec()).unwrap()
}

#[tokio::test]
async fn csv_manifest_jobs_tag_objects_and_report() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let s3 = Mws::s3(&cfg);
    let control = aws_sdk_s3control::Client::new(&cfg);
    for b in ["data", "reports"] {
        s3.create_bucket().bucket(b).send().await.unwrap();
    }
    for k in ["a.txt", "dir/b c.txt"] {
        s3.put_object().bucket("data").key(k).body(ByteStream::from_static(b"x")).send().await.unwrap();
    }
    let manifest = "data,a.txt\ndata,dir/b%20c.txt\ndata,missing\n";
    let put = s3
        .put_object()
        .bucket("data")
        .key("manifest.csv")
        .body(ByteStream::from_static(manifest.as_bytes()))
        .send()
        .await
        .unwrap();
    let role = batch_role(&mws, "batch", TRUST).await;
    let location = |etag: &str| {
        JobManifest::builder()
            .spec(
                JobManifestSpec::builder()
                    .format(JobManifestFormat::S3BatchOperationsCsv20180820)
                    .fields(JobManifestFieldName::Bucket)
                    .fields(JobManifestFieldName::Key)
                    .build()
                    .unwrap(),
            )
            .location(
                JobManifestLocation::builder()
                    .object_arn("arn:aws:s3:::data/manifest.csv")
                    .e_tag(etag)
                    .build()
                    .unwrap(),
            )
            .build()
    };
    let tagging = JobOperation::builder()
        .s3_put_object_tagging(
            S3SetObjectTaggingOperation::builder()
                .tag_set(S3Tag::builder().key("team").value("blue").build().unwrap())
                .build(),
        )
        .build();
    let created = control
        .create_job()
        .account_id(ACCOUNT)
        .client_request_token("t1")
        .priority(10)
        .role_arn(&role)
        .operation(tagging.clone())
        .manifest(location(put.e_tag().unwrap()))
        .report(report("batch"))
        .tags(S3Tag::builder().key("owner").value("me").build().unwrap())
        .send()
        .await
        .unwrap();
    let id = created.job_id().unwrap().to_string();
    // The client token makes CreateJob idempotent.
    let again = control
        .create_job()
        .account_id(ACCOUNT)
        .client_request_token("t1")
        .priority(10)
        .role_arn(&role)
        .operation(tagging.clone())
        .manifest(location(put.e_tag().unwrap()))
        .report(report("batch"))
        .send()
        .await
        .unwrap();
    assert_eq!(again.job_id(), Some(id.as_str()));

    let job = wait(&control, &id, JobStatus::Complete).await;
    let progress = job.progress_summary().unwrap();
    assert_eq!(progress.total_number_of_tasks(), Some(3));
    assert_eq!(progress.number_of_tasks_succeeded(), Some(2));
    assert_eq!(progress.number_of_tasks_failed(), Some(1));
    assert_eq!(job.job_arn(), Some(format!("arn:aws:s3:us-east-1:{ACCOUNT}:job/{id}").as_str()));
    let tags = s3.get_object_tagging().bucket("data").key("dir/b c.txt").send().await.unwrap();
    assert_eq!(tags.tag_set()[0].value(), "blue");

    // The completion report lists every task.
    let report_manifest: serde_json::Value =
        serde_json::from_str(&text(&s3, "reports", &format!("batch/job-{id}/manifest.json")).await).unwrap();
    let results = report_manifest["Results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    let failed = results.iter().find(|r| r["TaskExecutionStatus"] == "failed").unwrap();
    let csv = text(&s3, "reports", failed["Key"].as_str().unwrap()).await;
    assert!(csv.starts_with("data,missing,,failed,404,NoSuchKey,"), "{csv}");

    // Listing, priority and tags.
    let listed = control.list_jobs().account_id(ACCOUNT).job_statuses(JobStatus::Complete).send().await.unwrap();
    assert_eq!(listed.jobs().len(), 1);
    assert_eq!(listed.jobs()[0].operation().map(|o| o.as_str()), Some("S3PutObjectTagging"));
    let p = control.update_job_priority().account_id(ACCOUNT).job_id(&id).priority(99).send().await.unwrap();
    assert_eq!(p.priority(), 99);
    let tags = control.get_job_tagging().account_id(ACCOUNT).job_id(&id).send().await.unwrap();
    assert_eq!(tags.tags()[0].key(), "owner");
    control
        .put_job_tagging()
        .account_id(ACCOUNT)
        .job_id(&id)
        .tags(S3Tag::builder().key("k").value("v").build().unwrap())
        .send()
        .await
        .unwrap();
    control.delete_job_tagging().account_id(ACCOUNT).job_id(&id).send().await.unwrap();
    assert!(control.get_job_tagging().account_id(ACCOUNT).job_id(&id).send().await.unwrap().tags().is_empty());
    let err = control
        .update_job_status()
        .account_id(ACCOUNT)
        .job_id(&id)
        .requested_job_status(RequestedJobStatus::Cancelled)
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("JobStatusException"));
    let err = control
        .describe_job()
        .account_id(ACCOUNT)
        .job_id("00000000-0000-0000-0000-000000000000")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("NotFoundException"));

    // A manifest whose ETag changed fails the job.
    let stale = control
        .create_job()
        .account_id(ACCOUNT)
        .client_request_token("t2")
        .priority(1)
        .role_arn(&role)
        .operation(tagging.clone())
        .manifest(location("\"0000\""))
        .report(JobReport::builder().enabled(false).build())
        .send()
        .await
        .unwrap();
    let job = wait(&control, stale.job_id().unwrap(), JobStatus::Failed).await;
    assert!(!job.failure_reasons().is_empty());

    // A role Batch Operations may not assume fails the job too.
    let lambda_trust = TRUST.replace("batchoperations.s3", "lambda");
    let untrusted = batch_role(&mws, "not-batch", &lambda_trust).await;
    let job = control
        .create_job()
        .account_id(ACCOUNT)
        .client_request_token("t3")
        .priority(1)
        .role_arn(&untrusted)
        .operation(tagging)
        .manifest(location(put.e_tag().unwrap()))
        .report(JobReport::builder().enabled(false).build())
        .send()
        .await
        .unwrap();
    let job = wait(&control, job.job_id().unwrap(), JobStatus::Failed).await;
    assert_eq!(job.failure_reasons()[0].failure_code(), Some("AccessDenied"));
}

#[tokio::test]
async fn generated_manifests_confirmation_copy_and_lambda() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let s3 = Mws::s3(&cfg);
    let control = aws_sdk_s3control::Client::new(&cfg);
    for b in ["src", "dst", "reports"] {
        s3.create_bucket().bucket(b).send().await.unwrap();
    }
    for k in ["logs/1.log", "logs/2.log", "logs/skip.txt", "other/3.log"] {
        s3.put_object().bucket("src").key(k).body(ByteStream::from_static(b"payload")).send().await.unwrap();
    }
    let role = batch_role(&mws, "batch", TRUST).await;
    let generator = JobManifestGenerator::S3JobManifestGenerator(
        S3JobManifestGenerator::builder()
            .source_bucket("arn:aws:s3:::src")
            .enable_manifest_output(true)
            .manifest_output_location(
                S3ManifestOutputLocation::builder()
                    .bucket("arn:aws:s3:::reports")
                    .manifest_prefix("generated")
                    .manifest_format(GeneratedManifestFormat::S3InventoryReportCsv20211130)
                    .build()
                    .unwrap(),
            )
            .filter(
                JobManifestGeneratorFilter::builder()
                    .key_name_constraint(
                        KeyNameConstraint::builder().match_any_prefix("logs/").match_any_suffix(".log").build(),
                    )
                    .build(),
            )
            .build()
            .unwrap(),
    );
    let copy = JobOperation::builder()
        .s3_put_object_copy(
            S3CopyObjectOperation::builder().target_resource("arn:aws:s3:::dst").target_key_prefix("copied/").build(),
        )
        .build();
    let created = control
        .create_job()
        .account_id(ACCOUNT)
        .client_request_token("copy")
        .confirmation_required(true)
        .priority(1)
        .role_arn(&role)
        .operation(copy)
        .manifest_generator(generator)
        .report(JobReport::builder().enabled(false).build())
        .send()
        .await
        .unwrap();
    let id = created.job_id().unwrap().to_string();
    let job = wait(&control, &id, JobStatus::Suspended).await;
    assert_eq!(job.suspended_cause(), Some("AWAITING_CONFIRMATION"));
    let moved = control
        .update_job_status()
        .account_id(ACCOUNT)
        .job_id(&id)
        .requested_job_status(RequestedJobStatus::Ready)
        .send()
        .await
        .unwrap();
    assert_eq!(moved.status(), Some(&JobStatus::Ready));
    let job = wait(&control, &id, JobStatus::Complete).await;
    assert_eq!(job.progress_summary().unwrap().number_of_tasks_succeeded(), Some(2));
    let copied = s3.list_objects_v2().bucket("dst").send().await.unwrap();
    let keys: Vec<_> = copied.contents().iter().filter_map(|o| o.key()).collect();
    assert_eq!(keys, ["copied/logs/1.log", "copied/logs/2.log"]);
    let generated = job.generated_manifest_descriptor().unwrap().location().unwrap();
    assert_eq!(generated.object_arn(), format!("arn:aws:s3:::reports/generated/job-{id}/manifest.json"));

    // LambdaInvoke runs the function once per task and reads its result.
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    let fn_trust = TRUST.replace("batchoperations.s3", "lambda");
    let fn_role = iam.create_role().role_name("fn").assume_role_policy_document(fn_trust).send().await.unwrap();
    let code = r#"
def handler(event, context):
    task = event["tasks"][0]
    code = "PermanentFailure" if task["s3Key"].endswith("2.log") else "Succeeded"
    return {"invocationSchemaVersion": "2.0", "treatMissingKeysAs": "PermanentFailure",
            "invocationId": event["invocationId"],
            "results": [{"taskId": task["taskId"], "resultCode": code,
                         "resultString": event["job"]["userArguments"]["greeting"] + " " + task["s3Key"]}]}
"#;
    let f = lambda
        .create_function()
        .function_name("batch-fn")
        .runtime(Runtime::Python312)
        .role(fn_role.role().unwrap().arn())
        .handler("app.handler")
        .code(FunctionCode::builder().zip_file(Blob::new(crate::lambda::zip(&[("app.py", code)]))).build())
        .send()
        .await
        .unwrap();
    mws_e2e::function_active(&lambda, "batch-fn").await;
    let manifest = "src,logs/1.log\nsrc,logs/2.log\n";
    let put = s3
        .put_object()
        .bucket("src")
        .key("m.csv")
        .body(ByteStream::from_static(manifest.as_bytes()))
        .send()
        .await
        .unwrap();
    let created = control
        .create_job()
        .account_id(ACCOUNT)
        .client_request_token("lambda")
        .priority(1)
        .role_arn(&role)
        .operation(
            JobOperation::builder()
                .lambda_invoke(
                    LambdaInvokeOperation::builder()
                        .function_arn(f.function_arn().unwrap())
                        .invocation_schema_version("2.0")
                        .user_arguments("greeting", "hello")
                        .build(),
                )
                .build(),
        )
        .manifest(
            JobManifest::builder()
                .spec(
                    JobManifestSpec::builder()
                        .format(JobManifestFormat::S3BatchOperationsCsv20180820)
                        .fields(JobManifestFieldName::Bucket)
                        .fields(JobManifestFieldName::Key)
                        .build()
                        .unwrap(),
                )
                .location(
                    JobManifestLocation::builder()
                        .object_arn("arn:aws:s3:::src/m.csv")
                        .e_tag(put.e_tag().unwrap())
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .report(report("fn"))
        .send()
        .await
        .unwrap();
    let id = created.job_id().unwrap().to_string();
    let job = wait(&control, &id, JobStatus::Complete).await;
    let p = job.progress_summary().unwrap();
    assert_eq!((p.number_of_tasks_succeeded(), p.number_of_tasks_failed()), (Some(1), Some(1)));
    let manifest: serde_json::Value =
        serde_json::from_str(&text(&s3, "reports", &format!("fn/job-{id}/manifest.json")).await).unwrap();
    let ok = manifest["Results"].as_array().unwrap().iter().find(|r| r["TaskExecutionStatus"] == "succeeded").unwrap();
    let csv = text(&s3, "reports", ok["Key"].as_str().unwrap()).await;
    assert_eq!(csv.trim(), "src,logs%2F1.log,,succeeded,200,,hello logs/1.log");
}
