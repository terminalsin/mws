//! Amplify Hosting: apps, branches and the rest of the API, and deployments
//! that are really served (manual uploads, S3 sources, repository builds),
//! with rewrites, redirects, basic auth, custom headers, domains and logs.

use std::time::Duration;

use aws_sdk_amplify::error::ProvideErrorMetadata;
use aws_sdk_amplify::types::{CustomRule, JobStatus, JobType, SourceUrlType, Stage, SubDomainSetting};
use base64::Engine;
use mws_e2e::Mws;

fn zip(files: &[(&str, &str)]) -> Vec<u8> {
    use std::io::Write;
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        for (name, body) in files {
            z.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
            z.write_all(body.as_bytes()).unwrap();
        }
        z.finish().unwrap();
    }
    buf.into_inner()
}

async fn wait_for_job(
    amplify: &aws_sdk_amplify::Client,
    app: &str,
    branch: &str,
    job: &str,
) -> aws_sdk_amplify::types::Job {
    for _ in 0..600 {
        let j = amplify.get_job().app_id(app).branch_name(branch).job_id(job).send().await.unwrap();
        let job = j.job.unwrap();
        if matches!(job.summary().unwrap().status(), JobStatus::Succeed | JobStatus::Failed | JobStatus::Cancelled) {
            return job;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("job {job} did not finish");
}

/// GET a page of a branch's site by its Amplify host name.
async fn page(mws: &Mws, host: &str, path: &str, headers: &[(&str, &str)]) -> (u16, Vec<(String, String)>, String) {
    let mut all = vec![("Host", host)];
    all.extend_from_slice(headers);
    let (status, headers, body) = mws.raw("GET", path, &all, b"").await;
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

#[tokio::test]
async fn apps_branches_webhooks_and_tags() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let amplify = aws_sdk_amplify::Client::new(&cfg);

    let app = amplify
        .create_app()
        .name("reports")
        .description("ABI reports")
        .environment_variables("NODE_ENV", "production")
        .tags("team", "web")
        .send()
        .await
        .unwrap()
        .app
        .unwrap();
    let app_id = app.app_id().to_string();
    assert!(app_id.starts_with('d') && app_id.len() == 14, "{app_id}");
    assert_eq!(app.default_domain(), format!("{app_id}.amplifyapp.com"));
    assert_eq!(app.app_arn(), format!("arn:aws:amplify:us-east-1:123456789012:apps/{app_id}"));
    assert_eq!(app.platform().as_str(), "WEB");
    assert_eq!(app.custom_rules()[0].status(), Some("404-200"));

    let err = amplify.get_app().app_id("dnothere000000").send().await.unwrap_err();
    assert_eq!(err.code(), Some("NotFoundException"));
    let err = amplify.create_app().name("x").repository("https://github.com/o/r").send().await.unwrap_err();
    assert_eq!(err.code(), Some("BadRequestException"));

    let got = amplify.get_app().app_id(&app_id).send().await.unwrap().app.unwrap();
    assert_eq!(got.environment_variables().get("NODE_ENV").map(String::as_str), Some("production"));
    let listed = amplify.list_apps().send().await.unwrap();
    assert!(listed.apps().iter().any(|a| a.app_id() == app_id));
    let updated = amplify.update_app().app_id(&app_id).description("new").send().await.unwrap().app.unwrap();
    assert_eq!(updated.description(), "new");

    let branch = amplify
        .create_branch()
        .app_id(&app_id)
        .branch_name("feature/login")
        .stage(Stage::Beta)
        .tags("kind", "feature")
        .send()
        .await
        .unwrap()
        .branch
        .unwrap();
    assert_eq!(branch.display_name(), "feature-login");
    assert_eq!(branch.branch_arn(), format!("{}/branches/feature%2Flogin", app.app_arn()));
    let err = amplify.create_branch().app_id(&app_id).branch_name("feature/login").send().await.unwrap_err();
    assert_eq!(err.code(), Some("BadRequestException"));
    amplify.create_branch().app_id(&app_id).branch_name("main").stage(Stage::Production).send().await.unwrap();
    let b = amplify.get_branch().app_id(&app_id).branch_name("feature/login").send().await.unwrap().branch.unwrap();
    assert_eq!(b.stage().as_str(), "BETA");
    let branches = amplify.list_branches().app_id(&app_id).max_results(1).send().await.unwrap();
    assert_eq!(branches.branches().len(), 1);
    let rest = amplify.list_branches().app_id(&app_id).next_token(branches.next_token().unwrap()).send().await.unwrap();
    assert_eq!(rest.branches().len(), 1);
    let b = amplify
        .update_branch()
        .app_id(&app_id)
        .branch_name("feature/login")
        .description("login work")
        .send()
        .await
        .unwrap()
        .branch
        .unwrap();
    assert_eq!(b.description(), "login work");
    let got = amplify.get_app().app_id(&app_id).send().await.unwrap().app.unwrap();
    assert_eq!(got.production_branch().unwrap().branch_name(), Some("main"));

    // Backend environments.
    let env = amplify
        .create_backend_environment()
        .app_id(&app_id)
        .environment_name("staging")
        .stack_name("amplify-reports-staging")
        .send()
        .await
        .unwrap()
        .backend_environment
        .unwrap();
    assert!(env.backend_environment_arn().ends_with("/backendenvironments/staging"));
    let got = amplify.get_backend_environment().app_id(&app_id).environment_name("staging").send().await.unwrap();
    assert_eq!(got.backend_environment().unwrap().stack_name(), Some("amplify-reports-staging"));
    let listed = amplify.list_backend_environments().app_id(&app_id).send().await.unwrap();
    assert_eq!(listed.backend_environments().len(), 1);
    amplify.delete_backend_environment().app_id(&app_id).environment_name("staging").send().await.unwrap();
    let err = amplify.get_backend_environment().app_id(&app_id).environment_name("staging").send().await.unwrap_err();
    assert_eq!(err.code(), Some("NotFoundException"));

    // Webhooks.
    let hook = amplify.create_webhook().app_id(&app_id).branch_name("main").description("ci").send().await.unwrap();
    let hook = hook.webhook.unwrap();
    assert!(hook.webhook_url().starts_with("https://webhooks.amplify.us-east-1.amazonaws.com/prod/webhooks?id="));
    let got = amplify.get_webhook().webhook_id(hook.webhook_id()).send().await.unwrap().webhook.unwrap();
    assert_eq!(got.branch_name(), "main");
    let listed = amplify.list_webhooks().app_id(&app_id).send().await.unwrap();
    assert_eq!(listed.webhooks().len(), 1);
    let updated = amplify
        .update_webhook()
        .webhook_id(hook.webhook_id())
        .branch_name("feature/login")
        .send()
        .await
        .unwrap()
        .webhook
        .unwrap();
    assert_eq!(updated.branch_name(), "feature/login");
    amplify.delete_webhook().webhook_id(hook.webhook_id()).send().await.unwrap();
    let err = amplify.get_webhook().webhook_id(hook.webhook_id()).send().await.unwrap_err();
    assert_eq!(err.code(), Some("NotFoundException"));

    // Tags on apps and branches.
    amplify.tag_resource().resource_arn(app.app_arn()).tags("cost", "1").send().await.unwrap();
    amplify.untag_resource().resource_arn(app.app_arn()).tag_keys("team").send().await.unwrap();
    let tags = amplify.list_tags_for_resource().resource_arn(app.app_arn()).send().await.unwrap();
    let tags = tags.tags().unwrap();
    assert_eq!(tags.get("cost").map(String::as_str), Some("1"));
    assert!(!tags.contains_key("team"));
    let tags = amplify.list_tags_for_resource().resource_arn(branch.branch_arn()).send().await.unwrap();
    assert_eq!(tags.tags().unwrap().get("kind").map(String::as_str), Some("feature"));
    let err = amplify
        .list_tags_for_resource()
        .resource_arn("arn:aws:amplify:us-east-1:123456789012:apps/dnothere000000")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("ResourceNotFoundException"));

    amplify.delete_branch().app_id(&app_id).branch_name("feature/login").send().await.unwrap();
    let err = amplify.get_branch().app_id(&app_id).branch_name("feature/login").send().await.unwrap_err();
    assert_eq!(err.code(), Some("NotFoundException"));
    amplify.delete_app().app_id(&app_id).send().await.unwrap();
    let err = amplify.get_app().app_id(&app_id).send().await.unwrap_err();
    assert_eq!(err.code(), Some("NotFoundException"));
}

#[tokio::test]
async fn manual_deployments_are_served() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let amplify = aws_sdk_amplify::Client::new(&cfg);
    let app_id = amplify.create_app().name("site").send().await.unwrap().app.unwrap().app_id().to_string();
    amplify.create_branch().app_id(&app_id).branch_name("main").send().await.unwrap();
    let host = format!("main.{app_id}.amplifyapp.com");

    // Nothing deployed yet.
    let (status, _, _) = page(&mws, &host, "/", &[]).await;
    assert_eq!(status, 404);

    let deployment = amplify.create_deployment().app_id(&app_id).branch_name("main").send().await.unwrap();
    let job_id = deployment.job_id().unwrap().to_string();
    let site =
        zip(&[("index.html", "<h1>home</h1>"), ("docs/index.html", "<h1>docs</h1>"), ("app.js", "console.log(1)")]);
    let (status, _, _) = mws.raw("PUT", deployment.zip_upload_url(), &[], &site).await;
    assert_eq!(status, 200);
    let started = amplify.start_deployment().app_id(&app_id).branch_name("main").job_id(&job_id).send().await.unwrap();
    assert_eq!(started.job_summary().unwrap().job_type().as_str(), "MANUAL");
    let job = wait_for_job(&amplify, &app_id, "main", &job_id).await;
    assert_eq!(job.summary().unwrap().status(), &JobStatus::Succeed);
    assert_eq!(job.steps()[0].step_name(), "DEPLOY");
    let log_url = job.steps()[0].log_url().unwrap();
    let (status, _, log) = mws.raw("GET", log_url, &[], b"").await;
    assert_eq!(status, 200);
    assert!(String::from_utf8_lossy(&log).contains("Deploying 3 files"));

    let (status, headers, body) = page(&mws, &host, "/", &[]).await;
    assert_eq!((status, body.as_str()), (200, "<h1>home</h1>"));
    assert_eq!(header(&headers, "content-type"), Some("text/html"));
    let (status, headers, _) = page(&mws, &host, "/app.js", &[]).await;
    assert_eq!(status, 200);
    assert_eq!(header(&headers, "content-type"), Some("application/javascript"));
    // Directories redirect to their trailing slash.
    let (status, headers, _) = page(&mws, &host, "/docs", &[]).await;
    assert_eq!(status, 301);
    assert_eq!(header(&headers, "location"), Some("/docs/"));
    let (_, _, body) = page(&mws, &host, "/docs/", &[]).await;
    assert_eq!(body, "<h1>docs</h1>");
    // The default rule serves index.html for missing paths (single-page apps).
    let (status, _, body) = page(&mws, &host, "/some/route", &[]).await;
    assert_eq!((status, body.as_str()), (200, "<h1>home</h1>"));
    // The same site on the MWS endpoint itself.
    let (status, _, body) = mws.raw("GET", &format!("/_aws/amplify/sites/{app_id}/main/docs/"), &[], b"").await;
    assert_eq!((status, String::from_utf8_lossy(&body).as_ref()), (200, "<h1>docs</h1>"));

    // Redirects, rewrites and custom 404s.
    amplify
        .update_app()
        .app_id(&app_id)
        .custom_rules(CustomRule::builder().source("/old/<*>").target("/docs/<*>").status("301").build().unwrap())
        .custom_rules(CustomRule::builder().source("/guide").target("/docs/index.html").status("200").build().unwrap())
        .custom_rules(CustomRule::builder().source("/<*>").target("/index.html").status("404").build().unwrap())
        .send()
        .await
        .unwrap();
    let (status, headers, _) = page(&mws, &host, "/old/intro", &[]).await;
    assert_eq!(status, 301);
    assert_eq!(header(&headers, "location"), Some("/docs/intro"));
    let (status, _, body) = page(&mws, &host, "/guide", &[]).await;
    assert_eq!((status, body.as_str()), (200, "<h1>docs</h1>"));
    let (status, _, body) = page(&mws, &host, "/missing", &[]).await;
    assert_eq!((status, body.as_str()), (404, "<h1>home</h1>"));
    let err = amplify
        .update_app()
        .app_id(&app_id)
        .custom_rules(CustomRule::builder().source("/a").target("/b").status("999").build().unwrap())
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("BadRequestException"));

    // Custom headers.
    let yaml = "customHeaders:\n  - pattern: '**/*'\n    headers:\n      - key: 'Strict-Transport-Security'\n        value: 'max-age=31536000'\n  - pattern: '*.js'\n    headers:\n      - key: 'Cache-Control'\n        value: 'max-age=3600'\n";
    amplify.update_app().app_id(&app_id).custom_headers(yaml).send().await.unwrap();
    let (_, headers, _) = page(&mws, &host, "/app.js", &[]).await;
    assert_eq!(header(&headers, "strict-transport-security"), Some("max-age=31536000"));
    assert_eq!(header(&headers, "cache-control"), Some("max-age=3600"));

    // Basic auth on the branch.
    let creds = base64::engine::general_purpose::STANDARD.encode("admin:s3cret");
    amplify
        .update_branch()
        .app_id(&app_id)
        .branch_name("main")
        .enable_basic_auth(true)
        .basic_auth_credentials(&creds)
        .send()
        .await
        .unwrap();
    let (status, headers, _) = page(&mws, &host, "/", &[]).await;
    assert_eq!(status, 401);
    assert_eq!(header(&headers, "www-authenticate"), Some("Basic"));
    let wrong = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("admin:nope"));
    assert_eq!(page(&mws, &host, "/", &[("Authorization", &wrong)]).await.0, 401);
    let right = format!("Basic {creds}");
    let (status, _, body) = page(&mws, &host, "/", &[("Authorization", &right)]).await;
    assert_eq!((status, body.as_str()), (200, "<h1>home</h1>"));
    amplify.update_branch().app_id(&app_id).branch_name("main").enable_basic_auth(false).send().await.unwrap();

    // A second deployment with a file map: only the changed file is uploaded.
    let index_md5 = format!("{:x}", md5::Md5::digest(b"<h1>home v2</h1>"));
    let js_md5 = format!("{:x}", md5::Md5::digest(b"console.log(1)"));
    let deployment = amplify
        .create_deployment()
        .app_id(&app_id)
        .branch_name("main")
        .file_map("index.html", index_md5)
        .file_map("app.js", js_md5)
        .send()
        .await
        .unwrap();
    let urls = deployment.file_upload_urls();
    assert_eq!(urls.len(), 2);
    let (status, _, _) = mws.raw("PUT", &urls["index.html"], &[], b"<h1>home v2</h1>").await;
    assert_eq!(status, 200);
    let second = deployment.job_id().unwrap().to_string();
    amplify.start_deployment().app_id(&app_id).branch_name("main").job_id(&second).send().await.unwrap();
    let job = wait_for_job(&amplify, &app_id, "main", &second).await;
    assert_eq!(job.summary().unwrap().status(), &JobStatus::Succeed);
    assert_eq!(page(&mws, &host, "/", &[]).await.2, "<h1>home v2</h1>");
    assert_eq!(page(&mws, &host, "/app.js", &[]).await.2, "console.log(1)");
    assert_eq!(page(&mws, &host, "/docs/", &[]).await.0, 404);

    // A deployment that is never started can be stopped; a finished job
    // can be deleted.
    let third = amplify.create_deployment().app_id(&app_id).branch_name("main").send().await.unwrap();
    let third = third.job_id().unwrap().to_string();
    let stopped = amplify.stop_job().app_id(&app_id).branch_name("main").job_id(&third).send().await.unwrap();
    assert_eq!(stopped.job_summary().unwrap().status(), &JobStatus::Cancelled);
    let err = amplify.start_deployment().app_id(&app_id).branch_name("main").job_id(&third).send().await.unwrap_err();
    assert_eq!(err.code(), Some("BadRequestException"));
    let jobs = amplify.list_jobs().app_id(&app_id).branch_name("main").send().await.unwrap();
    let ids: Vec<&str> = jobs.job_summaries().iter().map(|j| j.job_id()).collect();
    assert_eq!(ids, vec![third.as_str(), second.as_str(), job_id.as_str()]);
    let artifacts = amplify.list_artifacts().app_id(&app_id).branch_name("main").job_id(&job_id).send().await.unwrap();
    assert!(artifacts.artifacts().is_empty());
    let deleted = amplify.delete_job().app_id(&app_id).branch_name("main").job_id(&job_id).send().await.unwrap();
    assert_eq!(deleted.job_summary().unwrap().job_id(), job_id);
    let err = amplify.get_job().app_id(&app_id).branch_name("main").job_id(&job_id).send().await.unwrap_err();
    assert_eq!(err.code(), Some("NotFoundException"));

    // Access logs cover the requests above.
    let logs = amplify
        .generate_access_logs()
        .app_id(&app_id)
        .domain_name(format!("{app_id}.amplifyapp.com"))
        .send()
        .await
        .unwrap();
    let (status, _, csv) = mws.raw("GET", logs.log_url().unwrap(), &[], b"").await;
    assert_eq!(status, 200);
    let csv = String::from_utf8(csv).unwrap();
    assert!(csv.starts_with("date,time,x-edge-location"));
    assert!(csv.contains(",/old/intro,301,"), "{csv}");
    let err = amplify.generate_access_logs().app_id(&app_id).domain_name("example.org").send().await.unwrap_err();
    assert_eq!(err.code(), Some("NotFoundException"));
}

#[tokio::test]
async fn deployments_from_s3_follow_the_bucket_policy() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let amplify = aws_sdk_amplify::Client::new(&cfg);
    let s3 = Mws::s3(&cfg);
    let app_id = amplify.create_app().name("from-s3").send().await.unwrap().app.unwrap().app_id().to_string();
    amplify.create_branch().app_id(&app_id).branch_name("prod").send().await.unwrap();
    let host = format!("prod.{app_id}.amplifyapp.com");

    s3.create_bucket().bucket("site-builds").send().await.unwrap();
    let bundle = zip(&[("index.html", "from a zip")]);
    s3.put_object().bucket("site-builds").key("v1/site.zip").body(bundle.into()).send().await.unwrap();
    s3.put_object()
        .bucket("site-builds")
        .key("v2/index.html")
        .body(b"from a prefix".to_vec().into())
        .send()
        .await
        .unwrap();
    s3.put_object().bucket("site-builds").key("v2/css/app.css").body(b"body{}".to_vec().into()).send().await.unwrap();

    // Amplify reads the bucket as amplify.amazonaws.com: without a bucket
    // policy that allows it, the job fails.
    let job = amplify
        .start_deployment()
        .app_id(&app_id)
        .branch_name("prod")
        .source_url("s3://site-builds/v1/site.zip")
        .send()
        .await
        .unwrap();
    let id = job.job_summary().unwrap().job_id().to_string();
    let job = wait_for_job(&amplify, &app_id, "prod", &id).await;
    assert_eq!(job.summary().unwrap().status(), &JobStatus::Failed);
    assert!(job.steps()[0].status_reason().unwrap().contains("bucket policy"), "{:?}", job.steps()[0]);

    let branch_arn = format!("arn:aws:amplify:us-east-1:123456789012:apps/{app_id}/branches/prod");
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[
            {{"Effect":"Allow","Principal":{{"Service":"amplify.amazonaws.com"}},"Action":"s3:GetObject","Resource":"arn:aws:s3:::site-builds/*","Condition":{{"StringEquals":{{"aws:SourceArn":"{branch_arn}"}}}}}},
            {{"Effect":"Allow","Principal":{{"Service":"amplify.amazonaws.com"}},"Action":"s3:ListBucket","Resource":"arn:aws:s3:::site-builds","Condition":{{"StringEquals":{{"aws:SourceArn":"{branch_arn}"}}}}}}]}}"#
    );
    s3.put_bucket_policy().bucket("site-builds").policy(policy).send().await.unwrap();
    let job = amplify
        .start_deployment()
        .app_id(&app_id)
        .branch_name("prod")
        .source_url("s3://site-builds/v1/site.zip")
        .source_url_type(SourceUrlType::Zip)
        .send()
        .await
        .unwrap();
    let summary = job.job_summary().unwrap();
    assert_eq!(summary.source_url(), Some("s3://site-builds/v1/site.zip"));
    let job = wait_for_job(&amplify, &app_id, "prod", summary.job_id()).await;
    assert_eq!(job.summary().unwrap().status(), &JobStatus::Succeed);
    assert_eq!(page(&mws, &host, "/", &[]).await.2, "from a zip");

    let job = amplify
        .start_deployment()
        .app_id(&app_id)
        .branch_name("prod")
        .source_url("s3://site-builds/v2/")
        .source_url_type(SourceUrlType::BucketPrefix)
        .send()
        .await
        .unwrap();
    let job = wait_for_job(&amplify, &app_id, "prod", job.job_summary().unwrap().job_id()).await;
    assert_eq!(job.summary().unwrap().status(), &JobStatus::Succeed);
    assert_eq!(page(&mws, &host, "/", &[]).await.2, "from a prefix");
    let (status, headers, body) = page(&mws, &host, "/css/app.css", &[]).await;
    assert_eq!((status, body.as_str()), (200, "body{}"));
    assert_eq!(header(&headers, "content-type"), Some("text/css"));

    // A zip anywhere on HTTP (here, a presigned S3 URL).
    s3.put_object()
        .bucket("site-builds")
        .key("v3.zip")
        .body(zip(&[("index.html", "over http")]).into())
        .send()
        .await
        .unwrap();
    let presigned = s3
        .get_object()
        .bucket("site-builds")
        .key("v3.zip")
        .presigned(aws_sdk_s3::presigning::PresigningConfig::expires_in(Duration::from_secs(300)).unwrap())
        .await
        .unwrap();
    let job = amplify
        .start_deployment()
        .app_id(&app_id)
        .branch_name("prod")
        .source_url(presigned.uri())
        .send()
        .await
        .unwrap();
    let job = wait_for_job(&amplify, &app_id, "prod", job.job_summary().unwrap().job_id()).await;
    assert_eq!(job.summary().unwrap().status(), &JobStatus::Succeed);
    assert_eq!(page(&mws, &host, "/", &[]).await.2, "over http");
}

fn git(dir: &std::path::Path, args: &[&str]) {
    let out = std::process::Command::new("git")
        .current_dir(dir)
        .args(["-c", "user.name=MWS", "-c", "user.email=mws@example.com", "-c", "init.defaultBranch=main"])
        .args(args)
        .output()
        .expect("git runs");
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
}

#[tokio::test]
async fn repository_builds_run_the_build_spec() {
    if std::process::Command::new("git").arg("--version").output().is_err() {
        eprintln!("skipping: git is not installed");
        return;
    }
    let repo = std::env::temp_dir().join(format!("mws-amplify-repo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&repo);
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::write(repo.join("src/page.html"), "<p>built from git</p>").unwrap();
    std::fs::write(
        repo.join("amplify.yml"),
        "version: 1\nfrontend:\n  phases:\n    preBuild:\n      commands:\n        - mkdir -p dist\n    build:\n      commands:\n        - cp src/page.html dist/index.html\n        - echo \"$AWS_BRANCH $GREETING\" > dist/env.txt\n  artifacts:\n    baseDirectory: dist\n    files:\n      - '**/*'\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("customHttp.yml"),
        "customHeaders:\n  - pattern: '**'\n    headers:\n      - key: X-Built\n        value: 'yes'\n",
    )
    .unwrap();
    git(&repo, &["init", "-q"]);
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-q", "-m", "first page"]);

    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let amplify = aws_sdk_amplify::Client::new(&cfg);
    let app_id = amplify
        .create_app()
        .name("built")
        .repository(repo.to_string_lossy())
        .access_token("not-needed-for-local-repos")
        .environment_variables("GREETING", "hello")
        .send()
        .await
        .unwrap()
        .app
        .unwrap()
        .app_id()
        .to_string();
    amplify.create_branch().app_id(&app_id).branch_name("main").send().await.unwrap();
    let host = format!("main.{app_id}.amplifyapp.com");
    // Manual deployments are for apps without a repository.
    let err = amplify.create_deployment().app_id(&app_id).branch_name("main").send().await.unwrap_err();
    assert_eq!(err.code(), Some("BadRequestException"));

    let started =
        amplify.start_job().app_id(&app_id).branch_name("main").job_type(JobType::Release).send().await.unwrap();
    let id = started.job_summary().unwrap().job_id().to_string();
    let job = wait_for_job(&amplify, &app_id, "main", &id).await;
    let steps: Vec<(&str, &str)> = job.steps().iter().map(|s| (s.step_name(), s.status().as_str())).collect();
    assert_eq!(job.summary().unwrap().status(), &JobStatus::Succeed, "{steps:?}");
    assert_eq!(steps, vec![("BUILD", "SUCCEED"), ("DEPLOY", "SUCCEED"), ("VERIFY", "SUCCEED")]);
    assert_eq!(job.summary().unwrap().commit_message(), "first page");
    assert_eq!(job.summary().unwrap().commit_id().len(), 40);
    let (status, headers, body) = page(&mws, &host, "/", &[]).await;
    assert_eq!((status, body.as_str()), (200, "<p>built from git</p>"));
    assert_eq!(header(&headers, "x-built"), Some("yes"));
    assert_eq!(page(&mws, &host, "/env.txt", &[]).await.2, "main hello\n");

    // The build's artifacts.
    let artifacts = amplify.list_artifacts().app_id(&app_id).branch_name("main").job_id(&id).send().await.unwrap();
    let artifact = &artifacts.artifacts()[0];
    assert_eq!(artifact.artifact_file_name(), "artifacts.zip");
    let url = amplify.get_artifact_url().artifact_id(artifact.artifact_id()).send().await.unwrap();
    let (status, _, data) = mws.raw("GET", url.artifact_url(), &[], b"").await;
    assert_eq!(status, 200);
    let archive = zip::ZipArchive::new(std::io::Cursor::new(data)).unwrap();
    assert!(archive.file_names().any(|n| n == "index.html"));

    // A webhook call starts a build of the latest commit.
    std::fs::write(repo.join("src/page.html"), "<p>second</p>").unwrap();
    git(&repo, &["commit", "-q", "-am", "second page"]);
    let hook = amplify.create_webhook().app_id(&app_id).branch_name("main").send().await.unwrap().webhook.unwrap();
    let query = hook.webhook_url().split_once('?').unwrap().1;
    let (status, _, body) =
        mws.raw("POST", &format!("/prod/webhooks?{query}"), &[("Content-Type", "application/json")], b"{}").await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let hook_job: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let hook_id = hook_job["jobId"].as_str().unwrap();
    let job = wait_for_job(&amplify, &app_id, "main", hook_id).await;
    assert_eq!(job.summary().unwrap().job_type().as_str(), "WEB_HOOK");
    assert_eq!(job.summary().unwrap().status(), &JobStatus::Succeed);
    assert_eq!(page(&mws, &host, "/", &[]).await.2, "<p>second</p>");
    let (status, _, _) = mws.raw("POST", "/prod/webhooks?id=nope&token=nope", &[], b"").await;
    assert_eq!(status, 403);

    // A failing build fails the job and keeps the site; a retry reruns the
    // same commit; a running build can be stopped.
    amplify
        .update_branch()
        .app_id(&app_id)
        .branch_name("main")
        .build_spec("version: 1\nfrontend:\n  phases:\n    build:\n      commands:\n        - exit 3\n  artifacts:\n    baseDirectory: dist\n")
        .send()
        .await
        .unwrap();
    let failed =
        amplify.start_job().app_id(&app_id).branch_name("main").job_type(JobType::Release).send().await.unwrap();
    let failed_id = failed.job_summary().unwrap().job_id().to_string();
    let job = wait_for_job(&amplify, &app_id, "main", &failed_id).await;
    assert_eq!(job.summary().unwrap().status(), &JobStatus::Failed);
    assert_eq!(job.steps()[0].status().as_str(), "FAILED");
    assert_eq!(page(&mws, &host, "/", &[]).await.2, "<p>second</p>");
    let retry = amplify
        .start_job()
        .app_id(&app_id)
        .branch_name("main")
        .job_type(JobType::Retry)
        .job_id(&failed_id)
        .send()
        .await
        .unwrap();
    assert_eq!(retry.job_summary().unwrap().commit_id(), job.summary().unwrap().commit_id());
    wait_for_job(&amplify, &app_id, "main", retry.job_summary().unwrap().job_id()).await;

    amplify
        .update_branch()
        .app_id(&app_id)
        .branch_name("main")
        .build_spec("version: 1\nfrontend:\n  phases:\n    build:\n      commands:\n        - sleep 30\n")
        .send()
        .await
        .unwrap();
    let slow = amplify.start_job().app_id(&app_id).branch_name("main").job_type(JobType::Release).send().await.unwrap();
    let slow_id = slow.job_summary().unwrap().job_id().to_string();
    for _ in 0..100 {
        let j = amplify.get_job().app_id(&app_id).branch_name("main").job_id(&slow_id).send().await.unwrap();
        if j.job().unwrap().summary().unwrap().status() == &JobStatus::Running {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    amplify.stop_job().app_id(&app_id).branch_name("main").job_id(&slow_id).send().await.unwrap();
    let job = wait_for_job(&amplify, &app_id, "main", &slow_id).await;
    assert_eq!(job.summary().unwrap().status(), &JobStatus::Cancelled);
    let _ = std::fs::remove_dir_all(&repo);
}

#[tokio::test]
async fn custom_domains_verify_through_route53() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let amplify = aws_sdk_amplify::Client::new(&cfg);
    let route53 = aws_sdk_route53::Client::new(&cfg);
    let app_id = amplify.create_app().name("domains").send().await.unwrap().app.unwrap().app_id().to_string();
    amplify.create_branch().app_id(&app_id).branch_name("main").send().await.unwrap();
    let deployment = amplify.create_deployment().app_id(&app_id).branch_name("main").send().await.unwrap();
    mws.raw("PUT", deployment.zip_upload_url(), &[], &zip(&[("index.html", "custom domain")])).await;
    let job_id = deployment.job_id().unwrap();
    amplify.start_deployment().app_id(&app_id).branch_name("main").job_id(job_id).send().await.unwrap();
    wait_for_job(&amplify, &app_id, "main", job_id).await;

    // A domain hosted in Route 53 in this account: Amplify writes the
    // validation and subdomain records itself.
    route53.create_hosted_zone().name("example.com").caller_reference("amplify").send().await.unwrap();
    let www = SubDomainSetting::builder().prefix("www").branch_name("main").build().unwrap();
    let created = amplify
        .create_domain_association()
        .app_id(&app_id)
        .domain_name("example.com")
        .sub_domain_settings(www.clone())
        .send()
        .await
        .unwrap()
        .domain_association
        .unwrap();
    assert_eq!(created.domain_status().as_str(), "CREATING");
    assert!(created.certificate_verification_dns_record().unwrap().contains(".acm-validations.aws."));
    let got = amplify.get_domain_association().app_id(&app_id).domain_name("example.com").send().await.unwrap();
    let got = got.domain_association().unwrap();
    assert_eq!(got.domain_status().as_str(), "AVAILABLE");
    assert!(got.sub_domains()[0].verified());
    let branch = amplify.get_branch().app_id(&app_id).branch_name("main").send().await.unwrap().branch.unwrap();
    assert_eq!(branch.custom_domains(), ["www.example.com"]);
    let (status, _, body) = page(&mws, "www.example.com", "/", &[]).await;
    assert_eq!((status, body.as_str()), (200, "custom domain"));

    // A domain MWS has no zone for waits for its records.
    let other = amplify
        .create_domain_association()
        .app_id(&app_id)
        .domain_name("example.net")
        .sub_domain_settings(SubDomainSetting::builder().prefix("").branch_name("main").build().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(other.domain_association().unwrap().domain_name(), "example.net");
    let listed = amplify.list_domain_associations().app_id(&app_id).send().await.unwrap();
    let statuses: Vec<(&str, &str)> =
        listed.domain_associations().iter().map(|d| (d.domain_name(), d.domain_status().as_str())).collect();
    assert_eq!(statuses, vec![("example.com", "AVAILABLE"), ("example.net", "PENDING_VERIFICATION")]);
    let err = amplify
        .create_domain_association()
        .app_id(&app_id)
        .domain_name("example.com")
        .sub_domain_settings(www)
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("BadRequestException"));

    let updated = amplify
        .update_domain_association()
        .app_id(&app_id)
        .domain_name("example.com")
        .sub_domain_settings(SubDomainSetting::builder().prefix("app").branch_name("main").build().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(updated.domain_association().unwrap().sub_domains()[0].sub_domain_setting().unwrap().prefix(), "app");
    let got = amplify.get_domain_association().app_id(&app_id).domain_name("example.com").send().await.unwrap();
    assert_eq!(got.domain_association().unwrap().domain_status().as_str(), "AVAILABLE");
    assert_eq!(page(&mws, "app.example.com", "/", &[]).await.2, "custom domain");
    amplify.delete_domain_association().app_id(&app_id).domain_name("example.net").send().await.unwrap();
    let err = amplify.get_domain_association().app_id(&app_id).domain_name("example.net").send().await.unwrap_err();
    assert_eq!(err.code(), Some("NotFoundException"));
}

#[tokio::test]
async fn amplify_calls_are_authorized() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    iam.create_user().user_name("viewer").send().await.unwrap();
    iam.put_user_policy()
        .user_name("viewer")
        .policy_name("read")
        .policy_document(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["amplify:Get*","amplify:List*"],"Resource":"*"}]}"#)
        .send()
        .await
        .unwrap();
    let key = iam.create_access_key().user_name("viewer").send().await.unwrap().access_key.unwrap();
    let viewer = mws.sdk_config(key.access_key_id(), key.secret_access_key(), None).await;
    let viewer = aws_sdk_amplify::Client::new(&viewer);
    viewer.list_apps().send().await.unwrap();
    let err = viewer.create_app().name("nope").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDeniedException"));
}

/// A repository whose build writes its environment, its `secrets` and its
/// credentials into the deployed site.
fn env_repo(name: &str) -> std::path::PathBuf {
    let repo = std::env::temp_dir().join(format!("mws-amplify-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&repo);
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(
        repo.join("amplify.yml"),
        "version: 1\nfrontend:\n  phases:\n    build:\n      commands:\n        - mkdir -p dist\n        - env > dist/env.txt\n        - printf '%s' \"$secrets\" > dist/secrets.txt\n        - printf '%s\\n%s\\n%s\\n' \"$AWS_ACCESS_KEY_ID\" \"$AWS_SECRET_ACCESS_KEY\" \"$AWS_SESSION_TOKEN\" > dist/creds.txt\n        - echo ok > dist/index.html\n  artifacts:\n    baseDirectory: dist\n",
    )
    .unwrap();
    git(&repo, &["init", "-q"]);
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-q", "-m", "env"]);
    repo
}

/// Start a build and record every status a fast poller sees.
async fn build_and_watch(
    amplify: &aws_sdk_amplify::Client,
    app_id: &str,
) -> (aws_sdk_amplify::types::Job, Vec<String>) {
    let started =
        amplify.start_job().app_id(app_id).branch_name("main").job_type(JobType::Release).send().await.unwrap();
    let id = started.job_summary().unwrap().job_id().to_string();
    let mut seen = vec![started.job_summary().unwrap().status().as_str().to_string()];
    for _ in 0..3000 {
        let j = amplify.get_job().app_id(app_id).branch_name("main").job_id(&id).send().await.unwrap();
        let job = j.job.unwrap();
        let status = job.summary().unwrap().status().as_str().to_string();
        if seen.last() != Some(&status) {
            seen.push(status.clone());
        }
        if matches!(status.as_str(), "SUCCEED" | "FAILED" | "CANCELLED") {
            return (job, seen);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("job {id} did not finish");
}

#[tokio::test]
async fn builds_run_as_the_service_role_without_the_host_environment() {
    if std::process::Command::new("git").arg("--version").output().is_err() {
        eprintln!("skipping: git is not installed");
        return;
    }
    // A secret in MWS's own environment must never reach a build.
    std::env::set_var("MWS_TEST_HOST_SECRET", "host-secret-7f3a");
    let repo = env_repo("env");
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let amplify = aws_sdk_amplify::Client::new(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    let ssm = aws_sdk_ssm::Client::new(&cfg);
    let role = iam
        .create_role()
        .role_name("AmplifyBuildRole")
        .assume_role_policy_document(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"amplify.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#)
        .send()
        .await
        .unwrap()
        .role
        .unwrap();
    iam.put_role_policy()
        .role_name("AmplifyBuildRole")
        .policy_name("secrets")
        .policy_document(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ssm:GetParametersByPath","Resource":"*"}]}"#)
        .send()
        .await
        .unwrap();

    let app_id = amplify
        .create_app()
        .name("with-role")
        .repository(repo.to_string_lossy())
        .access_token("local")
        .iam_service_role_arn(role.arn())
        .send()
        .await
        .unwrap()
        .app
        .unwrap()
        .app_id()
        .to_string();
    amplify.create_branch().app_id(&app_id).branch_name("main").send().await.unwrap();
    for (name, value) in [
        (format!("/amplify/shared/{app_id}/SHARED"), "shared-value"),
        (format!("/amplify/shared/{app_id}/TOKEN"), "shared-token"),
        (format!("/amplify/{app_id}/main/TOKEN"), "branch-token"),
    ] {
        ssm.put_parameter()
            .name(name)
            .value(value)
            .r#type(aws_sdk_ssm::types::ParameterType::String)
            .send()
            .await
            .unwrap();
    }

    let (job, seen) = build_and_watch(&amplify, &app_id).await;
    assert_eq!(job.summary().unwrap().status(), &JobStatus::Succeed, "{seen:?}");
    let order: Vec<&str> = seen.iter().map(String::as_str).filter(|s| *s != "PENDING").collect();
    assert_eq!(order, ["PROVISIONING", "RUNNING", "SUCCEED"], "{seen:?}");

    let host = format!("main.{app_id}.amplifyapp.com");
    let env = page(&mws, &host, "/env.txt", &[]).await.2;
    assert!(!env.contains("MWS_TEST_HOST_SECRET") && !env.contains("host-secret-7f3a"), "{env}");
    for var in [
        format!("AWS_APP_ID={app_id}"),
        "AWS_BRANCH=main".into(),
        "AWS_REGION=us-east-1".into(),
        "AWS_DEFAULT_REGION=us-east-1".into(),
        "AWS_JOB_ID=0000000001".into(),
        "AWS_ENDPOINT_URL=".into(),
    ] {
        assert!(env.lines().any(|l| l.starts_with(&var)), "{var} missing from {env}");
    }
    let home = std::env::var("HOME").unwrap_or_default();
    if !home.is_empty() {
        assert!(!env.lines().any(|l| l == format!("HOME={home}")), "{env}");
    }

    // Branch secrets override shared ones.
    let secrets: serde_json::Value = serde_json::from_str(&page(&mws, &host, "/secrets.txt", &[]).await.2).unwrap();
    assert_eq!(secrets, serde_json::json!({ "SHARED": "shared-value", "TOKEN": "branch-token" }));

    // The credentials are the service role's, and they work.
    let creds = page(&mws, &host, "/creds.txt", &[]).await.2;
    let lines: Vec<&str> = creds.lines().collect();
    assert!(lines[0].starts_with("ASIA"), "{creds}");
    let role_cfg = mws.sdk_config(lines[0], lines[1], Some(lines[2])).await;
    let me = aws_sdk_sts::Client::new(&role_cfg).get_caller_identity().send().await.unwrap();
    assert!(me.arn().unwrap().contains(":assumed-role/AmplifyBuildRole/"), "{:?}", me.arn());

    // Without a service role a build gets no credentials and no secrets.
    let bare = amplify
        .create_app()
        .name("no-role")
        .repository(repo.to_string_lossy())
        .access_token("local")
        .send()
        .await
        .unwrap()
        .app
        .unwrap()
        .app_id()
        .to_string();
    amplify.create_branch().app_id(&bare).branch_name("main").send().await.unwrap();
    let (job, _) = build_and_watch(&amplify, &bare).await;
    assert_eq!(job.summary().unwrap().status(), &JobStatus::Succeed);
    let env = page(&mws, &format!("main.{bare}.amplifyapp.com"), "/env.txt", &[]).await.2;
    assert!(!env.contains("AWS_ACCESS_KEY_ID") && !env.contains("AWS_SECRET_ACCESS_KEY"), "{env}");
    assert!(!env.lines().any(|l| l.starts_with("secrets=")), "{env}");

    // A role Amplify may not assume fails the build.
    iam.create_role()
        .role_name("NotForAmplify")
        .assume_role_policy_document(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#)
        .send()
        .await
        .unwrap();
    let untrusted = format!("arn:aws:iam::{}:role/NotForAmplify", role.arn().split(':').nth(4).unwrap());
    amplify.update_app().app_id(&bare).iam_service_role_arn(&untrusted).send().await.unwrap();
    let (job, _) = build_and_watch(&amplify, &bare).await;
    assert_eq!(job.summary().unwrap().status(), &JobStatus::Failed);
    assert!(job.steps()[0].status_reason().unwrap_or_default().contains("Unable to assume specified IAM Role"));
    let _ = std::fs::remove_dir_all(&repo);
}

#[tokio::test]
async fn amplify_roles_need_pass_role_and_must_exist() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let amplify = aws_sdk_amplify::Client::new(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    let role = iam
        .create_role()
        .role_name("AmplifyRole")
        .assume_role_policy_document(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"amplify.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#)
        .send()
        .await
        .unwrap()
        .role
        .unwrap();
    let account = role.arn().split(':').nth(4).unwrap().to_string();
    let missing = format!("arn:aws:iam::{account}:role/DoesNotExist");

    // A role that does not exist is a bad request.
    let err = amplify.create_app().name("bad").iam_service_role_arn(&missing).send().await.unwrap_err();
    assert_eq!(err.code(), Some("BadRequestException"), "{err:?}");
    let err = amplify.create_app().name("bad").compute_role_arn(&missing).send().await.unwrap_err();
    assert_eq!(err.code(), Some("BadRequestException"), "{err:?}");
    let app_id = amplify
        .create_app()
        .name("good")
        .iam_service_role_arn(role.arn())
        .send()
        .await
        .unwrap()
        .app
        .unwrap()
        .app_id()
        .to_string();
    let err = amplify.update_app().app_id(&app_id).iam_service_role_arn(&missing).send().await.unwrap_err();
    assert_eq!(err.code(), Some("BadRequestException"));
    let err = amplify
        .create_branch()
        .app_id(&app_id)
        .branch_name("main")
        .compute_role_arn(&missing)
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("BadRequestException"));

    // Handing Amplify a role needs iam:PassRole for amplify.amazonaws.com.
    let policy = |pass: bool| {
        let pass = if pass {
            format!(
                r#",{{"Effect":"Allow","Action":"iam:PassRole","Resource":"{}","Condition":{{"StringEquals":{{"iam:PassedToService":"amplify.amazonaws.com"}}}}}}"#,
                role.arn()
            )
        } else {
            String::new()
        };
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"amplify:*","Resource":"*"}}{pass}]}}"#
        )
    };
    let (_, no_pass) = mws_e2e::user_with_policy(&mws, "no-pass", Some(&policy(false))).await;
    let no_pass = aws_sdk_amplify::Client::new(&no_pass);
    let err = no_pass.create_app().name("x").iam_service_role_arn(role.arn()).send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDeniedException"), "{err:?}");
    let err = no_pass.update_app().app_id(&app_id).compute_role_arn(role.arn()).send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDeniedException"));
    let err = no_pass
        .create_branch()
        .app_id(&app_id)
        .branch_name("dev")
        .compute_role_arn(role.arn())
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("AccessDeniedException"));
    no_pass.create_app().name("no-roles").send().await.unwrap();
    let (_, with_pass) = mws_e2e::user_with_policy(&mws, "with-pass", Some(&policy(true))).await;
    let with_pass = aws_sdk_amplify::Client::new(&with_pass);
    with_pass.create_app().name("y").iam_service_role_arn(role.arn()).send().await.unwrap();
    with_pass.create_branch().app_id(&app_id).branch_name("dev").compute_role_arn(role.arn()).send().await.unwrap();
    with_pass.update_branch().app_id(&app_id).branch_name("dev").compute_role_arn(role.arn()).send().await.unwrap();

    // Authorization comes before the lookup: a caller who may not read
    // apps is denied whether or not the app exists.
    let (_, nothing) = mws_e2e::user_with_policy(&mws, "nothing", None).await;
    let nothing = aws_sdk_amplify::Client::new(&nothing);
    for id in [app_id.as_str(), "dnotanappatall"] {
        let err = nothing.get_app().app_id(id).send().await.unwrap_err();
        assert_eq!(err.code(), Some("AccessDeniedException"), "{id}");
        let err = nothing.delete_branch().app_id(id).branch_name("main").send().await.unwrap_err();
        assert_eq!(err.code(), Some("AccessDeniedException"), "{id}");
        let err = nothing.get_job().app_id(id).branch_name("main").job_id("1").send().await.unwrap_err();
        assert_eq!(err.code(), Some("AccessDeniedException"), "{id}");
    }
    let err = amplify.get_app().app_id("dnotanappatall").send().await.unwrap_err();
    assert_eq!(err.code(), Some("NotFoundException"));
}

#[tokio::test]
async fn amplify_quotas_follow_service_quotas() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let amplify = aws_sdk_amplify::Client::new(&cfg);
    let quotas = aws_sdk_servicequotas::Client::new(&cfg);
    let mut first = None;
    for i in 0..25 {
        let app = amplify.create_app().name(format!("app-{i}")).send().await.unwrap().app.unwrap();
        first.get_or_insert(app.app_id().to_string());
    }
    let err = amplify.create_app().name("one-too-many").send().await.unwrap_err();
    assert_eq!(err.code(), Some("LimitExceededException"), "{err:?}");
    quotas
        .request_service_quota_increase()
        .service_code("amplify")
        .quota_code("L-1BED97F3")
        .desired_value(26.0)
        .send()
        .await
        .unwrap();
    let mut created = false;
    for _ in 0..50 {
        if amplify.create_app().name("after-increase").send().await.is_ok() {
            created = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(created, "the raised quota was never applied");

    // Five domains per app.
    let app_id = first.unwrap();
    amplify.create_branch().app_id(&app_id).branch_name("main").send().await.unwrap();
    let sub = SubDomainSetting::builder().prefix("www").branch_name("main").build().unwrap();
    for i in 0..5 {
        amplify
            .create_domain_association()
            .app_id(&app_id)
            .domain_name(format!("quota{i}.example"))
            .sub_domain_settings(sub.clone())
            .send()
            .await
            .unwrap();
    }
    let err = amplify
        .create_domain_association()
        .app_id(&app_id)
        .domain_name("quota5.example")
        .sub_domain_settings(sub)
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("LimitExceededException"), "{err:?}");
}

#[tokio::test]
async fn custom_certificates_are_checked_in_acm() {
    use aws_sdk_amplify::types::{CertificateSettings, CertificateType};
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let amplify = aws_sdk_amplify::Client::new(&cfg);
    let acm = aws_sdk_acm::Client::new(&cfg);
    let import = |names: &'static [&'static str]| {
        let acm = acm.clone();
        async move {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params =
                rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>()).unwrap();
            params.distinguished_name.push(rcgen::DnType::CommonName, names[0]);
            let now = ::time::OffsetDateTime::now_utc();
            params.not_before = now - ::time::Duration::days(1);
            params.not_after = now + ::time::Duration::days(90);
            let cert = params.self_signed(&key).unwrap().pem();
            acm.import_certificate()
                .certificate(aws_sdk_acm::primitives::Blob::new(cert.as_bytes()))
                .private_key(aws_sdk_acm::primitives::Blob::new(key.serialize_pem().as_bytes()))
                .send()
                .await
                .unwrap()
                .certificate_arn()
                .unwrap()
                .to_string()
        }
    };
    let wildcard = import(&["example.org", "*.example.org"]).await;
    let other = import(&["other.example"]).await;
    let app_id = amplify.create_app().name("certs").send().await.unwrap().app.unwrap().app_id().to_string();
    amplify.create_branch().app_id(&app_id).branch_name("main").send().await.unwrap();
    let custom = |arn: &str| {
        CertificateSettings::builder().r#type(CertificateType::Custom).custom_certificate_arn(arn).build().unwrap()
    };
    let subs = [
        SubDomainSetting::builder().prefix("").branch_name("main").build().unwrap(),
        SubDomainSetting::builder().prefix("www").branch_name("main").build().unwrap(),
    ];
    let associate = |domain: &'static str, arn: String| {
        amplify
            .create_domain_association()
            .app_id(&app_id)
            .domain_name(domain)
            .set_sub_domain_settings(Some(subs.to_vec()))
            .certificate_settings(custom(&arn))
            .send()
    };

    // A certificate that does not cover the domain, or does not exist.
    let err = associate("example.org", other.clone()).await.unwrap_err();
    assert_eq!(err.code(), Some("BadRequestException"), "{err:?}");
    let missing = format!("{}0000", &wildcard[..wildcard.len() - 4]);
    let err = associate("example.org", missing).await.unwrap_err();
    assert_eq!(err.code(), Some("BadRequestException"), "{err:?}");
    let err = associate("example.org", wildcard.replace("us-east-1", "eu-west-1")).await.unwrap_err();
    assert_eq!(err.code(), Some("BadRequestException"), "{err:?}");

    // The apex and one level under the wildcard are covered; two levels
    // are not.
    let created = associate("example.org", wildcard.clone()).await.unwrap().domain_association.unwrap();
    assert_eq!(created.certificate().unwrap().custom_certificate_arn(), Some(wildcard.as_str()));
    let err = amplify
        .update_domain_association()
        .app_id(&app_id)
        .domain_name("example.org")
        .sub_domain_settings(SubDomainSetting::builder().prefix("a.b").branch_name("main").build().unwrap())
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("BadRequestException"), "{err:?}");
}

use md5::Digest as _;
