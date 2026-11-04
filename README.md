# MWS

A lightweight local stand-in for AWS, written in Rust, for testing code that
talks to AWS. Point an unmodified AWS SDK at it and it should behave like the
real service: same wire protocol, same validation messages, same error codes,
real SigV4 authentication.

It is not meant to carry load. It is meant to tell you whether your code
would work against AWS. State lives in memory by default; it can optionally
be saved to a local SQLite file, seeded from a scenario file, reset between
tests and snapshotted (see [State, scenarios and snapshots](#state-scenarios-and-snapshots)).

## Status

| Service | State |
| --- | --- |
| IAM | All 180 operations are implemented, generated from the AWS model and validating input like AWS: users, groups, roles, access keys, login profiles, managed and inline policies, permissions boundaries, tags, instance profiles, OIDC and SAML providers, virtual MFA devices (real TOTP codes, QR PNGs), SSH public keys, signing and server certificates (key pair checks), service-specific credentials, the password policy and `ChangePassword`, the credential report, access advisor (service last accessed, `ListPoliciesGrantingServiceAccess`), service-linked roles, delegation requests, outbound web identity federation, account properties and summary, authorization details, and the policy simulator. Centralized root access and Organizations access reports follow the caller's organization, and no AWS role templates exist. Access-key last use, access advisor and Organizations access reports come from the requests MWS actually authorized. |
| STS | All operations: `GetCallerIdentity`, `AssumeRole` (trust policies, session policies, tags, transitive tags, external id, source identity, role chaining limits), MFA codes checked against IAM virtual devices, `GetSessionToken`, `GetFederationToken`, `AssumeRoleWithWebIdentity`, `AssumeRoleWithSAML` (assertions are checked like AWS, and the response or assertion must carry a valid XML signature from a certificate in the provider's metadata), `GetWebIdentityToken` (RS256/ES384 JWTs), `GetDelegatedAccessToken`, `DecodeAuthorizationMessage`, `GetAccessKeyInfo`, and `AssumeRoot` (root task sessions in member accounts once the organization enables root sessions). Cross-account `AssumeRole` into member accounts. |
| Organizations | All 63 operations are generated from the AWS model (awsJson1.1). Implemented: organizations (all features or consolidated billing), roots, nested OUs (depth limit), `CreateAccount` creating real member accounts with their own IAM namespace and `OrganizationAccountAccessRole`, moving, removing, leaving and closing accounts, invitations and the other handshakes (enable all features, billing responsibility transfers), every policy type with per-type validation and attachment limits, `EnablePolicyType`/`DisablePolicyType` (FullAWSAccess and RCPFullAWSAccess attached everywhere), effective management policies merged with the inheritance operators, trusted service access, delegated administrators, the organization resource policy, and tags. SCPs and RCPs are enforced by the IAM engine for member accounts. `CreateGovCloudAccount` fails as it does for accounts without GovCloud. |
| Route 53 | All 71 operations are generated from the AWS model (restXml). Implemented: public and private hosted zones (create, get, list, list by name and by VPC, count, comment, delete, VPC associate/disassociate), atomic `ChangeResourceRecordSets` (CREATE, UPSERT, DELETE with Route 53's `InvalidChangeBatch` messages, CNAME conflicts, apex rules, A/AAAA value checks), `ListResourceRecordSets` in Route 53's order with pagination and `\052` escaping, `GetChange`, health checks (status always healthy), traffic policies and instances, DNSSEC key-signing keys backed by real KMS keys (the key policy must allow `dnssec-route53.amazonaws.com`; DNSKEY and DS records come from the key's public key), reusable delegation sets, CIDR collections, query logging configs (the CloudWatch Logs group must exist and allow Route 53; the DNS responder writes query logs to it), VPC association authorizations, limits, `TestDNSAnswer`, geo locations, and tags. Changes report `PENDING` and then `INSYNC`. An optional DNS responder serves the zones over UDP. |
| Private CA | All 23 operations are generated from the AWS model (awsJson1.1). Implemented: root and subordinate CAs with real keys (RSA 2048/3072/4096, EC P-256/P-384/P-521), CSRs, self-issued root certificates, import with chain checks, `IssueCertificate` with ACM PCA templates (end-entity, server/client auth, code signing, OCSP, root, subordinate path lengths), validity rules, `GetCertificate` with chains, revocation, disable/delete/restore, tags, permissions, and CA resource policies evaluated by the IAM engine. Certificates verify with standard X.509 tooling. CRLs and audit reports (JSON or CSV) are written into S3 buckets as `acm-pca.amazonaws.com`, so the bucket policy must allow it as in AWS (checked when the CRL bucket is configured and when a report is requested); OCSP is answered unsigned. Not yet: API passthrough extensions, and hash/curve combinations other than the natural ones for EC keys. |
| S3 | 111 of 112 operations, generated from the AWS model (restXml with S3's quirks: no error wrapping, `x-id` routing, `x-amz-meta-*`, raw payloads). Path-style and virtual-hosted addressing, SigV4 headers, presigned URLs and `aws-chunked` streaming uploads with chunk and trailer signatures (Signature Version 2 is refused as for new buckets). Buckets (global names, per-account listing, `ExpectedBucketOwner`), objects with metadata, ranges, conditional reads and writes, checksums (CRC32/CRC32C/CRC64NVME/SHA1/SHA256, composite and full-object multipart), multipart uploads and copies, versioning with delete markers, `ListObjects`/`V2`/`ListObjectVersions` with delimiters and pagination, `DeleteObjects`, `CopyObject`, tagging, object attributes, ACLs and ownership controls, Block Public Access, bucket policies evaluated by the IAM engine (cross-account needs both sides, anonymous access through public policies or ACLs), CORS with preflight, SSE-S3, SSE-C and SSE-KMS through KMS with the caller's permissions, Object Lock (retention, legal hold), and the bucket configuration APIs (lifecycle, website, logging, notifications, replication, analytics/metrics/inventory/intelligent tiering, accelerate, request payment). Lifecycle rules act on the emulated clock (`POST /_mws/clock {"advanceSeconds":n}` moves it; expiration, noncurrent expiration, transitions, multipart abort, `x-amz-expiration`), and replication rules copy new versions and delete markers to the destination as the configured role, with replication status on both sides. `SelectObjectContent` runs S3 Select SQL (projections, `WHERE`, `LIMIT`, `CAST`, `LIKE`/`IN`/`BETWEEN`/`CASE`, string functions, `COUNT`/`SUM`/`AVG`/`MIN`/`MAX`) over CSV and JSON (DOCUMENT/LINES), GZIP or BZIP2 compressed, with scan ranges, streamed as event-stream `Records`/`Progress`/`Stats`/`End`. Directory buckets (`name--zone--x-s3`): `s3express:` authorization for bucket management, `CreateSession` credentials that the SDKs sign object requests with (ReadOnly sessions cannot write), `EXPRESS_ONEZONE` storage, `ListDirectoryBuckets` and `RenameObject`. Object annotations, torrents, and S3 Metadata journal/inventory/annotation table configurations (described, not queryable). Event notifications are delivered: `PutBucketNotificationConfiguration` checks event names, filters and overlapping rules, asks each SNS topic, SQS queue or Lambda function whether S3 may use it (the topic, queue or function policy must allow `s3.amazonaws.com`), and sends topics and queues an `s3:TestEvent`; object creations, removals (with delete markers), tagging, ACL and restore requests then send the S3 event message to the matching destinations. Server access logging is delivered: requests to a logging bucket write records in S3's access log format to the target bucket (`SimplePrefix` or `PartitionedPrefix` keys, one object per request rather than AWS's batches) as `logging.s3.amazonaws.com`, which the target bucket's policy must allow; a target owned by another account is refused with `InvalidTargetBucketForLogging`. Inventory configurations deliver reports at 00:00 UTC on the emulated clock (the first midnight after the configuration is put, then daily or weekly) as `s3.amazonaws.com`, which the destination bucket policy must allow: gzipped CSV or Parquet data files, `manifest.json`, `manifest.checksum` and a Hive `symlink.txt` in AWS's layout, with current or all versions, a prefix filter, the optional fields in AWS's column order, and SSE-S3 or SSE-KMS (the key policy must let S3 generate data keys); ORC reports are not written. Other configurations (website, analytics) are stored and returned; archived objects restore instantly. Access points and Object Lambda access points (from S3 Control) serve data by ARN (host-style, `{name}-{account}.{endpoint}`) or by alias (`...-s3alias`, `...--ol-s3`), authorized against the access point policy and the bucket policy (`s3:DataAccessPointArn` and friends). Object Lambda runs the Lambda function for transformed `GetObject`, `HeadObject` and `ListObjects*` requests: the function gets a `getObjectContext` with an `inputS3Url`, presigned with SigV4 and temporary credentials that act as the caller, that reads the original object through the supporting access point (with `aws:CalledVia` and `aws:ViaAWSService`), and its `WriteGetObjectResponse` (status, headers, metadata, error codes) becomes the caller's response; `LambdaNotFound`, `LambdaPermissionError`, `LambdaResponseNotReceived`, `LambdaRuntimeError` and `LambdaTimeout` as in AWS. Not yet: Parquet input for Select. |
| S3 Control | All 97 operations are generated from the AWS model (restXml, `{AccountId}.` host prefix, `x-amz-account-id`). Implemented: access points (create, get, list, delete, VPC network origin, their own Block Public Access, policies with `BlockPublicPolicy` checks, policy status, tags), Object Lambda access points (create, get, list, delete, transformation configurations, allowed features, policies, policy status) and account-level Block Public Access, which S3 applies to every bucket of the account. Not yet: multi-Region access points, Batch Operations jobs, Storage Lens, Access Grants and Outposts buckets. |
| Lambda | 68 of 88 operations are generated from the AWS model (restJson1) and implemented; functions really run. `Invoke` (`RequestResponse`, `Event` with retries, maximum event age and Lambda destinations, `DryRun`), `InvokeAsync` and `InvokeWithResponseStream` start an execution environment speaking the Lambda Runtime API: Python and Node.js functions run on the local `python3`/`node` (`MWS_LAMBDA_PYTHON`/`MWS_LAMBDA_NODE` pick the interpreter) with a runtime client that loads handlers and reports errors as Lambda does, and `provided.*` functions run their own `bootstrap`. Environments stay warm, honour timeouts and reserved concurrency (throttling with `TooManyRequestsException`), capture logs (`START`/`END`/`REPORT`, `LogType: Tail`, and CloudWatch Logs groups written as the execution role), and get the execution role's STS credentials and `AWS_ENDPOINT_URL` pointing back at MWS, so SDKs inside functions use the emulator. Also: zips direct or from S3, code downloads, versions, aliases with weighted routing, resource policies (`AddPermission`), layers (on `PYTHONPATH`/`NODE_PATH`/`PATH`) and their permissions, `iam:PassRole` and trust policy checks, environment variables, tags, function URLs that serve HTTP (by `Host: <id>.lambda-url.<region>.on.aws` or at `/_aws/lambda-url/<id>/`, payload format 2.0 events and responses, CORS, `AWS_IAM` SigV4 or `NONE` with the resource policy granting `lambda:InvokeFunctionUrl` and `lambda:InvokeFunction` with `lambda:InvokedViaFunctionUrl`; `RESPONSE_STREAM` responses are buffered), event invoke configs, provisioned concurrency, recursion and runtime management settings, code signing configs, and event source mappings. SQS mappings really poll: `CreateEventSourceMapping` checks the execution role may receive, delete and read attributes (and that the queue's visibility timeout covers the function's timeout), batches arrive as `aws:sqs` records with `BatchSize` and `MaximumBatchingWindowInSeconds` honoured, processed messages are deleted, failed batches return after their visibility timeout (so the queue's redrive policy applies), and `ReportBatchItemFailures` keeps only the reported messages. Mappings for other sources (Kinesis, DynamoDB, Kafka, MQ, DocumentDB) are stored only. `FilterCriteria` on SQS mappings is applied with the EventBridge pattern language (records that match no filter are deleted without invoking the function, as Lambda does). Container images are stored but cannot run. Not yet: durable executions, capacity providers, scaling configs and account resource policies. |
| CloudWatch Logs | All 118 operations are generated from the AWS model (awsJson1.1, event streams). Implemented: log groups (classes, retention against event timestamps, deletion protection, bearer token setting, KMS keys checked against their key policy for `logs.<region>.amazonaws.com`) and streams, `PutLogEvents` with AWS's ordering, batch span and too-old/too-new/expired rules, `GetLogEvents` and `FilterLogEvents` with forward/backward tokens and the full filter pattern syntax (terms, `?` alternatives, JSON `{ $.x > 1 }` and space-delimited `[a, b=5*]` patterns), live tail (`StartLiveTail` keeps its event stream open and pushes matching events every second), CloudWatch Logs Insights queries (`fields`, `filter`, `parse` glob and regex, `stats` with the aggregate functions and `bin()`, `sort`, `limit`, `dedup`, `display`, `@ptr`, `GetLogRecord`, `GetLogObject`, query definitions, field discovery), resource policies (account-wide and per log group, with revision ids) that the IAM engine evaluates with `aws:ResourceTag` conditions, account policies, data protection policies that mask events ingested after them unless the caller may `logs:Unmask`, field index policies and `DescribeFieldIndexes`, metric filters and subscription filters (patterns checked, `TestMetricFilter` really matches and extracts), destinations with cross-account access policies, transformers (`TestTransformer` runs the processors: JSON, key-value, CSV, grok, date conversion, string and key operations) that apply at ingestion (log group transformers or account `TRANSFORMER_POLICY` policies): the original and transformed events are both kept, `GetLogEvents` and `FilterLogEvents` return originals, Logs Insights queries the transformed events, and subscription filters use them with `applyOnTransformedLogs`, vended log delivery sources, destinations, destination policies and deliveries, and export tasks that write gzipped events into S3 as `logs.<region>.amazonaws.com`, judged by the bucket policy. Subscription filters to Lambda functions deliver matching events as gzipped, base64 `awslogs` payloads (`PutSubscriptionFilter` checks the function policy lets `logs.amazonaws.com` invoke it). Other services write here as AWS does: Lambda functions log to `/aws/lambda/<name>` as their execution role, and Route 53 query logging checks the log group's resource policy and the DNS responder writes query logs. Stored and described only: anomaly detectors (no anomalies are found), scheduled queries (not run), OpenSearch and S3 Tables integrations, lookup tables, syslog configurations and the storage tier. Not yet: metric filters publishing metrics (MWS has no CloudWatch metrics), subscription filters to Kinesis, Firehose or destinations, deliveries delivering, SQL and PPL queries, and imports (no CloudTrail Lake). |
| SQS | All 23 operations are generated from the AWS model (awsJson1.0, `awsQueryCompatible`: errors carry the awsQuery code in `x-amzn-query-error`, so SDKs report `AWS.SimpleQueueService.NonExistentQueue` and friends). Legacy awsQuery requests from older SDKs are answered too, generated from the same model. Standard and FIFO queues hold real messages: queue and per-message delays, visibility timeouts with fresh receipt handles per receive (stale handles stop acting), long polling that wakes when a message arrives, retention against the emulated clock, MD5 digests of bodies and message attributes as SQS computes them, message attribute and size validation, FIFO message groups (a group with a message in flight yields nothing further), deduplication (explicit or content-based, per queue or per group, five minutes), sequence numbers and `ReceiveRequestAttemptId` retries. Dead-letter queues receive messages after `maxReceiveCount` receives (`DeadLetterQueueSourceArn`), with redrive allow policies, and message move tasks redrive them back or to another queue at `MaxNumberOfMessagesPerSecond` (cancellable while running). `PurgeQueue` once a minute, queue names blocked for 60 s after deletion, batch operations with SQS's entry rules, `AddPermission`/`RemovePermission` editing the queue policy, tags, and `ListQueues`/`ListDeadLetterSourceQueues` pagination. Queue policies are evaluated by the IAM engine with `aws:ResourceTag` conditions; SSE-KMS queues get data keys from MWS KMS with the caller's permissions (`kms:GenerateDataKey` to send, `kms:Decrypt` to receive), and `alias/aws/sqs` works. Other services deliver as AWS service principals judged by the queue policy (`Sqs::send_message_as_service`). |
| SSM Parameter Store | The Parameter Store part of Systems Manager: 19 of the 152 SSM operations, generated from the AWS model (awsJson1.1). `PutParameter`, `GetParameter`, `GetParameters`, `GetParametersByPath`, `DescribeParameters`, `GetParameterHistory`, `DeleteParameter(s)`, `LabelParameterVersion`, `UnlabelParameterVersion`, tags, service settings, and resource policies. Parameters keep up to 100 versions (`ParameterMaxVersionLimitExceeded` when the oldest is labelled), are read by name, ARN, `name:version` or `name:label`, and follow AWS's naming rules (reserved `aws`/`ssm` prefixes, 15 hierarchy levels, `foo` and `/foo` being the same parameter). `String`, `StringList` and `SecureString` types, `text`/`aws:ec2:image`/`aws:ssm:integration` data types, allowed patterns, Standard/Advanced/Intelligent-Tiering tiers with their size limits and the account's default tier setting, and every `ParameterFilters` key and option. SecureStrings are really encrypted with KMS for the caller (`alias/aws/ssm` by default, `kms:ViaService`, encryption context `PARAMETER_ARN`; envelope encryption for advanced parameters), so `WithDecryption` needs `kms:Decrypt`. Parameter policies are validated, and `Expiration` deletes the parameter when the emulated clock passes it. Advanced parameters can be shared with other accounts through resource policies (read by ARN, `DescribeParameters --shared`). `/aws/reference/secretsmanager/<id>[:version-or-label]` names read the secret from Secrets Manager as the caller (`secretsmanager:GetSecretValue` and the secret's KMS key apply). Every policy sends its "Parameter Store Policy Action" event to EventBridge when the emulated clock reaches it (`ExpirationNotification` and `NoChangeNotification` then show `Finished`). Public parameters under `/aws/service/` answer `GetParameter(s)` and `GetParametersByPath` with account-less ARNs: the Region and service catalogues under `global-infrastructure/` and the latest Amazon Linux, ECS- and EKS-optimized AMI parameters (stable made-up `ami-` ids per Region, since there is no EC2). Not yet: "Parameter Store Change" events, and the rest of Systems Manager, which answers `NotImplemented`: Run Command, Automation and runbooks, State Manager associations, documents, managed nodes and hybrid activations, inventory, compliance, Patch Manager, maintenance windows, Session Manager, OpsCenter and OpsMetadata, Change Calendar, Explorer resource data syncs and node/access requests. |
| Secrets Manager | All 23 operations are generated from the AWS model (awsJson1.1). Implemented: secrets with string or binary values, versions and staging labels moved as Secrets Manager moves them (`AWSCURRENT`, `AWSPREVIOUS` following it, `AWSPENDING`, custom labels, deprecated versions, idempotent `ClientRequestToken`s), name, ARN and partial-ARN lookup, `BatchGetSecretValue` with per-secret errors, `ListSecrets` filters (prefix, negation, `all`), sorting and pages, `GetRandomPassword`, tags, and deletion with a recovery window on the emulated clock, `RestoreSecret` and forced deletion. Every version is sealed with AES-256-GCM under a KMS data key generated through Secrets Manager (`kms:ViaService`, the secret ARN and version id as encryption context), so customer managed keys need `kms:Decrypt` and disabled keys fail with `DecryptionFailure`/`EncryptionFailure`; `aws/secretsmanager` is created on first use. Resource policies are evaluated by the IAM engine with Secrets Manager's condition keys, `BlockPublicPolicy` and `ValidateResourcePolicy` reject public statements. Rotation really runs: `RotateSecret` checks that the function policy allows `secretsmanager.amazonaws.com`, adds the empty `AWSPENDING` version and invokes the Lambda function through `createSecret`, `setSecret`, `testSecret` and `finishSecret`; the function calls back with its execution role. Schedules (`AutomaticallyAfterDays`, `rate()`, `cron()` with `Duration` windows) set `NextRotationDate` and start rotations when the emulated clock reaches the window. Replicas live in their Region with their own KMS key, follow every change to the primary, are read-only, and can be removed or promoted. Managed external secrets (`Type`, `ExternalSecretRotation*`) are stored but not rotated (no partners to call). |
| EventBridge | All 57 operations are generated from the AWS model (awsJson1.1). Implemented: the default event bus of every account and Region, custom buses and partner event buses, bus policies (`PutPermission`/`RemovePermission` or whole documents) that the IAM engine evaluates for cross-account `PutEvents` and rule management, rules with EventBridge's full event pattern language (exact values, `prefix`, `suffix`, `equals-ignore-case`, `wildcard`, `anything-but`, `numeric`, `exists`, `cidr`, `$or`, arrays) and its validation messages, `TestEventPattern`, scheduled rules (`rate()` and six-field `cron()` against the emulated clock), targets with `Input`, `InputPath` and `InputTransformer`, retry policies and dead-letter queues. Events really reach targets: SNS topics (allowed by the topic policy), SQS queues (sent as `events.amazonaws.com`, allowed by the queue policy, with `MessageGroupId` for FIFO queues; dead-letter queues get EventBridge's error attributes), Lambda functions (invoked asynchronously as `events.amazonaws.com`, allowed by the function policy), CloudWatch Logs groups (one stream per event, allowed by the Logs resource policy), other buses in any account or Region (through a target role, or the receiving bus policy), and API destinations (real HTTP requests with basic, API key or OAuth client credentials auth from the connection, path, header and query parameters). S3 buckets with EventBridge notifications turned on put `aws.s3` events (`Object Created`, `Object Deleted`, restores, tags, ACLs, storage class changes) on the owner's default bus, SSM parameter policies send "Parameter Store Policy Action" events, and ACM sends "ACM Certificate Approaching Expiration" events. Archives keep matching events (with EventBridge's managed rule) and replays send them back with `replay-name`. Connections, API destinations, global endpoints (`PutEvents` with `EndpointId` goes to the primary bus), partner event sources (`PutPartnerEvents`), and tags. `iam:PassRole` is checked for rule and target roles. Not yet: other target types (Kinesis, Step Functions, ECS, ...) are accepted but not delivered; event bus logging and KMS encryption are stored only. |
| SNS | All 42 operations are generated from the AWS model (awsQuery). Implemented: standard and FIFO topics (name rules, idempotent `CreateTopic`, attributes with AWS's defaults and `EffectiveDeliveryPolicy`, the default access policy, `AddPermission`/`RemovePermission`, access policies the IAM engine evaluates with `aws:ResourceTag` conditions, tags, data protection policies), subscriptions for every protocol with endpoint checks, confirmation tokens, `ReturnSubscriptionArn`, `AuthenticateOnUnsubscribe` and attributes, filter policies on message attributes or the message body (exact, prefix, suffix, `anything-but`, `numeric`, `exists`, `cidr`, `equals-ignore-case`, `$or`) with AWS's limits, `Publish` and `PublishBatch` with message attribute and size checks, `MessageStructure` JSON, FIFO group ids, sequence numbers and five-minute deduplication (content based or explicit), mobile push platform applications and endpoints, SMS settings, opt-outs and the SMS sandbox. Messages are really delivered and signed (`SignatureVersion` 1 or 2) with a certificate served at `SigningCertURL`: Lambda functions get the SNS event asynchronously as `sns.amazonaws.com` when the function policy allows it, SQS queues get the envelope or the raw message (with its attributes, FIFO group and deduplication ids) when the queue policy allows it, as do dead-letter queues, HTTP/HTTPS endpoints get signed `SubscriptionConfirmation`, `Notification` (raw or enveloped, retried per the delivery policy) and `UnsubscribeConfirmation` POSTs, and the unsigned `SubscribeURL`/`UnsubscribeURL` links work. Email, SMS and push messages land in an outbox at `/_aws/sns/email-messages`, `/sms-messages` and `/platform-endpoint-messages` (with `/_aws/sns/subscription-tokens/<arn>` and `POST /_aws/sns/sms-opt-out?phoneNumber=` for tests). Other services publish as AWS does: S3 event notifications, judged by the topic policy. Delivery status logging works for Lambda, SQS, HTTP/S and application endpoints: with `<Protocol>SuccessFeedbackRoleArn`/`FailureFeedbackRoleArn` set, SNS assumes the role and writes AWS's status records to `sns/<region>/<account>/<topic>` (successes sampled by `SuccessFeedbackSampleRate`) and `.../Failure`. Server-side encryption: topics with `KmsMasterKeyId` get a data key from KMS for every publish, so publishers need `kms:GenerateDataKey*` and `kms:Decrypt` on the key (`KMSAccessDenied`, `KMSDisabled`, `KMSInvalidState`, `KMSNotFound` otherwise); the AWS managed key `alias/aws/sns` works through SNS for the whole account, and AWS services publishing for a resource (S3 events, EventBridge) need the key policy to allow their service principal. Not yet: Firehose delivery, data protection policies acting on messages, and FIFO message archiving and replay. |
| ACM | All 40 operations are generated from the AWS model (awsJson1.1). Certificates are real X.509 with real keys. Public certificates are signed by issuing CAs MWS makes for itself (`Amazon RSA 2048 M01`, `Amazon ECDSA 256/384 M01` under `MWS Root CA 1`, so `Issuer` reads `Amazon`), valid for 198 days. DNS validation is real: ACM hands out the per-account CNAME record (wildcards share their base domain's) and issues once the record exists in a public hosted zone in MWS's Route 53. Email validation goes to the usual five addresses; MWS logs each "validation email" with its approval link (`/_acm/approvals?certificate=<arn>&domain=<domain>`, unsigned) that approves the domain. Private certificates (`CertificateAuthorityArn`) are issued by MWS's Private CA with the requester's `acm-pca:IssueCertificate` permission (failures show as `PCA_*` failure reasons) and renewed by `acm.amazonaws.com` when the CA grants it with `CreatePermission`. Imports check that the key (PKCS#8, PKCS#1 or SEC1) matches the certificate and support reimport; exports return the key as PBES2-encrypted PKCS#8 under the passphrase, for private and exportable public certificates, and exported public certificates can be revoked. The lifecycle follows the emulated clock: validation times out after 72 hours, certificates expire, and managed renewal starts 60 days before expiry (public ones renew while their DNS records still validate). Also: email-to-DNS validation migration (`UpdateCertificateOptions`, `ListCertificateDomainValidations`), `ListCertificates` filters (RSA_2048 by default, ACME certificates only when asked), `SearchCertificates` with nested `And`/`Or`/`Not` filter statements and every sort key, tags, account configuration, failure reasons for non-public domains, and IAM condition keys (`acm:ValidationMethod`, `acm:DomainNames`, `acm:KeyAlgorithm`, `acm:CertificateAuthority`, `acm:Export`, `aws:ResourceTag`). Managed ACME endpoints run a real RFC 8555 server at `<MWS endpoint>/_acme/<id>/directory`: external account binding (HS256) is required, domain prevalidations write their CNAME into the hosted zone as the caller and become `VALID` once it resolves, orders for covered identifiers are `ready` at once (`PRE_APPROVED`), and finalized orders are issued for the client's own key and appear in ACM with key pair origin `ACME`. ACM assumes the binding's role as `acm.amazonaws.com`, which needs `acm:RequestCertificate` to order and `acm:RevokeCertificate` to revoke. Accounts can be updated, deactivated, rekeyed (`key-change`) and revoked. Issued certificates send a daily "ACM Certificate Approaching Expiration" event to EventBridge from the account's `DaysBeforeExpiry` on (emulated clock). Not yet: integrated services (`InUseBy` is always empty), other ACM events, and HTTP validation (CloudFront only). |
| KMS | All 56 operations are generated from the AWS model (awsJson1.1). Keys do real cryptography: symmetric keys encrypt with AES-256-GCM and bind the encryption context, `Decrypt` finds the key from the ciphertext, and RSA, ECC (P-256/384/521, secp256k1), Ed25519, ML-DSA, HMAC, ECDH and ML-KEM keys sign, verify, encrypt, MAC, agree and encapsulate with results that check out in standard tooling. Data keys and data key pairs, `ReEncrypt`, `GenerateRandom`, aliases, tags, enable/disable, scheduled deletion (lazy, by wall clock), automatic and on-demand rotation (old ciphertexts keep decrypting), imported key material (all wrapping algorithms, expiry, re-import of the same material only), multi-Region keys and replicas, and `DryRun`. Key policies are evaluated the way KMS does (the key policy must allow the caller, directly or by delegating to IAM), with the policy lockout safety check, and grants (with encryption context constraints) allow their grantees. Other services use KMS keys through the crate's API (`kms:ViaService`, AWS managed `alias/aws/*` keys, service principals). Not supported: SM2 (China Regions only), Nitro Enclaves `Recipient`, `ED25519_PH_SHA_512` and ML-DSA `EXTERNAL_MU`; custom key stores can be managed but never connect (no CloudHSM, no reachable XKS proxy). |

Authentication is real: requests must carry a valid SigV4 signature (header or
presigned URL) from a known access key or STS session. Failures come back the
way each service reports them: `InvalidClientTokenId` and
`SignatureDoesNotMatch` from awsQuery services (IAM, STS, SNS, SQS),
`UnrecognizedClientException` and `InvalidSignatureException` from JSON
services (status 400 for awsJson, 403 for Lambda), `InvalidAccessKeyId` from
S3, and `MissingAuthenticationToken(Exception)` for unsigned requests in the
protocol of the service they address.

Authorization is real too. Every call to every service is evaluated against
the caller's IAM policies with AWS's evaluation logic: explicit deny wins;
identity policies (inline, managed, group) must allow; permissions boundaries
and session policies cap them; resource policies and role trust policies are
honoured (including account-level delegation). Requests across accounts need
both the caller's identity policies and the resource's policy. For member
accounts of an organization, service control policies (every level of the OU
tree must allow) and resource control policies apply too, and the
`aws:PrincipalOrgID`/`aws:PrincipalOrgPaths`/`aws:ResourceOrg*` keys are set.
Conditions support every
operator (`String*`, `Numeric*`, `Date*`, `Bool`, `IpAddress`, `Arn*`,
`Binary*`, `Null`, `...IfExists`, `ForAllValues:`/`ForAnyValue:`) and policy
variables such as `${aws:username}`. Denials use AWS's message wording.

The account root user is allowed everything, as in AWS. Notes:
`AssumeRoleWithWebIdentity` verifies token signatures as AWS does: it fetches
the issuer's keys through OpenID Connect discovery
(`https://<issuer>/.well-known/openid-configuration`, then `jwks_uri`) and
trusts the provider's TLS certificate when it chains to a public root or
matches a thumbprint on the IAM OIDC provider, so a local identity provider
with a self-signed certificate works once its thumbprint is registered.
Tokens from MWS's own `GetWebIdentityToken` are checked against MWS's keys.
AWS managed policies are a trimmed subset covering the services MWS
emulates.

## Running

```sh
cargo run -p mws            # listens on 0.0.0.0:4566
```

| Variable | Default |
| --- | --- |
| `MWS_LISTEN` | `0.0.0.0:4566` |
| `MWS_ACCOUNT_ID` | `123456789012` |
| `MWS_ROOT_ACCESS_KEY_ID` | `AKIAMWSROOTEXAMPLE00` |
| `MWS_ROOT_SECRET_ACCESS_KEY` | `mwsRootSecretAccessKeyEXAMPLEKEY00000000` |
| `MWS_DNS_LISTEN` | unset; e.g. `127.0.0.1:5353` starts the Route 53 DNS responder |
| `MWS_DB` | unset (in memory); a path such as `.mws/state.db` keeps state in SQLite across restarts |
| `MWS_SCENARIO` | unset; a scenario file run at startup and used as the reset baseline |
| `MWS_LAMBDA_PYTHON` / `MWS_LAMBDA_NODE` | unset (`python3.x`/`python3` and `node` from `PATH`); the interpreter Lambda functions run on |
| `MWS_SKIP_FEDERATION_SIGNATURE_VERIFICATION` | unset; `1` accepts web identity tokens and SAML responses without checking their signatures (for test suites that hand-craft them) |
| `RUST_LOG` | `info` |

Then use any SDK or the CLI with the endpoint overridden:

```sh
export AWS_ENDPOINT_URL=http://localhost:4566
export AWS_ACCESS_KEY_ID=AKIAMWSROOTEXAMPLE00
export AWS_SECRET_ACCESS_KEY=mwsRootSecretAccessKeyEXAMPLEKEY00000000
export AWS_REGION=us-east-1
aws iam create-user --user-name alice
aws iam create-access-key --user-name alice   # these keys now authenticate as alice
```

Some SDK calls put a name in front of the endpoint's host, as AWS does: S3
Control requests go to `{account-id}.localhost:4566`, and S3 requests that
name an access point or Object Lambda access point ARN go to
`{name}-{account-id}.localhost:4566`. Those names must resolve to MWS
(wildcard DNS for the endpoint host, or a custom resolver in the SDK's HTTP
client). Access point aliases need no DNS: they are used as bucket names.
Code running inside Lambda functions gets `AWS_DISABLE_HOST_PREFIX_INJECTION`
so that `WriteGetObjectResponse` goes straight to the endpoint.

## State, scenarios and snapshots

**Persistence.** With `MWS_DB` set, every service's state is written to that
SQLite file shortly after each change (within about 250 ms) and again on
shutdown (Ctrl-C or SIGTERM), and comes back on the next start. Temporary
STS credentials survive too, until they expire.

**Scenarios.** A scenario is a JSON list of API calls that sets up state.
Each step names the service (its signing name), the operation, and the input
in the same shape as `aws ... --cli-input-json`. Steps go through the real
handlers, so they are validated and authorized like SDK calls (as the root
user unless a step sets `accessKeyId`). A step with an `id` exposes its output
to later steps as `${id.Path.To.Field}`, with optional `|basename` (strip
`/hostedzone/`) and `|base64` (for blob inputs such as a CSR) filters.
If any step fails, the whole scenario is rolled back and the error names the
step.

```json
{
  "steps": [
    { "service": "iam", "action": "CreateUser", "input": { "UserName": "deployer" } },
    { "id": "key", "service": "iam", "action": "CreateAccessKey", "input": { "UserName": "deployer" } },
    { "id": "zone", "service": "route53", "action": "CreateHostedZone",
      "input": { "Name": "example.internal", "CallerReference": "seed" } },
    { "service": "route53", "action": "ChangeResourceRecordSets",
      "input": { "HostedZoneId": "${zone.HostedZone.Id|basename}", "ChangeBatch": { "Changes": [
        { "Action": "CREATE", "ResourceRecordSet": { "Name": "api.example.internal", "Type": "A",
          "TTL": 60, "ResourceRecords": [{ "Value": "10.0.0.10" }] } } ] } } }
  ]
}
```

[`examples/scenario.json`](examples/scenario.json) also creates a role and
a Private CA and activates it with a self-signed root certificate.

`MWS_SCENARIO` runs a scenario at startup on an empty emulator, and the
result becomes the **baseline** that `POST /_mws/reset` returns to. With
`MWS_DB` as well, the scenario runs only once: later starts restore the saved
state. If the scenario file changes, the saved state is replaced by a fresh
run of the new scenario (the old state is kept as a snapshot named
`before-scenario-change-...`).

**Control API.** Plain unsigned JSON over HTTP on the same port:

| Request | Effect |
| --- | --- |
| `GET /_mws/health` | liveness and the emulated services |
| `GET /_mws/state` | export the whole emulator's state |
| `PUT /_mws/state` | replace it with an exported document |
| `POST /_mws/reset` | back to the baseline (`?to=empty` for a fresh emulator) |
| `POST /_mws/scenario` | run a scenario now; returns the outputs of steps with an `id`. `?baseline=true` makes the result the new baseline |
| `GET /_mws/snapshots` | list named snapshots |
| `PUT /_mws/snapshots/{name}` | save the current state |
| `GET /_mws/snapshots/{name}` | export a snapshot |
| `POST /_mws/snapshots/{name}/restore` | replace the current state with a snapshot |
| `DELETE /_mws/snapshots/{name}` | delete a snapshot |
| `GET /_mws/clock` | the emulated time and its offset from the wall clock |
| `POST /_mws/clock` | move the emulated time: `{"advanceSeconds": n}` or `{"offsetSeconds": n}` (time-based behaviour such as S3 lifecycle follows it; signatures still use the wall clock) |

A typical test suite starts MWS with a scenario and calls `POST /_mws/reset`
before each test. Snapshots live in the database when `MWS_DB` is set, and in
memory otherwise. The control API is unauthenticated, like the rest of a
local emulator: don't expose the port beyond your machine.

## Layout

```
crates/
  mws-core          service-agnostic contracts: ServiceError, RequestContext, Caller,
                    Authorizer, CredentialStore, Service
  mws-sigv4         SigV4 verification (header + presigned query)
  mws-smithy        reads Smithy JSON AST models
  mws-codegen       generates server stubs from Smithy models (build-time)
  mws-proto-query   awsQuery protocol runtime (form decoding, XML, errors)
  mws-proto-restxml restXml protocol runtime (HTTP binding, routing, XML, errors)
  mws-proto-json    awsJson1.0/1.1 protocol runtime (X-Amz-Target, JSON, errors)
  mws-proto-restjson restJson1 protocol runtime (HTTP bindings, JSON bodies, errors)
  mws-xml           XML writer and reader shared by the XML protocols
  mws-server        HTTP front door: authenticates, routes by signing name; the
                    /_mws control API, scenarios, snapshots and persistence
  mws-store         SQLite persistence of opaque per-service state documents
  mws               the binary; the only crate that knows which services exist
  services/
    mws-iam         IAM: model/iam.json + behaviour
    mws-iam-policy  the IAM policy language and evaluation logic
    mws-sts         STS: temporary credentials over IAM identities
    mws-route53     Route 53: hosted zones, record sets, health checks, DNS responder
    mws-acmpca      AWS Private CA: CAs and real X.509 issuance
    mws-kms         KMS: keys with real cryptography, key policies, grants, aliases
    mws-s3          S3: buckets, objects, multipart, versioning, policies, SSE, lifecycle, replication, Select, Object Lambda
    mws-s3control   S3 Control: access points, Object Lambda access points, account Block Public Access
    mws-lambda      Lambda: functions that really run on local runtimes via the Runtime API
    mws-logs        CloudWatch Logs: log events, filter patterns, Insights queries, live tail
    mws-sqs         SQS: standard and FIFO queues, long polling, dead-letter queues, redrive
    mws-ssm         SSM Parameter Store: versioned parameters, KMS SecureStrings, policies, sharing
    mws-events      EventBridge: buses, rules with event patterns, targets that really receive events
    mws-secretsmanager  Secrets Manager: KMS-sealed versions, resource policies, Lambda rotation, replicas
    mws-sns         SNS: topics, subscriptions, filter policies and signed deliveries
    mws-acm         ACM: public, private and imported certificates, DNS validation, ACME endpoints
examples/
  scenario.json     a sample scenario: IAM user and role, a hosted zone, an active CA
tests/
  e2e-rust          official Rust SDK against an in-process MWS
  e2e-python        boto3 against the mws binary
```

Each service is its own crate that depends only on generic crates. Shared
crates are protocol or infrastructure code, never service logic.

## Testing

```sh
cargo test --workspace
cargo build -p mws && pip install -r tests/e2e-python/requirements.txt && pytest tests/e2e-python
```
