# Amazon SES (v1 and v2)

> Crate: [`mws-ses`](../../crates/services/mws-ses) · Tests: [`tests/e2e-rust/tests/e2e/ses.rs`](../../tests/e2e-rust/tests/e2e/ses.rs)

All 71 SES v1 operations (awsQuery) and all 116 SES v2 operations (restJson1
under `/v2/email/`) are generated from the AWS models and implemented. Both
APIs share one state, as in AWS: an identity, template or configuration set
made through one is visible through the other. Mail is never sent to the
internet: it lands in an outbox tests read, or in this emulator's own
receiving.

✅ supported · 🟡 partial · ❌ not supported

## Sending

| Feature | Status | Details |
| --- | :---: | --- |
| `SendEmail`, `SendRawEmail`, templated and bulk sends | ✅ | v1 and v2, composed as SES composes them (MIME, `Message-ID`, attachments, custom headers). |
| Verified senders | ✅ | The sender or its domain must be a verified identity in the Region (`MessageRejected` with AWS's wording otherwise). |
| Sandbox and quotas | ✅ | 200 messages a day, 1 a second, verified recipients only, until `PutAccountDetails` asks for production access (granted at once: 50,000 a day, 14 a second). |
| Sending authorization | ✅ | Identity policies decide delegated sending (`SourceArn`, `FromArn`, `ReturnPathArn`, v2 identity ARNs). |
| IAM condition keys | ✅ | `ses:FromAddress`, `ses:FromDisplayName`, `ses:Recipients`, `ses:FeedbackAddress`, `ses:ApiVersion`, tags. |
| Templates | ✅ | SES's Handlebars subset (`{{var}}`, `{{{raw}}}`, `#if`, `#unless`, `#each`, `#with`); missing attributes are rendering failures. |
| Suppression list | ✅ | Account and configuration set suppression; hard bounces and complaints are added when its reasons say so. |
| Mailbox simulator | ✅ | `success@`, `bounce@`, `complaint@`, `ooto@` (an auto-reply lands in the outbox), `suppressionlist@simulator.amazonses.com`. |
| List management | ✅ | Contact lists and topics, `List-Unsubscribe` headers, and a working one-click unsubscribe link that raises `Subscription` events. |
| Outbox | ✅ | `GET /_aws/ses[?id=&email=&to=]` returns `{"messages": [...]}`; `DELETE` clears it. |
| Remote delivery | ❌ | Mail is never handed to another mail server. |
| Open and click tracking | ❌ | Links are not rewritten, so there are no `Open` or `Click` events. |
| DKIM signing | ❌ | Messages are not signed. |

## Identities

| Feature | Status | Details |
| --- | :---: | --- |
| Email identities | ✅ | Verified by following the link mailed to the outbox (`GET /_aws/ses/verify/<token>`), or a custom verification template's mail and redirects. |
| Domain identities | ✅ | Verified through Route 53 public hosted zones: the `_amazonses` `TXT` record, Easy DKIM `CNAME`s (`<token>._domainkey` → `<token>.dkim.amazonses.com`) or a BYODKIM `TXT` record. |
| Custom MAIL FROM | ✅ | Needs its `MX` record (`feedback-smtp.<region>.amazonses.com`); `BehaviorOnMXFailure` applies. |
| Verification windows | ✅ | Pending identities fail after 24 hours (links) or 72 hours (DNS) on the emulated clock. |
| Shortcuts for tests | ✅ | `MWS_SES_AUTO_VERIFY=1`, or `POST /_aws/ses/verify-identity?identity=`. |
| Notifications and feedback forwarding | ✅ | Bounce, complaint and delivery topics (with or without headers); forwarded feedback lands in the outbox. |

## Events and metrics

| Feature | Status | Details |
| --- | :---: | --- |
| Event records | ✅ | `Send`, `Delivery`, `Bounce`, `Complaint`, `RenderingFailure`, `Subscription` with SES's JSON, tags and headers. |
| SNS destinations | ✅ | Published as `ses.amazonaws.com`; the default topic policy admits the owner's own topics. |
| EventBridge destinations | ✅ | `aws.ses` events (`Email Sent`, `Email Bounced`, ...) on the default bus. |
| Firehose destinations | ✅ | Written as the IAM role SES assumes. |
| CloudWatch | ✅ | `AWS/SES` metrics per destination dimension, and account-wide counts. |
| `Reject` and `DeliveryDelay` events | ❌ | Nothing is scanned for viruses and nothing is delayed. |

## Receiving

| Feature | Status | Details |
| --- | :---: | --- |
| Receipt rule sets, rules and IP filters | ✅ | All v1 operations, with AWS's limits and errors (`AlreadyExists`, `RuleSetDoesNotExist`, `CannotDelete`, ...). |
| SMTP listener | ✅ | `MWS_SES_SMTP_LISTEN=127.0.0.1:2525`; recipients outside a hosted domain get `550`. Also `POST /_aws/ses/inbound`, and mail sent through SES to a hosted address. |
| S3 action | ✅ | Writes `<prefix><messageId>` as `ses.amazonaws.com` (the bucket policy must allow it) or as the action's role. |
| SNS action | ✅ | The `Received` notification with the content, UTF-8 or Base64, up to 150 KB. |
| Lambda action | ✅ | SES's `aws:ses` event, asynchronous or `RequestResponse` with `STOP_RULE` / `STOP_RULE_SET` dispositions; the function policy must allow SES. |
| Bounce, AddHeader and Stop actions | ✅ | Bounces land in the outbox and raise `Bounce` events for mail SES sent. |
| Permission checks | ✅ | `InvalidS3Configuration`, `InvalidSnsTopic`, `InvalidLambdaFunction` when SES may not use the resource. |
| Spam and virus verdicts | 🟡 | Always `PASS`. |
| S3 action KMS key | 🟡 | Encrypts server-side, not with the S3 encryption client. |
| WorkMail and Connect actions | ❌ | Recorded, but do nothing. |

## SMTP submission

| Feature | Status | Details |
| --- | :---: | --- |
| SES SMTP credentials | ✅ | `AUTH PLAIN` or `LOGIN` with an IAM access key id and the password SES derives from its secret (`mws_ses::smtp_password`). |
| Sending as the IAM identity | ✅ | Each message is a `SendRawEmail` by that identity: IAM, the sandbox and identity checks apply. |
| `X-SES-*` headers | ✅ | `X-SES-CONFIGURATION-SET`, `X-SES-MESSAGE-TAGS`, `X-SES-SOURCE-ARN`. |
| STARTTLS | ❌ | Not offered. |

## Everything else in v2

| Feature | Status | Details |
| --- | :---: | --- |
| Import and export jobs | ✅ | Import contacts or suppressed addresses from S3; export message insights or metrics to S3 (CSV or JSON). |
| VDM and insights | ✅ | VDM settings, `BatchGetMetricData`, message and address insights from the sends MWS recorded. |
| Multi-Region endpoints and tenants | ✅ | Endpoints, tenants, resource associations, tenant suppression and sending status. |
| Reputation entities and recommendations | ✅ | Customer-managed status and policies; DKIM recommendations when VDM is on. |
| Deliverability dashboard | 🟡 | Subscriptions and test reports work; placement figures are synthetic. |
| Dedicated IPs | 🟡 | Pools work, but no IPs can be leased, so they stay empty. |

See also: [all services](README.md) · [authentication and authorization](../security.md).
