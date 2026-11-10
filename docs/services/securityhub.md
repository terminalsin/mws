# AWS Security Hub

> Crate: [`mws-securityhub`](../../crates/services/mws-securityhub) · Tests: [`tests/e2e-rust/tests/e2e/securityhub.rs`](../../tests/e2e-rust/tests/e2e/securityhub.rs), [`securityhub_controls.rs`](../../tests/e2e-rust/tests/e2e/securityhub_controls.rs)

All 126 operations are generated from the AWS model (restJson1) and implemented, including the V2 (OCSF) API. Findings are stored as ASFF and served as OCSF through the V2 calls, so both views of a finding stay in step.

✅ supported · 🟡 partial · ❌ not supported

## Hub, products and standards

| Feature | Status | Details |
| --- | :---: | --- |
| Hub lifecycle | ✅ | `EnableSecurityHub` with default standards, tags and control finding generator; it creates the `AWSServiceRoleForSecurityHub` service-linked role in IAM (path `/aws-service-role/securityhub.amazonaws.com/`), which needs `iam:CreateServiceLinkedRole` (condition key `iam:AWSServiceName`) while the role does not exist; `DescribeHub`, `UpdateSecurityHubConfiguration`, `DisableSecurityHub` (refused for members and delegated administrators). Calls before enabling answer `InvalidAccessException` with AWS's wording. |
| Product integrations | ✅ | Catalogue of AWS integrations (enabled with the hub) and partner products; `EnableImportFindingsForProduct` subscriptions gate imports from partner products. |
| Standards | ✅ | FSBP, CIS 1.2.0 (ruleset ARN), CIS 1.4.0 and 3.0.0, PCI DSS 3.2.1, NIST 800-53 r5 and the resource tagging standard, with subscription ARNs and statuses as AWS reports them. |
| Control catalogue | ✅ | About 350 security controls from a data table (`src/controls.txt`): every AWS Foundational Security Best Practices v1.0.0 control (about 290) and the CIS v1.2.0, v1.4.0 and v3.0.0 controls with AWS's IDs, titles, severities, standard control IDs and CIS requirements, and remediation URLs (`https://docs.aws.amazon.com/securityhub/latest/userguide/<svc>-controls.html#<svc>-<n>`). PCI DSS v3.2.1 and NIST SP 800-53 r5 memberships and NIST requirements are partial (the controls listed above plus the common ones); the tagging standard lists only `ACM.3`. Descriptions are AWS's for the evaluated controls and derived from the title for the rest. Per-standard control status, consolidated security controls, parameter updates with validation, and standards control associations. |
| Control evaluation | 🟡 | No AWS Config: the checks read the emulated services directly, as the service-linked role. Evaluated: `CloudTrail.1`, `CloudTrail.2`, `EC2.2`, `EC2.19`, `GuardDuty.1`, `IAM.1`, `IAM.2`, `IAM.4`, `IAM.6`, `IAM.9`, `KMS.4`, `Lambda.1`, `RDS.3`, `S3.1`, `S3.5`, `S3.8`, `SecretsManager.1` (with `maximumAllowedRotationFrequency`), `SecurityHub.1`, `SNS.1`, `SQS.1`. Each enabled control gets one finding per resource with `Compliance.Status` `PASSED`/`FAILED`/`NOT_AVAILABLE`, `Compliance.SecurityControlId`, `AssociatedStandards`, `RelatedRequirements`, `GeneratorId` `security-control/<ID>` (consolidated) or the per-standard generator with `STANDARD_CONTROL`, AWS's `ProductFields` (`RelatedAWSResources:0/*` naming the Config rule), `INFORMATIONAL` severity when passed, and the workflow transitions (passed → `RESOLVED`, failing again → `NEW`). Findings of disabled controls and deleted resources are archived. Checks run before the next Security Hub request after enabling Security Hub, standards or controls, after any successful write to another service in the account (AWS: change-triggered), and every 12 hours of emulated time (`/_mws/clock`). Other controls produce no findings. |
| Custom actions, tags | ✅ | Action targets CRUD; tags on the hub, automation rules, configuration policies, connectors and aggregators. |
| Cross-Region aggregation | ✅ | Finding aggregators (`ALL_REGIONS`, `ALL_REGIONS_EXCEPT_SPECIFIED`, `SPECIFIED_REGIONS`, `NO_REGIONS`); the home Region sees findings from linked Regions. |

## Findings

| Feature | Status | Details |
| --- | :---: | --- |
| `BatchImportFindings` | ✅ | ASFF validation (schema version, account, timestamps, severity, resources, enabled product), Security Hub's own fields (`ProductName`, `CompanyName`, `Region`, `ProcessedAt`, `aws/securityhub/*` product fields, normalized severity, `FindingProviderFields`), and the update rules: provider updates never overwrite fields a customer set with `BatchUpdateFindings`, and a resolved finding reported again is reopened. Partial failures come back as `FailedFindings`. |
| `GetFindings` filters | ✅ | Every ASFF filter attribute: string (equals, prefix, contains and their negations), number, date (ranges and `DateRange`), boolean, map, IP/CIDR and keyword filters, sort criteria and pagination. |
| Workflow updates | ✅ | `BatchUpdateFindings` (with `FindingNotFound` for unknown findings) and the deprecated `UpdateFindings`. |
| Finding history | ✅ | `GetFindingHistory` records the creation, provider imports and customer updates with the fields that changed. |
| Insights | ✅ | Custom insights and Security Hub's managed insights, with grouped `GetInsightResults`. |
| Automation rules | ✅ | V1 rules (ordered, terminal, applied on import) and V2 rules on OCSF criteria. |
| EventBridge | ✅ | `Security Hub Findings - Imported` events on the default bus, source `aws.securityhub`. Other AWS services import findings through `SecurityHub::import_findings_as_service`. |

## Accounts

| Feature | Status | Details |
| --- | :---: | --- |
| Invitations | ✅ | `CreateMembers`, `InviteMembers`, accept/decline/delete invitations (both the administrator and the older master APIs), disassociation by either side; administrators see their enabled members' findings. |
| Organizations | ✅ | `EnableOrganizationAdminAccount` registers the delegated administrator in AWS Organizations (and enables trusted access); the delegated administrator adds organization accounts without invitations and can auto-enable Security Hub and default standards. |
| Central configuration | ✅ | `CENTRAL` organization configuration (needs a home-Region aggregator), configuration policies with standards and control settings, associations to accounts, OUs and the root with inheritance and self-managed targets; policies are applied to the target accounts. |

## Security Hub V2

| Feature | Status | Details |
| --- | :---: | --- |
| Enablement | ✅ | `EnableSecurityHubV2`, features, aggregators V2, free trial statuses and the V2 product catalogue. |
| OCSF findings | ✅ | `GetFindingsV2` (composite filters with nesting, sort, pagination), `BatchUpdateFindingsV2`, statistics and severity trends. |
| Resources and software | ✅ | Inventories derived from the resources and vulnerable packages in findings, with statistics and trends. |
| Exports | ✅ | Export jobs write findings to S3 as `securityhub.amazonaws.com` (judged by the bucket policy), encrypted with the job's KMS key. Jobs finish immediately (`SUCCEEDED` or `FAILED` with the reason). |
| Connectors | 🟡 | Jira Cloud (OAuth authorization URL and `RegisterConnectorV2`), ServiceNow and Azure connectors, and `CreateTicketV2`. Tickets are recorded but not sent anywhere. |
| Remediations, recommended policies | ❌ | `GetRemediationsV2` returns nothing; recommended policies report that the finding is not supported. |

## Security

| Feature | Status | Details |
| --- | :---: | --- |
| IAM authorization | ✅ | Every call is authorized as `securityhub:<Action>` on the hub or resource ARN, with `aws:RequestTag`/`aws:TagKeys` conditions on creates. |

## Known gaps

- Only the controls listed under Control evaluation produce findings; the rest of the catalogue never evaluates. There is no AWS Config, so `GetEnabledStandards` never reports `INCOMPLETE` / `NO_AVAILABLE_CONFIGURATION_RECORDER`. The security score and per-control pass/fail summary are console views AWS derives from these findings; the API has no such fields.
- PCI DSS and NIST 800-53 standard memberships are partial (see Control catalogue).
- GuardDuty, Inspector and the other AWS integrations send findings only where those services are emulated and wired to `import_findings_as_service`.
- Remediation analysis and recommended policies are not modelled.

See also: [all services](README.md) · [authentication and authorization](../security.md).
