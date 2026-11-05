# AWS Marketplace Metering and Entitlement Service

> Crates: [`mws-marketplace-metering`](../../crates/services/mws-marketplace-metering), [`mws-marketplace-entitlement`](../../crates/services/mws-marketplace-entitlement) · Tests: [`tests/e2e-rust/tests/e2e/marketplace.rs`](../../tests/e2e-rust/tests/e2e/marketplace.rs)

The two APIs a seller's software calls: Metering (`ResolveCustomer`,
`BatchMeterUsage`, `MeterUsage`, `RegisterUsage`; awsJson1.1) and the
Entitlement Service (`GetEntitlements`; RPC v2 CBOR, which current SDKs use, and
awsJson1.1). All 5 operations are generated from the AWS models and
implemented. Both sign as `aws-marketplace` and are authorized as
`aws-marketplace:<Action>` on `*`.

✅ supported · 🟡 partial · ❌ not supported

## Marketplace catalog

AWS fills the catalog through the Marketplace Management Portal and buyers'
purchases, which have no SDK operations. In MWS you seed it through the control
API at `/_aws/marketplace/` (unsigned JSON, camelCase):

| Request | Effect |
| --- | --- |
| `POST /_aws/marketplace/products` | List a product: `{"sellerAccountId": "123456789012", "productType": "SaaS" \| "AMI" \| "Container", "dimensions": [{"name": "users"}], "productCode"?, "title"?}`. Without `productCode` a 25-character code is made. The seller defaults to `MWS_ACCOUNT_ID`. |
| `GET /_aws/marketplace/products[/{code}]`, `DELETE .../{code}` | Read or delist products. |
| `POST /_aws/marketplace/subscriptions` | A buyer subscribes: `{"productCode", "customerAWSAccountId", "entitlements": [{"dimension", "value": {"integerValue": 10}, "expirationDate"?}], "customerIdentifier"?, "licenseArn"?, "agreementId"?, "tokenExpiresInSeconds"?}`. The answer carries the customer identifier, license ARN, agreement id and a `registrationToken`. Values are `integerValue`, `doubleValue`, `booleanValue` or `stringValue`. |
| `GET /_aws/marketplace/subscriptions[?productCode=&customerAWSAccountId=]`, `GET .../{customerIdentifier}` | Read subscriptions. |
| `DELETE /_aws/marketplace/subscriptions/{customerIdentifier}` | The buyer unsubscribes. |
| `PUT /_aws/marketplace/subscriptions/{customerIdentifier}/entitlements` | Replace its entitlements (`{"entitlements": [...]}`), e.g. after an upgrade. |
| `POST /_aws/marketplace/registration-tokens` | A new token for the SaaS landing page: `{"customerIdentifier", "expiresInSeconds"?}`. Tokens last an hour by default; `0` never expires, a negative value is already expired. |

What Metering accepted is readable at `/_aws/marketplace-metering/`:
`GET records[?productCode=&customerAWSAccountId=&customerIdentifier=&dimension=]`,
`DELETE records`, `GET registrations[?productCode=]` and `GET public-key` (the
PEM key that verifies `RegisterUsage` signatures).

The catalog and the records are part of MWS state (`/_mws/state`, snapshots,
`MWS_DB`).

## Metering

| Feature | Status | Details |
| --- | :---: | --- |
| `ResolveCustomer` | ✅ | Resolves a registration token to `CustomerIdentifier`, `CustomerAWSAccountId`, `ProductCode`, `LicenseArn` and `Metadata.AgreementId`, for the seller account that listed the product only (`InvalidTokenException` otherwise); `ExpiredTokenException` past the token's expiry on the emulated clock. |
| `BatchMeterUsage` | ✅ | Legacy records (`ProductCode` + `CustomerIdentifier`) and Concurrent Agreements records (`CustomerAWSAccountId` + `LicenseArn`, no `ProductCode`). Up to 25 records; the whole batch fails on an unknown customer, license, product or dimension, a timestamp 24 hours or more old, in the future, or before the month after the 06:00 UTC grace period, and on bad allocations. Each record is `Success`, `CustomerNotSubscribed` (cancelled or no subscription) or `DuplicateRecord` (another value for the same customer, dimension and hour); resending a record returns its original `MeteringRecordId`. |
| `MeterUsage` | ✅ | From the buyer's account (or the seller's, for testing its own listing): `CustomerNotEntitledException` without an active subscription. Once per reporting principal (instance or task role session), dimension and hour: identical repeats return the same record, another quantity is `DuplicateRequestException`. Six hours back at most. `ClientToken` idempotency (`IdempotencyConflictException`) and `DryRun`. |
| `RegisterUsage` | ✅ | Checks the subscription on a task's first call only (as AWS does), and answers a PS256 JWT with `productCode`, `publicKeyVersion`, `customerIdentifier`, `customerAWSAccountId`, `nonce` and `iat`, signed by MWS's own Marketplace key. Public key version 1 only (`InvalidPublicKeyVersionException`). |
| Usage allocations (vendor-metered tags) | ✅ | Sums must match the quantity (`InvalidUsageAllocationsException`), keys unique per allocation (`InvalidTagException`), tag sets unique. |
| Platform and Region checks | ❌ | `PlatformNotSupportedException`, `InvalidRegionException` and `InvalidEndpointRegionException` are never raised: MWS does not know where the caller runs. |
| Signature key | 🟡 | AWS's public key is replaced by MWS's (from `/_aws/marketplace-metering/public-key`), so code that pins AWS's key must be pointed at it. |
| Guessed wording | 🟡 | `DryRunOperation` (HTTP 412) and some error messages are not documented by AWS; messages follow the model's error descriptions. |
| Billing | ❌ | Records are kept for inspection; nothing is priced or invoiced. |

## Entitlements

| Feature | Status | Details |
| --- | :---: | --- |
| `GetEntitlements` | ✅ | Active subscriptions' entitlements for a product the caller sells; expired entitlements and cancelled subscriptions are left out. |
| Filters | ✅ | `CUSTOMER_IDENTIFIER`, `CUSTOMER_AWS_ACCOUNT_ID`, `LICENSE_ARN`, `DIMENSION`: values unioned, keys intersected; customer identifier and account id together are `InvalidParameterException`. |
| Pagination | ✅ | `MaxResults` 1-25 (default 25) and `NextToken`. |
| Another seller's or an unknown product | 🟡 | `InvalidParameterException`; AWS's exact wording is not documented. |

See also: [all services](README.md) · [authentication and authorization](../security.md).
