# Private CA Connector for SCEP

> Crate: [`mws-pca-connector-scep`](../../crates/services/mws-pca-connector-scep) · Tests: [`tests/e2e-rust/tests/e2e/pca_connector_scep.rs`](../../tests/e2e-rust/tests/e2e/pca_connector_scep.rs)

All 12 operations are generated from the AWS model (restJson1) and implemented. Each connector runs a real SCEP (RFC 8894) server at the `Endpoint` it reports, `<MWS endpoint>/_aws/pca-connector-scep/<id>`, which devices call unsigned. Certificates come from MWS's Private CA, issued as `pca-connector-scep.amazonaws.com`, so the CA must be shared with the connector through [RAM](ram.md), as in AWS's setup guide.

✅ supported · 🟡 partial · ❌ not supported

## Connectors and challenges

| Feature | Status | Details |
| --- | :---: | --- |
| General-purpose connectors | ✅ | The CA must be owned by the caller, use `GENERAL_PURPOSE` mode, be `ACTIVE` and valid for at least a year; without a RAM share the connector is `FAILED` with `PRIVATECA_ACCESS_DENIED`. A new connector is `CREATING` and a deleted one `DELETING` for the settle window (`MWS_ASYNC_DELAY_MS`, 500 ms by default); `DeleteConnector` on either answers `ConflictException`. |
| Intune connectors | 🟡 | Created with an OpenID configuration, but enrollment is refused: MWS cannot reach Microsoft Intune to validate requests. |
| Challenge passwords | ✅ | Static passwords (up to 5 per connector) with metadata and tags; deleting one stops it working. |
| VPC endpoints | 🟡 | Accepted and reported, with no effect. |

## SCEP endpoint

| Feature | Status | Details |
| --- | :---: | --- |
| `GetCACaps` | ✅ | `AES`, `POSTPKIOperation`, `SCEPStandard`, `SHA-1`, `SHA-256`, `SHA-512`. |
| `GetCACert` | ✅ | `application/x-x509-ca-ra-cert`: the connector's RA certificate (issued by the CA), then the CA and its chain. |
| `PKIOperation` | ✅ | GET and POST, `PKCSReq` enrollment and `GetCertInitial` polling; BER input (indefinite lengths) as OpenSSL-based clients send it. |
| Message security | ✅ | The request's signature and digest are checked, its envelope opened with the RA key (RSA PKCS#1 v1.5 or OAEP, AES-128/192/256-CBC), and the `CertRep` is signed by the RA and encrypted to the requester. |
| Issued certificates | ✅ | The CSR's subject, SANs and extensions pass through (`APICSRPassthrough`); client authentication is added when the CSR has no extended key usage; valid for a year, capped at the CA's expiry. Revoking the share stops issuance. |
| Errors | ✅ | A wrong challenge password gets a `CertRep` failure (`badRequest`) with HTTP 400; other errors use AWS's messages. |
| DES and 3DES envelopes | ❌ | Not supported. |
| `RenewalReq`, `GetCert`, `GetCRL` | ❌ | Not supported. |
| `ValidityPeriod` attributes | ❌ | Ignored. |

See also: [all services](README.md) · [Private CA](acm-pca.md) · [RAM](ram.md).
