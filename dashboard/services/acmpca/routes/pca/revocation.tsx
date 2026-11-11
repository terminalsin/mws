import { Field } from "@mws-dashboard/ui";
import { CreateCertificateAuthority } from "@mws-dashboard/ui/model/acm-pca";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";

const CRL = CreateCertificateAuthority.RevocationConfiguration.fields!.CrlConfiguration.fields!;
const OCSP = CreateCertificateAuthority.RevocationConfiguration.fields!.OcspConfiguration.fields!;

export interface RevocationDefaults {
  crl?: boolean;
  bucket?: string;
  days?: number;
  crlCname?: string;
  ocsp?: boolean;
  ocspCname?: string;
}

/** CRL distribution (to S3) and OCSP, as CreateCertificateAuthority and
 * UpdateCertificateAuthority take them. */
export function RevocationFields({ d = {}, buckets = [] }: { d?: RevocationDefaults; buckets?: string[] }) {
  return (
    <>
      <label className="check">
        <input type="checkbox" name="crl" defaultChecked={d.crl} /> Publish a CRL to S3
      </label>
      <div className="form-row">
        <Field label="CRL bucket" rule={{ ...CRL.S3BucketName, format: "bucket" }} known={buckets} member="RevocationConfiguration.CrlConfiguration.S3BucketName">
          <ResourcePicker kind="s3-bucket" use="name" name="crlBucket" defaultValue={d.bucket} />
        </Field>
        <Field label="CRL valid (days)" rule={CRL.ExpirationInDays} member="RevocationConfiguration.CrlConfiguration.ExpirationInDays">
          <input name="crlDays" type="number" defaultValue={d.days ?? 7} />
        </Field>
      </div>
      <Field label="CRL custom name" rule={{ ...CRL.CustomCname, format: "domain" }} member="RevocationConfiguration.CrlConfiguration.CustomCname">
        <input name="crlCname" defaultValue={d.crlCname} placeholder="crl.example.com" />
      </Field>
      <label className="check">
        <input type="checkbox" name="ocsp" defaultChecked={d.ocsp} /> OCSP
      </label>
      <Field label="OCSP custom name" rule={{ ...OCSP.OcspCustomCname, format: "domain" }} member="RevocationConfiguration.OcspConfiguration.OcspCustomCname">
        <input name="ocspCname" defaultValue={d.ocspCname} placeholder="ocsp.example.com" />
      </Field>
    </>
  );
}
