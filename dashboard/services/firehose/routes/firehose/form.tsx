import { AutoPick, Field } from "@mws-dashboard/ui";
import { CreateDeliveryStream as Rules } from "@mws-dashboard/ui/model/firehose";
import { MoreFields } from "@mws-dashboard/ui/presets";

import { DestinationSwitch } from "../../lib/destination-fields";
import { COMPRESSIONS } from "../../lib/firehose";

const S3 = Rules.ExtendedS3DestinationConfiguration.fields!;
const HTTP = Rules.HttpEndpointDestinationConfiguration.fields!;
const SPLUNK = Rules.SplunkDestinationConfiguration.fields!;
const FIELDSET = { border: 0, padding: 0, margin: 0, minWidth: 0 };

/** The destination half of the create form: S3, an HTTP endpoint or Splunk
 * (each with its S3 bucket for backups), buffering, compression, a Lambda
 * transform and error logging. */
export function DestinationFields({
  buckets,
  functions,
}: {
  buckets: { value: string; label: string }[];
  functions: string[];
}) {
  return (
    <DestinationSwitch name="destination">
      <fieldset data-dest="http" style={FIELDSET}>
        <Field
          label="Endpoint URL"
          rule={{ ...HTTP.EndpointConfiguration.fields!.Url, required: false }}
          format="url"
        >
          <input name="url" placeholder="https://example.com/ingest" />
        </Field>
        <div className="form-grid">
          <Field
            label="Endpoint name"
            rule={HTTP.EndpointConfiguration.fields!.Name}
          >
            <input name="endpointName" />
          </Field>
          <Field
            label="Access key"
            rule={HTTP.EndpointConfiguration.fields!.AccessKey}
          >
            <input name="accessKey" type="password" autoComplete="off" />
          </Field>
          <Field
            label="Content encoding"
            rule={HTTP.RequestConfiguration.fields!.ContentEncoding}
          >
            <select name="encoding" defaultValue="NONE">
              <option value="NONE">None</option>
              <option value="GZIP">GZIP</option>
            </select>
          </Field>
          <Field label="S3 backup" rule={HTTP.S3BackupMode}>
            <select name="httpBackup" defaultValue="FailedDataOnly">
              <option value="FailedDataOnly">Failed data only</option>
              <option value="AllData">All data</option>
            </select>
          </Field>
        </div>
      </fieldset>
      <fieldset data-dest="splunk" style={FIELDSET}>
        <Field
          label="HEC endpoint"
          rule={{ ...SPLUNK.HECEndpoint, required: false }}
          format="url"
        >
          <input name="hec" placeholder="https://splunk.example.com:8088" />
        </Field>
        <div className="form-grid">
          <Field label="Endpoint type" rule={SPLUNK.HECEndpointType}>
            <select name="hecType" defaultValue="Raw">
              <option>Raw</option>
              <option>Event</option>
            </select>
          </Field>
          <Field label="HEC token" rule={SPLUNK.HECToken}>
            <input name="hecToken" type="password" autoComplete="off" />
          </Field>
          <Field label="S3 backup" rule={SPLUNK.S3BackupMode}>
            <select name="splunkBackup" defaultValue="FailedEventsOnly">
              <option value="FailedEventsOnly">Failed events only</option>
              <option value="AllEvents">All events</option>
            </select>
          </Field>
        </div>
      </fieldset>
      <fieldset data-dest="http splunk" style={FIELDSET}>
        <Field
          label="Retry duration (s)"
          rule={{
            ...HTTP.RetryOptions.fields!.DurationInSeconds,
            unit: "seconds",
          }}
        >
          <input name="retry" type="number" defaultValue={300} />
        </Field>
      </fieldset>
      <AutoPick
        name="bucket"
        label="Destination bucket"
        creates="firehose-<account>-<region>"
        options={buckets}
        testId="destination-bucket"
      />
      <MoreFields label="Buffering, prefix, transform">
        <div className="form-grid">
          <Field label="Prefix" rule={S3.Prefix}>
            <input name="prefix" placeholder="events/" />
          </Field>
          <Field label="Error prefix" rule={S3.ErrorOutputPrefix}>
            <input
              name="errorPrefix"
              placeholder="errors/!{firehose:error-output-type}/"
            />
          </Field>
          <Field
            label="Buffer interval (s)"
            rule={S3.BufferingHints.fields!.IntervalInSeconds}
          >
            <input
              name="interval"
              type="number"
              min={0}
              max={900}
              defaultValue={300}
            />
          </Field>
          <Field
            label="Buffer size (MiB)"
            rule={S3.BufferingHints.fields!.SizeInMBs}
          >
            <input name="size" type="number" defaultValue={5} />
          </Field>
          <Field label="Compression" rule={S3.CompressionFormat}>
            <select name="compression" defaultValue="UNCOMPRESSED">
              {COMPRESSIONS.map((c) => (
                <option key={c}>{c}</option>
              ))}
            </select>
          </Field>
        </div>
        <fieldset data-dest="s3" style={FIELDSET}>
          <Field label="File extension" rule={S3.FileExtension}>
            <input name="extension" placeholder=".json" />
          </Field>
          <label className="check">
            <input type="checkbox" name="backup" /> Back up source records
          </label>
        </fieldset>
        <Field
          label="Transform with Lambda"
          rule={{ format: "arn", known: functions }}
        >
          <input
            name="lambda"
            list="firehose-functions"
            placeholder="arn:aws:lambda:…"
          />
        </Field>
        <datalist id="firehose-functions">
          {functions.map((f) => (
            <option key={f} value={f} />
          ))}
        </datalist>
        <label className="check">
          <input type="checkbox" name="logging" /> Log delivery errors to
          CloudWatch
        </label>
      </MoreFields>
    </DestinationSwitch>
  );
}
