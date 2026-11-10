import type {
  DeliveryStreamDescription,
  ProcessingConfiguration,
} from "@aws-sdk/client-firehose";

const bucketOf = (arn: string | undefined) => arn?.split(":::").pop() ?? "";

/** The console page of an S3 location (bucket and prefix up to its first
 * expression, since `!{timestamp:...}` parts vary per object). */
export function s3Href(bucketArn: string | undefined, prefix = "") {
  const fixed = prefix.split("!{")[0];
  const folder = fixed.includes("/")
    ? fixed.slice(0, fixed.lastIndexOf("/") + 1)
    : "";
  return `/s3/${encodeURIComponent(bucketOf(bucketArn))}${folder ? `?${new URLSearchParams({ prefix: folder })}` : ""}`;
}

/** Where a Firehose stream delivers, as a kind and a short target. */
export function destinationOf(s: DeliveryStreamDescription) {
  const d = s.Destinations?.[0];
  if (d?.ExtendedS3DestinationDescription || d?.S3DestinationDescription) {
    const x = d.ExtendedS3DestinationDescription ?? d.S3DestinationDescription!;
    return {
      kind: "S3",
      icon: "resource/AmazonSimpleStorageServiceBucket",
      target: `s3://${bucketOf(x.BucketARN)}/${x.Prefix ?? ""}`,
      href: s3Href(x.BucketARN, x.Prefix),
    };
  }
  if (d?.HttpEndpointDestinationDescription)
    return {
      kind: "HTTP",
      icon: "resource/Internet",
      target:
        d.HttpEndpointDestinationDescription.EndpointConfiguration?.Url ?? "",
      href: undefined,
    };
  if (d?.RedshiftDestinationDescription)
    return {
      kind: "Redshift",
      icon: "service/AmazonRedshift",
      target: d.RedshiftDestinationDescription.ClusterJDBCURL ?? "",
      href: undefined,
    };
  const os =
    d?.AmazonopensearchserviceDestinationDescription ??
    d?.ElasticsearchDestinationDescription;
  if (os)
    return {
      kind: "OpenSearch",
      icon: "service/AmazonOpenSearchService",
      target: [
        os.ClusterEndpoint ?? os.DomainARN?.split("/").pop(),
        os.IndexName,
      ]
        .filter(Boolean)
        .join(" / "),
      href: undefined,
    };
  if (d?.AmazonOpenSearchServerlessDestinationDescription) {
    const x = d.AmazonOpenSearchServerlessDestinationDescription;
    return {
      kind: "OpenSearch Serverless",
      icon: "service/AmazonOpenSearchService",
      target: [x.CollectionEndpoint, x.IndexName].filter(Boolean).join(" / "),
      href: undefined,
    };
  }
  if (d?.SplunkDestinationDescription)
    return {
      kind: "Splunk",
      icon: "resource/Internet",
      target: d.SplunkDestinationDescription.HECEndpoint ?? "",
      href: undefined,
    };
  if (d?.SnowflakeDestinationDescription)
    return {
      kind: "Snowflake",
      icon: "resource/Internet",
      target: d.SnowflakeDestinationDescription.AccountUrl ?? "",
      href: undefined,
    };
  if (d?.IcebergDestinationDescription)
    return {
      kind: "Iceberg",
      icon: "resource/AmazonSimpleStorageServiceBucket",
      target: "Apache Iceberg tables",
      href: undefined,
    };
  return {
    kind: "Other",
    icon: "service/AmazonDataFirehose",
    target: "",
    href: undefined,
  };
}

/** The Lambda function a processing configuration invokes, if any. */
export function lambdaOf(
  p: ProcessingConfiguration | undefined,
): string | undefined {
  if (!p?.Enabled) return undefined;
  return p.Processors?.find((x) => x.Type === "Lambda")?.Parameters?.find(
    (x) => x.ParameterName === "LambdaArn",
  )?.ParameterValue;
}

/** The processing configuration for a Lambda transform (or none). */
export function lambdaProcessing(
  arn: string | undefined,
): ProcessingConfiguration | undefined {
  if (!arn) return { Enabled: false };
  return {
    Enabled: true,
    Processors: [
      {
        Type: "Lambda",
        Parameters: [{ ParameterName: "LambdaArn", ParameterValue: arn }],
      },
    ],
  };
}

export const COMPRESSIONS = [
  "UNCOMPRESSED",
  "GZIP",
  "ZIP",
  "Snappy",
  "HADOOP_SNAPPY",
] as const;
