import type { DeliveryStreamDescription } from "@aws-sdk/client-firehose";

/** Where a Firehose stream delivers, as a kind and a short target. */
export function destinationOf(s: DeliveryStreamDescription) {
  const d = s.Destinations?.[0];
  if (d?.ExtendedS3DestinationDescription || d?.S3DestinationDescription) {
    const x = d.ExtendedS3DestinationDescription ?? d.S3DestinationDescription!;
    return { kind: "S3", icon: "resource/AmazonSimpleStorageServiceBucket", target: `s3://${x.BucketARN?.split(":::").pop()}/${x.Prefix ?? ""}`, href: `/storage/s3/${encodeURIComponent(x.BucketARN?.split(":::").pop() ?? "")}` };
  }
  if (d?.HttpEndpointDestinationDescription) return { kind: "HTTP", icon: "resource/Internet", target: d.HttpEndpointDestinationDescription.EndpointConfiguration?.Url ?? "", href: undefined };
  if (d?.RedshiftDestinationDescription) return { kind: "Redshift", icon: "service/AmazonRedshift", target: d.RedshiftDestinationDescription.ClusterJDBCURL ?? "", href: undefined };
  if (d?.AmazonopensearchserviceDestinationDescription || d?.ElasticsearchDestinationDescription) return { kind: "OpenSearch", icon: "service/AmazonOpenSearchService", target: "", href: undefined };
  if (d?.SplunkDestinationDescription) return { kind: "Splunk", icon: "resource/Internet", target: d.SplunkDestinationDescription.HECEndpoint ?? "", href: undefined };
  return { kind: "Other", icon: "service/AmazonDataFirehose", target: "", href: undefined };
}
