// Custom application metrics, published in batches with PutMetricData.
import { CloudWatchClient, PutMetricDataCommand, StandardUnit, type MetricDatum } from "@aws-sdk/client-cloudwatch";

export class Metrics {
  private pending: MetricDatum[] = [];

  constructor(
    private readonly client: CloudWatchClient,
    readonly namespace: string,
    private readonly dimensions: Record<string, string>,
  ) {}

  timing(name: string, milliseconds: number): void {
    this.pending.push({
      MetricName: name,
      Unit: StandardUnit.Milliseconds,
      Value: milliseconds,
      Timestamp: new Date(),
      Dimensions: Object.entries(this.dimensions).map(([Name, Value]) => ({ Name, Value })),
    });
  }

  async flush(): Promise<void> {
    // PutMetricData takes up to 1000 data points per call.
    while (this.pending.length > 0) {
      await this.client.send(
        new PutMetricDataCommand({ Namespace: this.namespace, MetricData: this.pending.splice(0, 1000) }),
      );
    }
  }
}
