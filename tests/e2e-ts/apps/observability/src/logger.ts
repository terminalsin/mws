// A small structured logger that ships JSON lines to CloudWatch Logs, the
// way a container log driver or Lambda's runtime would.
import {
  CloudWatchLogsClient,
  CreateLogStreamCommand,
  PutLogEventsCommand,
  ResourceAlreadyExistsException,
} from "@aws-sdk/client-cloudwatch-logs";

export type Level = "DEBUG" | "INFO" | "WARN" | "ERROR";

export class CloudWatchLogger {
  private buffer: { timestamp: number; message: string }[] = [];
  private streamReady?: Promise<void>;

  constructor(
    private readonly client: CloudWatchLogsClient,
    readonly logGroupName: string,
    readonly logStreamName: string,
    private readonly fields: Record<string, unknown> = {},
  ) {}

  log(level: Level, message: string, fields: Record<string, unknown> = {}): void {
    const timestamp = Date.now();
    this.buffer.push({
      timestamp,
      message: JSON.stringify({ time: new Date(timestamp).toISOString(), level, message, ...this.fields, ...fields }),
    });
  }

  info(message: string, fields?: Record<string, unknown>) {
    this.log("INFO", message, fields);
  }

  error(message: string, fields?: Record<string, unknown>) {
    this.log("ERROR", message, fields);
  }

  /** Sends everything buffered so far in one PutLogEvents call. */
  async flush(): Promise<void> {
    if (this.buffer.length === 0) return;
    this.streamReady ??= this.client
      .send(new CreateLogStreamCommand({ logGroupName: this.logGroupName, logStreamName: this.logStreamName }))
      .then(
        () => undefined,
        (err) => {
          if (!(err instanceof ResourceAlreadyExistsException)) throw err;
        },
      );
    await this.streamReady;
    const logEvents = this.buffer.splice(0);
    const { rejectedLogEventsInfo } = await this.client.send(
      new PutLogEventsCommand({ logGroupName: this.logGroupName, logStreamName: this.logStreamName, logEvents }),
    );
    if (rejectedLogEventsInfo) throw new Error(`log events rejected: ${JSON.stringify(rejectedLogEventsInfo)}`);
  }
}
