# upload-pipeline

A document service: clients upload files straight to S3 with presigned URLs,
and a background worker indexes every new upload.

```
browser --presigned PUT--> S3 bucket (uploads/...)
                              | s3:ObjectCreated:*, prefix uploads/
                              v
                           SNS topic --raw--> SQS "indexer" --> worker --> S3 index/....json
                              |                    | after 2 failed receives
                              |                    v
                              |                 SQS "indexer-dlq"
                              +--envelope--> SQS "audit"
```

- [`src/infrastructure.ts`](src/infrastructure.ts) creates the bucket, topic
  and queues with the resource policies each hop needs.
- [`src/uploads.ts`](src/uploads.ts) issues presigned upload and download
  URLs. Note the presigning client with `requestChecksumCalculation:
  "WHEN_REQUIRED"`: by default SDK v3 puts the CRC32 of an empty body in
  presigned `PutObject` URLs, and S3 then rejects the real upload.
- [`src/worker.ts`](src/worker.ts) long-polls the queue, skips S3's
  `s3:TestEvent`, decodes keys from the event and leaves failed messages for
  the redrive policy.

The tests upload with plain `fetch`, check that a mismatched `Content-Type`
breaks the signature, that the prefix filter holds, that the audit queue gets
SNS envelopes, and that an unindexable file ends up in the dead-letter queue.
