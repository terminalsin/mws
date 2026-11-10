# order-events

Event-driven order processing on a custom EventBridge bus.

```
checkout --OrderPlaced--> bus "orders"
  rule all-orders         --InputTransformer--> SQS "order-audit"
  rule high-value-orders  (detail.total >= 500) --> Lambda "fraud-check"
                                                        | PutEvents FraudCheckCompleted
  rule fraud-results      <-----------------------------+
                          --> SQS "fraud-results"
```

- [`src/functions/fraud-check.ts`](src/functions/fraud-check.ts) is the Lambda
  function. [`src/bundle.ts`](src/bundle.ts) bundles it with esbuild (SDK
  included) and zips it in memory. MWS runs it in the Lambda Node.js base image
  (or on a local `node` without Docker) with the execution role's credentials and `AWS_ENDPOINT_URL` set, so the SDK inside
  the function talks to MWS too.
- [`src/infrastructure.ts`](src/infrastructure.ts) creates the execution role,
  the function, the rules, `lambda:AddPermission` for EventBridge, and queue
  policies scoped to each rule's ARN.

The tests check the pattern with `TestEventPattern`, follow an order through
the audit queue, follow a high-value order through the function and back
onto the bus, find the function's output in CloudWatch Logs, and invoke the
function directly (including an unhandled error).
