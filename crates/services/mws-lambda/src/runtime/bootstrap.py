"""MWS's Python runtime client: the Lambda Runtime API loop around a handler.

It speaks the same Runtime API (AWS_LAMBDA_RUNTIME_API) as the AWS Python
runtime interface client, and reports errors in the same shapes.
"""

import importlib
import json
import logging
import os
import sys
import time
import traceback
import urllib.request

API = "http://" + os.environ["AWS_LAMBDA_RUNTIME_API"] + "/2018-06-01/runtime"
_request_id = ""


def _post(path, body, headers=None):
    req = urllib.request.Request(API + path, data=body, method="POST", headers=headers or {})
    with urllib.request.urlopen(req) as r:
        r.read()


def _error(e, error_type=None):
    frames = traceback.extract_tb(e.__traceback__)
    return {
        "errorMessage": str(e),
        "errorType": error_type or type(e).__name__,
        "requestId": _request_id,
        "stackTrace": traceback.format_list(frames),
    }


def _init_error(error_type, message):
    body = json.dumps({"errorMessage": message, "errorType": error_type, "requestId": "", "stackTrace": []})
    print(f"[ERROR] {error_type}: {message}", file=sys.stderr, flush=True)
    _post("/init/error", body.encode(), {"Lambda-Runtime-Function-Error-Type": error_type})
    sys.exit(1)


class _Formatter(logging.Formatter):
    def format(self, record):
        record.aws_request_id = _request_id
        return super().format(record)


def _setup_logging():
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        _Formatter("[%(levelname)s]\t%(asctime)s.%(msecs)03dZ\t%(aws_request_id)s\t%(message)s\n", "%Y-%m-%dT%H:%M:%S")
    )
    logging.Formatter.converter = time.gmtime
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(os.environ.get("AWS_LAMBDA_LOG_LEVEL", "WARNING").upper())


class LambdaContext:
    def __init__(self, request_id, deadline_ms, invoked_arn, client_context, identity):
        self.aws_request_id = request_id
        self.function_name = os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
        self.function_version = os.environ.get("AWS_LAMBDA_FUNCTION_VERSION")
        self.invoked_function_arn = invoked_arn
        self.memory_limit_in_mb = os.environ.get("AWS_LAMBDA_FUNCTION_MEMORY_SIZE")
        self.log_group_name = os.environ.get("AWS_LAMBDA_LOG_GROUP_NAME")
        self.log_stream_name = os.environ.get("AWS_LAMBDA_LOG_STREAM_NAME")
        self.client_context = client_context
        self.identity = identity
        self._deadline_ms = deadline_ms

    def get_remaining_time_in_millis(self):
        return max(0, int(self._deadline_ms - time.time() * 1000))


def _load_handler():
    handler = os.environ.get("_HANDLER", "")
    module_name, _, func_name = handler.rpartition(".")
    if not module_name or not func_name:
        _init_error("Runtime.MalformedHandlerName", f"Bad handler '{handler}': not enough values to unpack (expected 2, got 1)")
    task_root = os.environ.get("LAMBDA_TASK_ROOT", os.getcwd())
    if task_root not in sys.path:
        sys.path.insert(0, task_root)
    try:
        module = importlib.import_module(module_name.replace("/", "."))
    except ImportError as e:
        _init_error("Runtime.ImportModuleError", f"Unable to import module '{module_name}': {e}")
    except SyntaxError as e:
        _init_error("Runtime.UserCodeSyntaxError", f"Syntax error in module '{module_name}': {e}")
    except Exception as e:  # noqa: BLE001 - reported to Lambda like the AWS client does
        _init_error(type(e).__name__, str(e))
    fn = getattr(module, func_name, None)
    if fn is None:
        _init_error("Runtime.HandlerNotFound", f"Handler '{func_name}' missing on module '{module_name}'")
    return fn


def main():
    global _request_id
    _setup_logging()
    fn = _load_handler()
    while True:
        with urllib.request.urlopen(API + "/invocation/next") as r:
            headers = r.headers
            body = r.read()
        _request_id = headers.get("Lambda-Runtime-Aws-Request-Id", "")
        os.environ["_X_AMZN_TRACE_ID"] = headers.get("Lambda-Runtime-Trace-Id", "")
        client_context = headers.get("Lambda-Runtime-Client-Context")
        identity = headers.get("Lambda-Runtime-Cognito-Identity")
        context = LambdaContext(
            _request_id,
            int(headers.get("Lambda-Runtime-Deadline-Ms", "0")),
            headers.get("Lambda-Runtime-Invoked-Function-Arn"),
            json.loads(client_context) if client_context else None,
            json.loads(identity) if identity else None,
        )
        try:
            event = json.loads(body) if body else None
            result = fn(event, context)
        except Exception as e:  # noqa: BLE001
            sys.stdout.flush()
            payload = _error(e)
            print(f"[ERROR] {payload['errorType']}: {payload['errorMessage']}", file=sys.stderr, flush=True)
            _post(
                f"/invocation/{_request_id}/error",
                json.dumps(payload).encode(),
                {"Lambda-Runtime-Function-Error-Type": "Unhandled", "Content-Type": "application/json"},
            )
            continue
        try:
            out = json.dumps(result).encode()
        except Exception as e:  # noqa: BLE001
            payload = _error(e, "Runtime.MarshalError")
            payload["errorMessage"] = f"Unable to marshal response: {e}"
            _post(
                f"/invocation/{_request_id}/error",
                json.dumps(payload).encode(),
                {"Lambda-Runtime-Function-Error-Type": "Runtime.MarshalError"},
            )
            continue
        sys.stdout.flush()
        sys.stderr.flush()
        _post(f"/invocation/{_request_id}/response", out)


if __name__ == "__main__":
    main()
