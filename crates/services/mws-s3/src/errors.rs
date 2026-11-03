//! S3 error codes and messages, as S3 words them.

use mws_core::{ErrorValue, ServiceError};

fn err(code: &'static str, status: u16, message: impl Into<String>) -> ServiceError {
    ServiceError::client(code, status, message)
}

fn field(e: ServiceError, name: &str, value: impl Into<String>) -> ServiceError {
    e.with_field(name, ErrorValue::String(value.into()))
}

pub fn no_such_bucket(bucket: &str) -> ServiceError {
    field(err("NoSuchBucket", 404, "The specified bucket does not exist"), "BucketName", bucket)
}

pub fn no_such_key(key: &str) -> ServiceError {
    field(err("NoSuchKey", 404, "The specified key does not exist."), "Key", key)
}

pub fn no_such_version(key: &str, version_id: &str) -> ServiceError {
    let e = field(err("NoSuchVersion", 404, "The specified version does not exist."), "Key", key);
    field(e, "VersionId", version_id)
}

pub fn invalid_version_id(version_id: &str) -> ServiceError {
    invalid_argument("Invalid version id specified", "versionId", version_id)
}

pub fn no_such_upload(upload_id: &str) -> ServiceError {
    field(
        err(
            "NoSuchUpload",
            404,
            "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.",
        ),
        "UploadId",
        upload_id,
    )
}

pub fn bucket_already_exists(bucket: &str) -> ServiceError {
    field(
        err(
            "BucketAlreadyExists",
            409,
            "The requested bucket name is not available. The bucket namespace is shared by all users of the system. Please select a different name and try again.",
        ),
        "BucketName",
        bucket,
    )
}

pub fn bucket_already_owned_by_you(bucket: &str) -> ServiceError {
    field(
        err(
            "BucketAlreadyOwnedByYou",
            409,
            "Your previous request to create the named bucket succeeded and you already own it.",
        ),
        "BucketName",
        bucket,
    )
}

pub fn bucket_not_empty(bucket: &str, versioned: bool) -> ServiceError {
    let msg = if versioned {
        "The bucket you tried to delete is not empty. You must delete all versions in the bucket."
    } else {
        "The bucket you tried to delete is not empty"
    };
    field(err("BucketNotEmpty", 409, msg), "BucketName", bucket)
}

pub fn invalid_bucket_name(bucket: &str) -> ServiceError {
    field(err("InvalidBucketName", 400, "The specified bucket is not valid."), "BucketName", bucket)
}

pub fn access_denied(message: impl Into<String>) -> ServiceError {
    err("AccessDenied", 403, message)
}

pub fn precondition_failed(condition: &str) -> ServiceError {
    field(
        err("PreconditionFailed", 412, "At least one of the pre-conditions you specified did not hold"),
        "Condition",
        condition,
    )
}

pub fn not_modified() -> ServiceError {
    err("NotModified", 304, "Not Modified")
}

pub fn invalid_range(requested: &str, size: i64) -> ServiceError {
    let e = field(err("InvalidRange", 416, "The requested range is not satisfiable"), "RangeRequested", requested);
    field(e, "ActualObjectSize", size.to_string())
}

pub fn bad_digest_md5(expected: &str, calculated: &str) -> ServiceError {
    let e = field(
        err("BadDigest", 400, "The Content-MD5 you specified did not match what we received."),
        "ExpectedDigest",
        expected,
    );
    field(e, "CalculatedDigest", calculated)
}

pub fn invalid_digest(value: &str) -> ServiceError {
    field(err("InvalidDigest", 400, "The Content-MD5 you specified is not valid."), "Content-MD5", value)
}

pub fn bad_checksum(algorithm: &str) -> ServiceError {
    err("BadDigest", 400, format!("The {algorithm} you specified did not match the calculated checksum."))
}

pub fn invalid_checksum(algorithm: &str) -> ServiceError {
    invalid_request(format!("Value for x-amz-checksum-{} header is invalid.", algorithm.to_ascii_lowercase()))
}

pub fn malformed_xml() -> ServiceError {
    err(
        "MalformedXML",
        400,
        "The XML you provided was not well-formed or did not validate against our published schema",
    )
}

pub fn invalid_argument(message: impl Into<String>, name: &str, value: &str) -> ServiceError {
    let e = field(err("InvalidArgument", 400, message), "ArgumentName", name);
    field(e, "ArgumentValue", value)
}

pub fn invalid_request(message: impl Into<String>) -> ServiceError {
    err("InvalidRequest", 400, message)
}

pub fn entity_too_small(size: i64, part: i32, etag: &str) -> ServiceError {
    let e = field(
        err("EntityTooSmall", 400, "Your proposed upload is smaller than the minimum allowed size"),
        "ProposedSize",
        size.to_string(),
    );
    let e = field(e, "MinSizeAllowed", crate::multipart::MIN_PART_SIZE.to_string());
    let e = field(e, "PartNumber", part.to_string());
    field(e, "ETag", etag.trim_matches('"'))
}

pub fn invalid_part(upload_id: &str, part: i32, etag: &str) -> ServiceError {
    let e = field(
        err(
            "InvalidPart",
            400,
            "One or more of the specified parts could not be found.  The part may not have been uploaded, or the specified entity tag may not match the part's entity tag.",
        ),
        "UploadId",
        upload_id,
    );
    let e = field(e, "PartNumber", part.to_string());
    field(e, "ETag", etag)
}

pub fn invalid_part_order(upload_id: &str) -> ServiceError {
    field(
        err(
            "InvalidPartOrder",
            400,
            "The list of parts was not in ascending order. Parts must be ordered by part number.",
        ),
        "UploadId",
        upload_id,
    )
}

pub fn method_not_allowed(method: &str, resource_type: &str) -> ServiceError {
    let e = field(
        err("MethodNotAllowed", 405, "The specified method is not allowed against this resource."),
        "Method",
        method,
    );
    field(e, "ResourceType", resource_type)
}

pub fn key_too_long(size: usize) -> ServiceError {
    let e = field(err("KeyTooLongError", 400, "Your key is too long"), "Size", size.to_string());
    field(e, "MaxSizeAllowed", "1024")
}

pub fn metadata_too_large(size: usize) -> ServiceError {
    let e = field(
        err("MetadataTooLarge", 400, "Your metadata headers exceed the maximum allowed metadata size."),
        "Size",
        size.to_string(),
    );
    field(e, "MaxSizeAllowed", "2048")
}

pub fn entity_too_large(size: i64, max: i64) -> ServiceError {
    let e = field(
        err("EntityTooLarge", 400, "Your proposed upload exceeds the maximum allowed size"),
        "ProposedSize",
        size.to_string(),
    );
    field(e, "MaxSizeAllowed", max.to_string())
}

pub fn not_found_config(code: &'static str, message: &str, bucket: &str) -> ServiceError {
    field(err(code, 404, message), "BucketName", bucket)
}

pub fn no_such_tag_set(bucket: &str) -> ServiceError {
    not_found_config("NoSuchTagSet", "The TagSet does not exist", bucket)
}

pub fn malformed_policy(message: &str) -> ServiceError {
    err("MalformedPolicy", 400, message)
}

pub fn acls_not_supported() -> ServiceError {
    err("AccessControlListNotSupported", 400, "The bucket does not allow ACLs")
}

pub fn invalid_tag(message: &str, key: Option<&str>) -> ServiceError {
    let e = err("InvalidTag", 400, message);
    match key {
        Some(k) => field(e, "TagKey", k),
        None => e,
    }
}

pub fn invalid_storage_class(class: &str) -> ServiceError {
    field(
        err("InvalidStorageClass", 400, "The storage class you specified is not valid"),
        "StorageClassRequested",
        class,
    )
}

pub fn invalid_object_state(storage_class: &str) -> ServiceError {
    field(
        err("InvalidObjectState", 403, "The operation is not valid for the object's storage class"),
        "StorageClass",
        storage_class,
    )
}

pub fn invalid_bucket_state(message: &str) -> ServiceError {
    err("InvalidBucketState", 409, message)
}

pub fn no_such_configuration() -> ServiceError {
    err("NoSuchConfiguration", 404, "The specified configuration does not exist.")
}
