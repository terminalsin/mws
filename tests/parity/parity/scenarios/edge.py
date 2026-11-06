import json

from ..dsl import aws_error, scenario


@scenario("route53", "hosted zone and records")
def _(s):
    s.call("create_hosted_zone", Name="${name}.example.com", CallerReference="${name}", HostedZoneConfig={"Comment": "parity"}, save={"zone": "HostedZone.Id"}, _ignore=["Location"])
    s.call("get_hosted_zone", Id="${zone}")
    s.call("list_hosted_zones_by_name", DNSName="${name}.example.com", MaxItems="1")
    s.call(
        "change_resource_record_sets",
        HostedZoneId="${zone}",
        ChangeBatch={
            "Changes": [
                {
                    "Action": "CREATE",
                    "ResourceRecordSet": {"Name": "www.${name}.example.com", "Type": "A", "TTL": 60, "ResourceRecords": [{"Value": "192.0.2.1"}]},
                },
                {
                    "Action": "CREATE",
                    "ResourceRecordSet": {"Name": "txt.${name}.example.com", "Type": "TXT", "TTL": 300, "ResourceRecords": [{"Value": '"hello parity"'}]},
                },
            ]
        },
        save={"change": "ChangeInfo.Id"},
    )
    s.call("get_change", Id="${change}")
    s.call("list_resource_record_sets", HostedZoneId="${zone}")
    s.call(
        "change_resource_record_sets",
        HostedZoneId="${zone}",
        ChangeBatch={
            "Changes": [
                {
                    "Action": "CREATE",
                    "ResourceRecordSet": {"Name": "www.${name}.example.com", "Type": "A", "TTL": 60, "ResourceRecords": [{"Value": "192.0.2.1"}]},
                }
            ]
        },
        expect=aws_error("InvalidChangeBatch", 400),
    )
    s.call("change_tags_for_resource", ResourceType="hostedzone", ResourceId="${zone}", AddTags=[{"Key": "team", "Value": "parity"}])
    s.call("list_tags_for_resource", ResourceType="hostedzone", ResourceId="${zone}")
    s.call("get_hosted_zone", Id="Z0000000000000000000", expect=aws_error("NoSuchHostedZone", 404))
    s.call("delete_hosted_zone", Id="${zone}", expect=aws_error("HostedZoneNotEmpty", 400))
    s.cleanup(
        "change_resource_record_sets",
        HostedZoneId="${zone}",
        ChangeBatch={
            "Changes": [
                {"Action": "DELETE", "ResourceRecordSet": {"Name": "www.${name}.example.com", "Type": "A", "TTL": 60, "ResourceRecords": [{"Value": "192.0.2.1"}]}},
                {"Action": "DELETE", "ResourceRecordSet": {"Name": "txt.${name}.example.com", "Type": "TXT", "TTL": 300, "ResourceRecords": [{"Value": '"hello parity"'}]}},
            ]
        },
    )
    s.cleanup("delete_hosted_zone", Id="${zone}")


@scenario("route53", "health checks")
def _(s):
    s.call(
        "create_health_check",
        CallerReference="${name}",
        HealthCheckConfig={"Type": "HTTP", "FullyQualifiedDomainName": "example.com", "Port": 80, "ResourcePath": "/", "RequestInterval": 30, "FailureThreshold": 3},
        save={"hc": "HealthCheck.Id"},
        _ignore=["Location"],
    )
    s.call("get_health_check", HealthCheckId="${hc}")
    s.call("get_health_check_count", _shape_only=True)
    s.cleanup("delete_health_check", HealthCheckId="${hc}")


@scenario("acm", "certificates")
def _(s):
    s.call(
        "request_certificate",
        DomainName="${name}.example.com",
        ValidationMethod="DNS",
        SubjectAlternativeNames=["www.${name}.example.com"],
        Tags=[{"Key": "team", "Value": "parity"}],
        save={"cert": "CertificateArn"},
    )
    s.call("describe_certificate", CertificateArn="${cert}", _until="Certificate.DomainValidationOptions[0].ResourceRecord", _wait=15)
    s.call("list_certificates", _shape_only=True)
    s.call("list_tags_for_certificate", CertificateArn="${cert}")
    s.call("add_tags_to_certificate", CertificateArn="${cert}", Tags=[{"Key": "env", "Value": "test"}])
    s.call("get_certificate", CertificateArn="${cert}", expect=aws_error("RequestInProgressException", 400))
    s.call(
        "describe_certificate",
        CertificateArn="arn:aws:acm:${region}:${account}:certificate/00000000-0000-0000-0000-000000000000",
        expect=aws_error("ResourceNotFoundException", 400),
    )
    s.call("get_account_configuration", _shape_only=True)
    s.cleanup("delete_certificate", CertificateArn="${cert}")


@scenario("ses", "identities and sending")
def _(s):
    s.call("verify_email_identity", EmailAddress="${name}@example.com")
    s.call("verify_domain_identity", Domain="${name}.example.com", _ignore=["VerificationToken"])
    s.call("list_identities", IdentityType="EmailAddress", _shape_only=True)
    s.call("get_identity_verification_attributes", Identities=["${name}@example.com", "${name}.example.com"], _ignore=["VerificationAttributes.*"])
    s.call(
        "send_email",
        Source="${name}@example.com",
        Destination={"ToAddresses": ["someone@example.com"]},
        Message={"Subject": {"Data": "hi"}, "Body": {"Text": {"Data": "hello parity"}}},
        _note="sandbox accounts may require verified identities",
    )
    s.call("send_raw_email", RawMessage={"Data": "From: ${name}@example.com\r\nTo: a@example.com\r\nSubject: raw\r\n\r\nbody"})
    s.call("get_send_quota", _shape_only=True)
    s.call("create_template", Template={"TemplateName": "${name}", "SubjectPart": "Hi {{n}}", "TextPart": "Hello {{n}}"})
    s.call("get_template", TemplateName="${name}")
    s.call("get_template", TemplateName="${name}-none", expect=aws_error("TemplateDoesNotExist", 400))
    s.call("create_configuration_set", ConfigurationSet={"Name": "${name}"})
    s.call("describe_configuration_set", ConfigurationSetName="${name}")
    s.cleanup("delete_configuration_set", ConfigurationSetName="${name}")
    s.cleanup("delete_template", TemplateName="${name}")
    s.cleanup("delete_identity", Identity="${name}@example.com")
    s.cleanup("delete_identity", Identity="${name}.example.com")


@scenario("sesv2", "email identities")
def _(s):
    s.call("create_email_identity", EmailIdentity="${name}@example.com")
    s.call("get_email_identity", EmailIdentity="${name}@example.com")
    s.call("list_email_identities", _shape_only=True)
    s.call(
        "send_email",
        FromEmailAddress="${name}@example.com",
        Destination={"ToAddresses": ["a@example.com"]},
        Content={"Simple": {"Subject": {"Data": "hi"}, "Body": {"Text": {"Data": "hello"}}}},
    )
    s.call("get_account", _shape_only=True)
    s.call("get_email_identity", EmailIdentity="${name}-none@example.com", expect=aws_error("NotFoundException", 404))
    s.cleanup("delete_email_identity", EmailIdentity="${name}@example.com")


TEMPLATE = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"Suffix": {"Type": "String", "Default": "x"}},
        "Resources": {
            "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": {"Fn::Sub": "${AWS::StackName}-${Suffix}"}}},
            "Topic": {"Type": "AWS::SNS::Topic"},
        },
        "Outputs": {"QueueUrl": {"Value": {"Ref": "Queue"}}, "TopicArn": {"Value": {"Ref": "Topic"}}},
    }
)


@scenario("cloudformation", "stack lifecycle", needs=("sqs", "sns"))
def _(s):
    s.call("validate_template", TemplateBody=TEMPLATE)
    s.call("create_stack", StackName="${name}", TemplateBody=TEMPLATE, Parameters=[{"ParameterKey": "Suffix", "ParameterValue": "q"}], save={"stack": "StackId"})
    s.call("describe_stacks", StackName="${name}", _until="Stacks[0].StackStatus == 'CREATE_COMPLETE'", _wait=60)
    s.call("describe_stack_resources", StackName="${name}")
    s.call("list_stack_resources", StackName="${name}")
    s.call("get_template", StackName="${name}")
    s.call("describe_stack_events", StackName="${name}", _shape_only=True)
    s.call("get_template_summary", StackName="${name}")
    s.call("create_stack", StackName="${name}", TemplateBody=TEMPLATE, expect=aws_error("AlreadyExistsException", 400))
    s.call("describe_stacks", StackName="${name}-none", expect=aws_error("ValidationError", 400, message="does not exist"))
    s.call("validate_template", TemplateBody="{not a template", expect=aws_error("ValidationError", 400))
    s.call("delete_stack", StackName="${name}")
    s.call("describe_stacks", StackName="${stack}", _until="Stacks[0].StackStatus == 'DELETE_COMPLETE'", _wait=60)
