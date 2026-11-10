//! CloudFormation stacks of Amazon SES resources through the official Rust
//! SDK: identities, configuration sets and event destinations, templates,
//! contact lists, dedicated IP pools and receipt rule sets, rules and
//! filters, checked through the SES v1 and v2 SDKs, updated in place and
//! removed with the stack.

use std::time::Duration;

use aws_sdk_cloudformation::types::{Parameter, StackStatus};
use aws_sdk_cloudformation::Client;
use mws_e2e::Mws;

fn param(k: &str, v: &str) -> Parameter {
    Parameter::builder().parameter_key(k).parameter_value(v).build()
}

async fn settle(cfn: &Client, stack: &str) -> aws_sdk_cloudformation::types::Stack {
    for _ in 0..600 {
        let out = cfn.describe_stacks().stack_name(stack).send().await.unwrap();
        let s = out.stacks()[0].clone();
        if !s.stack_status().unwrap().as_str().ends_with("_IN_PROGRESS") {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("stack {stack} did not settle");
}

fn output(s: &aws_sdk_cloudformation::types::Stack, key: &str) -> String {
    s.outputs()
        .iter()
        .find(|o| o.output_key() == Some(key))
        .and_then(|o| o.output_value())
        .unwrap_or_else(|| panic!("no output {key}"))
        .to_string()
}

async fn failures(cfn: &Client, stack: &str) -> Vec<String> {
    let events = cfn.describe_stack_events().stack_name(stack).send().await.unwrap();
    events
        .stack_events()
        .iter()
        .filter(|e| e.resource_status().is_some_and(|s| s.as_str().ends_with("FAILED")))
        .map(|e| {
            format!(
                "{}: {}",
                e.logical_resource_id().unwrap_or_default(),
                e.resource_status_reason().unwrap_or_default()
            )
        })
        .collect()
}

const TEMPLATE: &str = r#"
Parameters:
  Tls: {Type: String, Default: REQUIRE}
  Subject: {Type: String, Default: "Hi {{name}}"}
  RuleEnabled: {Type: String, Default: "true"}
  ListDescription: {Type: String, Default: Weekly news}
Resources:
  Topic:
    Type: AWS::SNS::Topic
  ConfigSet:
    Type: AWS::SES::ConfigurationSet
    Properties:
      Name: marketing
      DeliveryOptions: {TlsPolicy: !Ref Tls}
      ReputationOptions: {ReputationMetricsEnabled: true}
      SendingOptions: {SendingEnabled: "true"}
      SuppressionOptions: {SuppressedReasons: [BOUNCE]}
      Tags: [{Key: team, Value: growth}]
  Destination:
    Type: AWS::SES::ConfigurationSetEventDestination
    Properties:
      ConfigurationSetName: !Ref ConfigSet
      EventDestination:
        Name: to-sns
        Enabled: true
        MatchingEventTypes: [send, bounce]
        SnsDestination: {TopicARN: !Ref Topic}
  Identity:
    Type: AWS::SES::EmailIdentity
    Properties:
      EmailIdentity: example.com
      ConfigurationSetAttributes: {ConfigurationSetName: !Ref ConfigSet}
      FeedbackAttributes: {EmailForwardingEnabled: false}
      MailFromAttributes: {MailFromDomain: mail.example.com, BehaviorOnMxFailure: USE_DEFAULT_VALUE}
  Welcome:
    Type: AWS::SES::Template
    Properties:
      Template:
        TemplateName: welcome
        SubjectPart: !Ref Subject
        TextPart: "Hello {{name}}"
        HtmlPart: "<p>Hello {{name}}</p>"
  Newsletter:
    Type: AWS::SES::ContactList
    Properties:
      ContactListName: newsletter
      Description: !Ref ListDescription
      Topics: [{TopicName: weekly, DisplayName: Weekly, DefaultSubscriptionStatus: OPT_OUT}]
  Pool:
    Type: AWS::SES::DedicatedIpPool
    Properties: {PoolName: transactional, ScalingMode: STANDARD}
  RuleSet:
    Type: AWS::SES::ReceiptRuleSet
    Properties: {RuleSetName: inbound}
  Rule:
    Type: AWS::SES::ReceiptRule
    Properties:
      RuleSetName: !Ref RuleSet
      Rule:
        Name: notify
        Enabled: !Ref RuleEnabled
        ScanEnabled: true
        Recipients: [inbox@example.com]
        Actions: [{SNSAction: {TopicArn: !Ref Topic, Encoding: UTF-8}}]
  Filter:
    Type: AWS::SES::ReceiptFilter
    Properties:
      Filter: {Name: block-private, IpFilter: {Policy: Block, Cidr: 10.0.0.0/8}}
  Unnamed:
    Type: AWS::SES::ConfigurationSet
Outputs:
  DkimName: {Value: !GetAtt Identity.DkimDNSTokenName1}
  DkimValue: {Value: !GetAtt Identity.DkimDNSTokenValue1}
  TemplateId: {Value: !GetAtt Welcome.Id}
  DestinationId: {Value: !GetAtt Destination.Id}
  Unnamed: {Value: !Ref Unnamed}
"#;

#[tokio::test]
async fn ses_resources_deploy_update_and_delete() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let cfn = Client::new(&config);
    let v2 = aws_sdk_sesv2::Client::new(&config);
    let v1 = aws_sdk_ses::Client::new(&config);

    cfn.create_stack().stack_name("mail").template_body(TEMPLATE).send().await.unwrap();
    let stack = settle(&cfn, "mail").await;
    assert_eq!(stack.stack_status(), Some(&StackStatus::CreateComplete), "{:?}", failures(&cfn, "mail").await);

    // Configuration set and its event destination.
    let cs = v2.get_configuration_set().configuration_set_name("marketing").send().await.unwrap();
    assert_eq!(cs.delivery_options().unwrap().tls_policy().unwrap().as_str(), "REQUIRE");
    assert!(cs.reputation_options().unwrap().reputation_metrics_enabled());
    assert!(cs.sending_options().unwrap().sending_enabled());
    assert_eq!(cs.suppression_options().unwrap().suppressed_reasons()[0].as_str(), "BOUNCE");
    assert!(cs.tags().iter().any(|t| t.key() == "team" && t.value() == "growth"));
    let dests = v2.get_configuration_set_event_destinations().configuration_set_name("marketing").send().await.unwrap();
    let d = &dests.event_destinations()[0];
    assert_eq!(d.name(), "to-sns");
    assert_eq!(output(&stack, "DestinationId"), "to-sns");
    let topic = cfn
        .describe_stack_resource()
        .stack_name("mail")
        .logical_resource_id("Topic")
        .send()
        .await
        .unwrap()
        .stack_resource_detail()
        .unwrap()
        .physical_resource_id()
        .unwrap()
        .to_string();
    assert_eq!(d.sns_destination().unwrap().topic_arn(), topic);
    assert_eq!(d.matching_event_types().len(), 2);
    let unnamed = output(&stack, "Unnamed");
    assert!(unnamed.starts_with("mail-Unnamed-"), "{unnamed}");
    v2.get_configuration_set().configuration_set_name(&unnamed).send().await.unwrap();

    // Email identity with its attributes and DKIM tokens.
    let id = v2.get_email_identity().email_identity("example.com").send().await.unwrap();
    assert_eq!(id.configuration_set_name(), Some("marketing"));
    assert!(!id.feedback_forwarding_status());
    assert_eq!(id.mail_from_attributes().unwrap().mail_from_domain(), "mail.example.com");
    let token = id.dkim_attributes().unwrap().tokens()[0].clone();
    assert_eq!(output(&stack, "DkimName"), format!("{token}._domainkey.example.com"));
    assert_eq!(output(&stack, "DkimValue"), format!("{token}.dkim.amazonses.com"));

    // Template, contact list, dedicated IP pool.
    assert_eq!(output(&stack, "TemplateId"), "welcome");
    let t = v1.get_template().template_name("welcome").send().await.unwrap();
    assert_eq!(t.template().unwrap().subject_part(), Some("Hi {{name}}"));
    let cl = v2.get_contact_list().contact_list_name("newsletter").send().await.unwrap();
    assert_eq!(cl.description(), Some("Weekly news"));
    assert_eq!(cl.topics()[0].topic_name(), "weekly");
    let pool = v2.get_dedicated_ip_pool().pool_name("transactional").send().await.unwrap();
    assert_eq!(pool.dedicated_ip_pool().unwrap().scaling_mode().as_str(), "STANDARD");

    // Receipt rule set, rule and filter.
    let rs = v1.describe_receipt_rule_set().rule_set_name("inbound").send().await.unwrap();
    let rule = &rs.rules()[0];
    assert_eq!(rule.name(), "notify");
    assert!(rule.enabled());
    assert!(rule.scan_enabled());
    assert_eq!(rule.actions()[0].sns_action().unwrap().topic_arn(), topic);
    let filters = v1.list_receipt_filters().send().await.unwrap();
    let f = filters.filters().iter().find(|f| f.name() == "block-private").unwrap();
    assert_eq!(f.ip_filter().unwrap().cidr(), "10.0.0.0/8");

    // Update in place.
    cfn.update_stack()
        .stack_name("mail")
        .template_body(TEMPLATE)
        .parameters(param("Tls", "OPTIONAL"))
        .parameters(param("Subject", "Welcome {{name}}"))
        .parameters(param("RuleEnabled", "false"))
        .parameters(param("ListDescription", "Monthly news"))
        .send()
        .await
        .unwrap();
    let stack = settle(&cfn, "mail").await;
    assert_eq!(stack.stack_status(), Some(&StackStatus::UpdateComplete), "{:?}", failures(&cfn, "mail").await);
    assert_eq!(output(&stack, "Unnamed"), unnamed);
    let cs = v2.get_configuration_set().configuration_set_name("marketing").send().await.unwrap();
    assert_eq!(cs.delivery_options().unwrap().tls_policy().unwrap().as_str(), "OPTIONAL");
    let t = v1.get_template().template_name("welcome").send().await.unwrap();
    assert_eq!(t.template().unwrap().subject_part(), Some("Welcome {{name}}"));
    let rs = v1.describe_receipt_rule_set().rule_set_name("inbound").send().await.unwrap();
    assert!(!rs.rules()[0].enabled());
    let cl = v2.get_contact_list().contact_list_name("newsletter").send().await.unwrap();
    assert_eq!(cl.description(), Some("Monthly news"));

    // Delete.
    cfn.delete_stack().stack_name("mail").send().await.unwrap();
    for _ in 0..600 {
        match cfn.describe_stacks().stack_name("mail").send().await {
            Err(_) => break,
            Ok(o) if o.stacks()[0].stack_status() == Some(&StackStatus::DeleteComplete) => break,
            Ok(o) if o.stacks()[0].stack_status() == Some(&StackStatus::DeleteFailed) => {
                panic!("delete failed: {:?}", failures(&cfn, "mail").await)
            }
            Ok(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    assert!(v2.get_configuration_set().configuration_set_name("marketing").send().await.is_err());
    assert!(v2.get_email_identity().email_identity("example.com").send().await.is_err());
    assert!(v1.get_template().template_name("welcome").send().await.is_err());
    assert!(v2.get_contact_list().contact_list_name("newsletter").send().await.is_err());
    assert!(v2.get_dedicated_ip_pool().pool_name("transactional").send().await.is_err());
    assert!(v1.describe_receipt_rule_set().rule_set_name("inbound").send().await.is_err());
    let filters = v1.list_receipt_filters().send().await.unwrap();
    assert!(filters.filters().iter().all(|f| f.name() != "block-private"));
    mws.stop().await;
}
