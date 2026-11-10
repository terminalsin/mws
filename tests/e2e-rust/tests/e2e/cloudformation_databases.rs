//! CloudFormation stacks with RDS and ElastiCache resources (metadata
//! backends): instances and clusters that wait for `available`, their
//! endpoints through `Fn::GetAtt`, in-place updates and snapshots on delete.

use std::time::Duration;

use aws_sdk_cloudformation::types::{Output, Parameter, StackStatus};
use aws_sdk_cloudformation::Client;
use mws_e2e::Mws;

const TEMPLATE: &str = r#"
Parameters:
  Retention: {Type: Number, Default: 7}
  Workers: {Type: String, Default: "4"}
  Description: {Type: String, Default: sessions}
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties: {CidrBlock: 10.40.0.0/16}
  SubnetA:
    Type: AWS::EC2::Subnet
    Properties: {VpcId: !Ref Vpc, CidrBlock: 10.40.1.0/24, AvailabilityZone: us-east-1a}
  SubnetB:
    Type: AWS::EC2::Subnet
    Properties: {VpcId: !Ref Vpc, CidrBlock: 10.40.2.0/24, AvailabilityZone: us-east-1b}
  DbSubnets:
    Type: AWS::RDS::DBSubnetGroup
    Properties:
      DBSubnetGroupDescription: database subnets
      SubnetIds: [!Ref SubnetA, !Ref SubnetB]
  DbParams:
    Type: AWS::RDS::DBParameterGroup
    Properties:
      Family: postgres16
      Description: app parameters
      Parameters:
        log_min_duration_statement: "1000"
        autovacuum_max_workers: !Ref Workers
  ClusterParams:
    Type: AWS::RDS::DBClusterParameterGroup
    Properties:
      Family: aurora-postgresql16
      Description: cluster parameters
      Parameters: {log_connections: "1"}
  Database:
    Type: AWS::RDS::DBInstance
    DeletionPolicy: Snapshot
    Properties:
      Engine: postgres
      EngineVersion: "16"
      DBInstanceClass: db.t3.micro
      AllocatedStorage: "20"
      MasterUsername: app
      MasterUserPassword: correct-horse-battery
      DBName: app
      DBSubnetGroupName: !Ref DbSubnets
      DBParameterGroupName: !Ref DbParams
      BackupRetentionPeriod: !Ref Retention
      Tags: [{Key: tier, Value: data}]
  Aurora:
    Type: AWS::RDS::DBCluster
    DeletionPolicy: Delete
    Properties:
      Engine: aurora-postgresql
      MasterUsername: app
      MasterUserPassword: correct-horse-battery
      DBSubnetGroupName: !Ref DbSubnets
      DBClusterParameterGroupName: !Ref ClusterParams
  CacheSubnets:
    Type: AWS::ElastiCache::SubnetGroup
    Properties:
      Description: cache subnets
      SubnetIds: [!Ref SubnetA, !Ref SubnetB]
  CacheParams:
    Type: AWS::ElastiCache::ParameterGroup
    Properties:
      CacheParameterGroupFamily: redis7
      Description: cache parameters
      Properties: {maxmemory-policy: allkeys-lru}
  Sessions:
    Type: AWS::ElastiCache::ReplicationGroup
    Properties:
      ReplicationGroupDescription: !Ref Description
      Engine: redis
      CacheNodeType: cache.t3.micro
      NumCacheClusters: 2
      AutomaticFailoverEnabled: true
      CacheSubnetGroupName: !Ref CacheSubnets
      CacheParameterGroupName: !Ref CacheParams
  Memcached:
    Type: AWS::ElastiCache::CacheCluster
    Properties:
      Engine: memcached
      CacheNodeType: cache.t3.micro
      NumCacheNodes: 1
      CacheSubnetGroupName: !Ref CacheSubnets
Outputs:
  DbId: {Value: !Ref Database}
  DbAddress: {Value: !GetAtt Database.Endpoint.Address}
  DbPort: {Value: !GetAtt Database.Endpoint.Port}
  DbArn: {Value: !GetAtt Database.DBInstanceArn}
  ClusterId: {Value: !Ref Aurora}
  ClusterAddress: {Value: !GetAtt Aurora.Endpoint.Address}
  ClusterReader: {Value: !GetAtt Aurora.ReadEndpoint.Address}
  ClusterArn: {Value: !GetAtt Aurora.DBClusterArn}
  SessionsId: {Value: !Ref Sessions}
  SessionsPrimary: {Value: !GetAtt Sessions.PrimaryEndPoint.Address}
  SessionsReaders: {Value: !GetAtt Sessions.ReadEndPoint.Addresses}
  MemcachedId: {Value: !Ref Memcached}
  MemcachedEndpoint: {Value: !GetAtt Memcached.ConfigurationEndpoint.Address}
  CacheParamsName: {Value: !Ref CacheParams}
"#;

fn param(k: &str, v: &str) -> Parameter {
    Parameter::builder().parameter_key(k).parameter_value(v).build()
}

fn output(outputs: &[Output], key: &str) -> String {
    outputs
        .iter()
        .find(|o| o.output_key() == Some(key))
        .and_then(|o| o.output_value())
        .unwrap_or_else(|| panic!("no output {key}"))
        .to_string()
}

async fn settle(cfn: &Client, stack: &str) -> aws_sdk_cloudformation::types::Stack {
    for _ in 0..1200 {
        let out = cfn.describe_stacks().stack_name(stack).send().await.unwrap();
        let s = out.stacks()[0].clone();
        if !s.stack_status().unwrap().as_str().ends_with("_IN_PROGRESS") {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("stack {stack} did not settle");
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

#[test]
fn databases_and_caches_deploy_update_and_snapshot_on_delete() {
    super::rds::run(body());
}

async fn body() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let cfn = Client::new(&config);
    let rds = aws_sdk_rds::Client::new(&config);
    let ec = aws_sdk_elasticache::Client::new(&config);

    cfn.create_stack().stack_name("data").template_body(TEMPLATE).send().await.unwrap();
    let stack = settle(&cfn, "data").await;
    assert_eq!(stack.stack_status(), Some(&StackStatus::CreateComplete), "{:?}", failures(&cfn, "data").await);
    let outs = stack.outputs().to_vec();

    // The instance is available, and the outputs are its endpoint.
    let db_id = output(&outs, "DbId");
    assert!(db_id.starts_with("data-database-"), "{db_id}");
    let d = rds.describe_db_instances().db_instance_identifier(&db_id).send().await.unwrap();
    let db = &d.db_instances()[0];
    assert_eq!(db.db_instance_status(), Some("available"));
    assert_eq!(db.endpoint().unwrap().address(), Some(output(&outs, "DbAddress").as_str()));
    assert_eq!(output(&outs, "DbPort"), "5432");
    assert_eq!(db.db_instance_arn(), Some(output(&outs, "DbArn").as_str()));
    assert_eq!(db.allocated_storage(), Some(20));
    assert_eq!(db.backup_retention_period(), Some(7));
    let group = db.db_parameter_groups()[0].db_parameter_group_name().unwrap().to_string();
    assert!(group.starts_with("data-dbparams-"), "{group}");
    let subnet_group = db.db_subnet_group().unwrap();
    assert_eq!(subnet_group.subnets().len(), 2);
    assert!(db.tag_list().iter().any(|t| t.key() == Some("tier") && t.value() == Some("data")));
    let params = rds.describe_db_parameters().db_parameter_group_name(&group).source("user").send().await.unwrap();
    let value = |name: &str| {
        params
            .parameters()
            .iter()
            .find(|p| p.parameter_name() == Some(name))
            .and_then(|p| p.parameter_value().map(String::from))
    };
    assert_eq!(value("log_min_duration_statement").as_deref(), Some("1000"));
    assert_eq!(value("autovacuum_max_workers").as_deref(), Some("4"));

    // The Aurora cluster, with its writer and reader endpoints.
    let cluster_id = output(&outs, "ClusterId");
    let c = rds.describe_db_clusters().db_cluster_identifier(&cluster_id).send().await.unwrap();
    let cluster = &c.db_clusters()[0];
    assert_eq!(cluster.status(), Some("available"));
    assert_eq!(cluster.endpoint(), Some(output(&outs, "ClusterAddress").as_str()));
    assert_eq!(cluster.reader_endpoint(), Some(output(&outs, "ClusterReader").as_str()));
    assert_eq!(cluster.db_cluster_arn(), Some(output(&outs, "ClusterArn").as_str()));
    assert!(cluster.db_cluster_parameter_group().unwrap().starts_with("data-clusterparams-"));

    // ElastiCache: the replication group's primary and the memcached
    // configuration endpoint.
    let rg_id = output(&outs, "SessionsId");
    let g = ec.describe_replication_groups().replication_group_id(&rg_id).send().await.unwrap();
    let rg = &g.replication_groups()[0];
    assert_eq!(rg.status(), Some("available"));
    assert_eq!(rg.description(), Some("sessions"));
    assert_eq!(rg.member_clusters().len(), 2);
    let ng = &rg.node_groups()[0];
    assert_eq!(ng.primary_endpoint().unwrap().address(), Some(output(&outs, "SessionsPrimary").as_str()));
    assert_eq!(output(&outs, "SessionsReaders").split(',').count(), 2);
    let mc = ec
        .describe_cache_clusters()
        .cache_cluster_id(output(&outs, "MemcachedId"))
        .show_cache_node_info(true)
        .send()
        .await
        .unwrap();
    let mc = &mc.cache_clusters()[0];
    assert_eq!(mc.cache_cluster_status(), Some("available"));
    assert_eq!(mc.configuration_endpoint().unwrap().address(), Some(output(&outs, "MemcachedEndpoint").as_str()));
    let cp = ec
        .describe_cache_parameters()
        .cache_parameter_group_name(output(&outs, "CacheParamsName"))
        .source("user")
        .send()
        .await
        .unwrap();
    assert!(cp
        .parameters()
        .iter()
        .any(|p| p.parameter_name() == Some("maxmemory-policy") && p.parameter_value() == Some("allkeys-lru")));

    // Update in place: the instance keeps its identifier.
    cfn.update_stack()
        .stack_name("data")
        .use_previous_template(true)
        .parameters(param("Retention", "3"))
        .parameters(param("Workers", "6"))
        .parameters(param("Description", "user sessions"))
        .send()
        .await
        .unwrap();
    let stack = settle(&cfn, "data").await;
    assert_eq!(stack.stack_status(), Some(&StackStatus::UpdateComplete), "{:?}", failures(&cfn, "data").await);
    assert_eq!(output(stack.outputs(), "DbId"), db_id);
    let d = rds.describe_db_instances().db_instance_identifier(&db_id).send().await.unwrap();
    assert_eq!(d.db_instances()[0].backup_retention_period(), Some(3));
    let params = rds.describe_db_parameters().db_parameter_group_name(&group).source("user").send().await.unwrap();
    assert!(params
        .parameters()
        .iter()
        .any(|p| p.parameter_name() == Some("autovacuum_max_workers") && p.parameter_value() == Some("6")));
    let g = ec.describe_replication_groups().replication_group_id(&rg_id).send().await.unwrap();
    assert_eq!(g.replication_groups()[0].description(), Some("user sessions"));

    // Delete: the instance's `Snapshot` policy leaves a final snapshot.
    cfn.delete_stack().stack_name("data").send().await.unwrap();
    let stack = settle(&cfn, "data").await;
    assert_eq!(stack.stack_status(), Some(&StackStatus::DeleteComplete), "{:?}", failures(&cfn, "data").await);
    let gone = rds.describe_db_instances().db_instance_identifier(&db_id).send().await.unwrap_err();
    assert_eq!(gone.into_service_error().meta().code(), Some("DBInstanceNotFound"));
    let gone = rds.describe_db_clusters().db_cluster_identifier(&cluster_id).send().await.unwrap_err();
    assert_eq!(gone.into_service_error().meta().code(), Some("DBClusterNotFoundFault"));
    let snaps =
        rds.describe_db_snapshots().db_instance_identifier(&db_id).snapshot_type("manual").send().await.unwrap();
    assert_eq!(snaps.db_snapshots().len(), 1, "{:?}", snaps.db_snapshots());
    let snap = &snaps.db_snapshots()[0];
    assert!(snap.db_snapshot_identifier().unwrap().starts_with("data-database-"), "{snap:?}");
    assert_eq!(snap.status(), Some("available"));
    let rgs = ec.describe_replication_groups().send().await.unwrap();
    assert!(rgs.replication_groups().is_empty());
    let all = ec.describe_cache_clusters().send().await.unwrap();
    assert!(all.cache_clusters().is_empty());
}
