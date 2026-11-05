//! EC2 instances that really run: the Docker backend, through the official
//! Rust SDK. Skipped when no Docker daemon answers.

use std::process::Command;
use std::time::Duration;

use aws_sdk_ec2::types::{Filter, InstanceStateName};
use aws_sdk_ec2::Client;
use mws_e2e::Mws;

fn docker_available() -> bool {
    Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .is_ok_and(|o| o.status.success())
}

async fn alpine_ami(ec2: &Client) -> String {
    let images = ec2
        .describe_images()
        .owners("amazon")
        .filters(Filter::builder().name("name").values("mws-alpine-*").build())
        .send()
        .await
        .unwrap();
    images.images()[0].image_id().unwrap().to_string()
}

/// `docker inspect` of an instance's container: its state, or `None` once
/// it is gone.
fn container_state(instance_id: &str) -> Option<String> {
    let out = Command::new("docker")
        .args(["inspect", "--format", "{{.State.Status}}", &format!("mws-ec2-{instance_id}")])
        .output()
        .ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

async fn wait_for_state(ec2: &Client, id: &str, want: InstanceStateName) {
    for _ in 0..240 {
        let d = ec2.describe_instances().instance_ids(id).send().await.unwrap();
        let state = d.reservations()[0].instances()[0].state().unwrap().name().cloned();
        if state.as_ref() == Some(&want) {
            return;
        }
        if want != InstanceStateName::Terminated && state == Some(InstanceStateName::Terminated) {
            panic!("instance {id} terminated: {:?}", d.reservations()[0].instances()[0].state_reason());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("instance {id} never reached {want:?}");
}

#[tokio::test]
async fn instances_run_as_containers() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    // Listen on every interface so instances reach MWS through the Docker
    // host gateway.
    let config = mws::Config { ec2_backend: mws_ec2::BackendChoice::Docker, ..Default::default() };
    let mws = Mws::start_on_all_interfaces(config).await;
    let ec2 = Client::new(&mws.root_sdk_config().await);

    let images = ec2
        .describe_images()
        .owners("amazon")
        .filters(Filter::builder().name("name").values("mws-alpine-*").build())
        .send()
        .await
        .unwrap();
    let ami = images.images()[0].image_id().unwrap().to_string();
    use base64::Engine;
    // User data runs once at first boot; it reads instance metadata the
    // way software on an instance would.
    let script = "#!/bin/sh\necho \"user data ran on $(hostname)\"\necho \"imds says $(wget -qO- \"$AWS_EC2_METADATA_SERVICE_ENDPOINT/latest/meta-data/instance-id\")\"\n";
    let run = ec2
        .run_instances()
        .image_id(&ami)
        .instance_type(aws_sdk_ec2::types::InstanceType::T3Nano)
        .user_data(base64::engine::general_purpose::STANDARD.encode(script))
        .min_count(1)
        .max_count(1)
        .send()
        .await
        .unwrap();
    let id = run.instances()[0].instance_id().unwrap().to_string();
    let ip = run.instances()[0].private_ip_address().unwrap().to_string();
    wait_for_state(&ec2, &id, InstanceStateName::Running).await;
    assert_eq!(container_state(&id).as_deref(), Some("running"));
    let inspect = Command::new("docker")
        .args([
            "inspect",
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            &format!("mws-ec2-{id}"),
        ])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&inspect.stdout).trim(), ip, "the container has the instance's private IP");

    let mut console = String::new();
    for _ in 0..120 {
        let out = ec2.get_console_output().instance_id(&id).send().await.unwrap();
        if let Some(text) = out.output() {
            console = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(text).unwrap()).unwrap();
            if console.contains("Cloud-init finished") {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(console.contains("user data ran on ip-"), "console: {console}");
    assert!(console.contains(&format!("imds says {id}")), "console: {console}");

    ec2.stop_instances().instance_ids(&id).send().await.unwrap();
    wait_for_state(&ec2, &id, InstanceStateName::Stopped).await;
    assert_eq!(container_state(&id).as_deref(), Some("exited"));
    ec2.start_instances().instance_ids(&id).send().await.unwrap();
    wait_for_state(&ec2, &id, InstanceStateName::Running).await;
    assert_eq!(container_state(&id).as_deref(), Some("running"));

    ec2.terminate_instances().instance_ids(&id).send().await.unwrap();
    wait_for_state(&ec2, &id, InstanceStateName::Terminated).await;
    assert_eq!(container_state(&id), None);

    mws.stop().await;
}

/// What `wget` inside an instance's container gets from `url` within two
/// seconds (`None` when the connection is filtered or refused).
fn fetch_from(instance_id: &str, url: &str) -> Option<String> {
    let out = Command::new("docker")
        .args(["exec", &format!("mws-ec2-{instance_id}"), "wget", "-qO-", "-T", "2", url])
        .output()
        .ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Poll until `fetch_from` gives the wanted outcome (VPC changes reach
/// running instances in the background).
async fn eventually(instance_id: &str, url: &str, reachable: bool, why: &str) {
    for _ in 0..30 {
        let got = fetch_from(instance_id, url);
        if got.is_some() == reachable {
            if let Some(body) = got {
                assert_eq!(body, "ok", "{why}");
            }
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let rules = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network",
            &format!("container:mws-ec2-{instance_id}"),
            "--cap-add",
            "NET_ADMIN",
            "--entrypoint",
            "iptables-save",
            mws_ec2::backend::DEFAULT_NETFILTER_IMAGE,
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    panic!("{url} from {instance_id}: expected reachable={reachable}: {why}\n{rules}");
}

#[tokio::test]
async fn security_groups_acls_and_routes_filter_traffic() {
    use aws_sdk_ec2::types::{IpPermission, IpRange, PortRange, RuleAction, UserIdGroupPair};
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let config = mws::Config { ec2_backend: mws_ec2::BackendChoice::Docker, ..Default::default() };
    let mws = Mws::start_on_all_interfaces(config).await;
    let ec2 = Client::new(&mws.root_sdk_config().await);

    // Something outside the VPC: a web server on the Docker host, which
    // instances reach as host.docker.internal.
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let outside_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        while let Ok((mut sock, _)) = listener.accept().await {
            let _ = sock.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        }
    });
    let outside = format!("http://host.docker.internal:{outside_port}/");
    // Some hosts do not let containers reach them at all; routes cannot be
    // shown there.
    let host_reachable = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--add-host",
            "host.docker.internal:host-gateway",
            "alpine:3.20",
            "wget",
            "-qO-",
            "-T",
            "3",
            &outside,
        ])
        .output()
        .is_ok_and(|o| o.status.success());

    let vpc = ec2.create_vpc().cidr_block("10.81.0.0/16").send().await.unwrap();
    let vpc_id = vpc.vpc().unwrap().vpc_id().unwrap().to_string();
    let zone = "us-east-1a";
    let subnet = |cidr: &'static str| {
        let ec2 = ec2.clone();
        let vpc_id = vpc_id.clone();
        async move {
            let s = ec2.create_subnet().vpc_id(vpc_id).cidr_block(cidr).availability_zone(zone).send().await.unwrap();
            s.subnet().unwrap().subnet_id().unwrap().to_string()
        }
    };
    let subnet_a = subnet("10.81.1.0/24").await;
    let subnet_b = subnet("10.81.2.0/24").await;
    let group = |name: &'static str| {
        let ec2 = ec2.clone();
        let vpc_id = vpc_id.clone();
        async move {
            let g = ec2.create_security_group().group_name(name).description(name).vpc_id(vpc_id).send().await.unwrap();
            g.group_id().unwrap().to_string()
        }
    };
    let server_sg = group("server").await;
    let client_sg = group("client").await;
    // The server admits port 8080 from members of the client group only.
    ec2.authorize_security_group_ingress()
        .group_id(&server_sg)
        .ip_permissions(
            IpPermission::builder()
                .ip_protocol("tcp")
                .from_port(8080)
                .to_port(8080)
                .user_id_group_pairs(UserIdGroupPair::builder().group_id(&client_sg).build())
                .build(),
        )
        .send()
        .await
        .unwrap();

    let ami = alpine_ami(&ec2).await;
    use base64::Engine;
    let serve = "#!/bin/sh\nfor p in 8080 8081; do (while true; do printf 'HTTP/1.0 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\nok' | nc -l -p $p; done) & done\n";
    let launch = |subnet: String, sg: String, user_data: Option<&'static str>| {
        let ec2 = ec2.clone();
        let ami = ami.clone();
        async move {
            let mut req = ec2
                .run_instances()
                .image_id(ami)
                .instance_type(aws_sdk_ec2::types::InstanceType::T3Nano)
                .subnet_id(subnet)
                .security_group_ids(sg)
                .min_count(1)
                .max_count(1);
            if let Some(u) = user_data {
                req = req.user_data(base64::engine::general_purpose::STANDARD.encode(u));
            }
            let run = req.send().await.unwrap();
            let i = &run.instances()[0];
            (i.instance_id().unwrap().to_string(), i.private_ip_address().unwrap().to_string())
        }
    };
    let (server, server_ip) = launch(subnet_a.clone(), server_sg.clone(), Some(serve)).await;
    let (client, _) = launch(subnet_b.clone(), client_sg.clone(), None).await;
    wait_for_state(&ec2, &server, InstanceStateName::Running).await;
    wait_for_state(&ec2, &client, InstanceStateName::Running).await;
    let open_port = format!("http://{server_ip}:8080/");
    let closed_port = format!("http://{server_ip}:8081/");

    // Security groups: by group reference, port by port, stateful.
    eventually(&client, &open_port, true, "the server's group admits the client's group on 8080").await;
    eventually(&client, &closed_port, false, "nothing admits 8081").await;
    eventually(&server, &format!("http://{server_ip}:8081/"), true, "an instance reaches itself").await;
    ec2.revoke_security_group_ingress()
        .group_id(&server_sg)
        .ip_permissions(
            IpPermission::builder()
                .ip_protocol("tcp")
                .from_port(8080)
                .to_port(8080)
                .user_id_group_pairs(UserIdGroupPair::builder().group_id(&client_sg).build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    eventually(&client, &open_port, false, "revoking the rule closes 8080").await;
    ec2.authorize_security_group_ingress()
        .group_id(&server_sg)
        .ip_permissions(
            IpPermission::builder()
                .ip_protocol("tcp")
                .from_port(8080)
                .to_port(8081)
                .ip_ranges(IpRange::builder().cidr_ip("10.81.2.0/24").build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    eventually(&client, &closed_port, true, "a CIDR rule for the client's subnet opens 8080-8081").await;
    // Egress rules filter too: the client may only reach port 8080.
    let all_egress =
        IpPermission::builder().ip_protocol("-1").ip_ranges(IpRange::builder().cidr_ip("0.0.0.0/0").build()).build();
    ec2.revoke_security_group_egress().group_id(&client_sg).ip_permissions(all_egress.clone()).send().await.unwrap();
    ec2.authorize_security_group_egress()
        .group_id(&client_sg)
        .ip_permissions(
            IpPermission::builder()
                .ip_protocol("tcp")
                .from_port(8080)
                .to_port(8080)
                .ip_ranges(IpRange::builder().cidr_ip("10.81.0.0/16").build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    eventually(&client, &closed_port, false, "the client's egress rules allow only 8080").await;
    eventually(&client, &open_port, true, "8080 is still allowed out").await;
    ec2.authorize_security_group_egress().group_id(&client_sg).ip_permissions(all_egress).send().await.unwrap();

    // Network ACLs are stateless and judge traffic crossing the subnet.
    let acl = ec2.create_network_acl().vpc_id(&vpc_id).send().await.unwrap();
    let acl_id = acl.network_acl().unwrap().network_acl_id().unwrap().to_string();
    let acls = ec2
        .describe_network_acls()
        .filters(Filter::builder().name("association.subnet-id").values(&subnet_a).build())
        .send()
        .await
        .unwrap();
    let assoc = acls.network_acls()[0]
        .associations()
        .iter()
        .find(|a| a.subnet_id() == Some(subnet_a.as_str()))
        .unwrap()
        .network_acl_association_id()
        .unwrap()
        .to_string();
    ec2.replace_network_acl_association().association_id(&assoc).network_acl_id(&acl_id).send().await.unwrap();
    eventually(&client, &open_port, false, "a new network ACL denies everything").await;
    let entry = |n: i32, egress: bool, from: i32, to: i32| {
        ec2.create_network_acl_entry()
            .network_acl_id(&acl_id)
            .rule_number(n)
            .egress(egress)
            .protocol("6")
            .rule_action(RuleAction::Allow)
            .cidr_block("10.81.2.0/24")
            .port_range(PortRange::builder().from(from).to(to).build())
            .send()
    };
    entry(100, false, 8080, 8080).await.unwrap();
    eventually(&client, &open_port, false, "replies need an outbound entry (ACLs are stateless)").await;
    entry(100, true, 1024, 65535).await.unwrap();
    eventually(&client, &open_port, true, "inbound 8080 plus outbound ephemeral ports").await;
    eventually(&client, &closed_port, false, "8081 is not in the ACL").await;

    if !host_reachable {
        // CI runners let containers reach the host, so there the routing
        // checks must run rather than skip.
        assert!(std::env::var_os("CI").is_none(), "containers cannot reach the Docker host at {outside}");
        eprintln!("skipping the routing checks: containers cannot reach this host");
        for id in [&server, &client] {
            ec2.terminate_instances().instance_ids(id.as_str()).send().await.unwrap();
        }
        mws.stop().await;
        return;
    }
    // Routes: leaving the VPC needs an internet gateway and a public
    // address, or a NAT gateway.
    eventually(&client, &outside, false, "the VPC's main route table has only the local route").await;
    let igw = ec2.create_internet_gateway().send().await.unwrap();
    let igw_id = igw.internet_gateway().unwrap().internet_gateway_id().unwrap().to_string();
    ec2.attach_internet_gateway().internet_gateway_id(&igw_id).vpc_id(&vpc_id).send().await.unwrap();
    let route_table = |subnet: String, nat: Option<String>| {
        let ec2 = ec2.clone();
        let vpc_id = vpc_id.clone();
        let igw_id = igw_id.clone();
        async move {
            let rt = ec2.create_route_table().vpc_id(vpc_id).send().await.unwrap();
            let rt_id = rt.route_table().unwrap().route_table_id().unwrap().to_string();
            let route = ec2.create_route().route_table_id(&rt_id).destination_cidr_block("0.0.0.0/0");
            match nat {
                Some(n) => route.nat_gateway_id(n),
                None => route.gateway_id(igw_id),
            }
            .send()
            .await
            .unwrap();
            let a = ec2.associate_route_table().route_table_id(&rt_id).subnet_id(subnet).send().await.unwrap();
            (rt_id, a.association_id().unwrap().to_string())
        }
    };
    let (_, client_assoc) = route_table(subnet_b.clone(), None).await;
    eventually(&client, &outside, false, "an internet gateway route without a public address").await;
    let eip = ec2.allocate_address().send().await.unwrap();
    let eip_assoc =
        ec2.associate_address().allocation_id(eip.allocation_id().unwrap()).instance_id(&client).send().await.unwrap();
    eventually(&client, &outside, true, "an Elastic IP and a route to the internet gateway").await;
    ec2.disassociate_address().association_id(eip_assoc.association_id().unwrap()).send().await.unwrap();
    eventually(&client, &outside, false, "without the Elastic IP").await;

    // A NAT gateway in subnet A (made public) carries the client out.
    let acl_default = ec2
        .describe_network_acls()
        .filters(Filter::builder().name("vpc-id").values(&vpc_id).build())
        .filters(Filter::builder().name("default").values("true").build())
        .send()
        .await
        .unwrap();
    let default_acl = acl_default.network_acls()[0].network_acl_id().unwrap().to_string();
    let acls = ec2
        .describe_network_acls()
        .filters(Filter::builder().name("association.subnet-id").values(&subnet_a).build())
        .send()
        .await
        .unwrap();
    let assoc = acls.network_acls()[0]
        .associations()
        .iter()
        .find(|a| a.subnet_id() == Some(subnet_a.as_str()))
        .unwrap()
        .network_acl_association_id()
        .unwrap()
        .to_string();
    ec2.replace_network_acl_association().association_id(&assoc).network_acl_id(&default_acl).send().await.unwrap();
    route_table(subnet_a.clone(), None).await;
    let nat_eip = ec2.allocate_address().send().await.unwrap();
    let nat = ec2
        .create_nat_gateway()
        .subnet_id(&subnet_a)
        .allocation_id(nat_eip.allocation_id().unwrap())
        .send()
        .await
        .unwrap();
    let nat_id = nat.nat_gateway().unwrap().nat_gateway_id().unwrap().to_string();
    ec2.disassociate_route_table().association_id(&client_assoc).send().await.unwrap();
    route_table(subnet_b.clone(), Some(nat_id.clone())).await;
    eventually(&client, &outside, true, "a route to a NAT gateway in a public subnet").await;
    ec2.delete_nat_gateway().nat_gateway_id(&nat_id).send().await.unwrap();
    eventually(&client, &outside, false, "the NAT gateway's route is a blackhole once it is deleted").await;

    for id in [&server, &client] {
        ec2.terminate_instances().instance_ids(id.as_str()).send().await.unwrap();
    }
    for id in [&server, &client] {
        wait_for_state(&ec2, id, InstanceStateName::Terminated).await;
    }
    mws.stop().await;
}
