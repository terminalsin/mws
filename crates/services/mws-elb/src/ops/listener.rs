//! Listeners: create, describe, modify, delete, certificates and
//! attributes. Every listener has a default rule holding its default
//! actions.

use mws_core::{RequestContext, ServiceError};

use crate::names::{self, validation};
use crate::state::{ListenerRecord, RegionState, RuleRecord};
use crate::v2::{errors, types as t};
use crate::{account_of, catalog, Elb};

pub(crate) fn listener_not_found() -> ServiceError {
    errors::listener_not_found("One or more listeners not found")
}

pub(crate) fn find_listener<'a>(r: &'a RegionState, arn: &str) -> Result<&'a ListenerRecord, ServiceError> {
    r.listeners.get(arn).ok_or_else(listener_not_found)
}

fn protocols_for(ty: &str) -> &'static [&'static str] {
    match ty {
        "network" => &["TCP", "TLS", "UDP", "TCP_UDP", "QUIC", "TCP_QUIC"],
        "gateway" => &[],
        _ => &["HTTP", "HTTPS"],
    }
}

impl Elb {
    /// Check that every certificate exists in ACM and is issued.
    fn check_certificates(&self, ctx: &RequestContext, arns: &[String]) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        for arn in arns {
            let found = self.acm().and_then(|acm| acm.server_certificate(arn));
            match found {
                Some(c) if c.account == account && c.region == ctx.region => {
                    if c.status != "ISSUED" {
                        return Err(errors::invalid_configuration_request(format!(
                            "Certificate '{arn}' must have a status of 'ISSUED' (it is '{}')",
                            c.status
                        )));
                    }
                }
                _ => return Err(errors::certificate_not_found(format!("Certificate '{arn}' not found"))),
            }
        }
        Ok(())
    }

    fn claim_certificates(&self, listener_arn: &str, arns: impl IntoIterator<Item = String>) {
        if let Some(acm) = self.acm() {
            let lb = names::lb_path_of_listener(listener_arn).and_then(|p| {
                listener_arn.split_once(":listener/").map(|(head, _)| format!("{head}:loadbalancer/{p}"))
            });
            for arn in arns {
                acm.set_in_use(&arn, lb.as_deref().unwrap_or(listener_arn), true);
            }
        }
    }

    /// Mark certificates no longer used by a listener's load balancer.
    pub(crate) fn release_certificates(&self, listener_arn: &str, arns: impl IntoIterator<Item = String>) {
        let Some(acm) = self.acm() else { return };
        let Some(lb) = names::lb_path_of_listener(listener_arn)
            .and_then(|p| listener_arn.split_once(":listener/").map(|(head, _)| format!("{head}:loadbalancer/{p}")))
        else {
            return;
        };
        let still_used: Vec<String> = {
            let st = self.lock();
            st.regions
                .values()
                .flat_map(|r| r.listeners.values())
                .filter(|l| l.arn() != listener_arn && l.lb_arn() == lb)
                .flat_map(|l| {
                    l.listener
                        .certificates
                        .iter()
                        .flatten()
                        .filter_map(|c| c.certificate_arn.clone())
                        .chain(l.extra_certificates.iter().cloned())
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        for arn in arns {
            if !still_used.contains(&arn) {
                acm.set_in_use(&arn, &lb, false);
            }
        }
    }

    pub(crate) fn create_listener_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateListenerInput,
    ) -> Result<t::CreateListenerOutput, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        names::check_tags(&tags)?;
        let (lb_type, lb_path) = self.with_region(ctx, |r| {
            super::lb::find_lb(r, &input.load_balancer_arn).map(|l| (l.ty().to_string(), names::lb_dimension(l.arn())))
        })?;
        let (protocol, port) = match lb_type.as_str() {
            "gateway" => {
                if input.protocol.is_some() || input.port.is_some() {
                    return Err(validation(
                        "Protocol and port cannot be specified for Gateway Load Balancer listeners",
                    ));
                }
                (String::new(), None)
            }
            _ => {
                let protocol =
                    input.protocol.clone().ok_or_else(|| validation("A listener protocol must be specified"))?;
                if !protocols_for(&lb_type).contains(&protocol.as_str()) {
                    return Err(errors::unsupported_protocol(format!(
                        "Protocol '{protocol}' is not supported for load balancers of type '{lb_type}'"
                    )));
                }
                let port = input.port.ok_or_else(|| validation("A listener port must be specified"))?;
                (protocol, Some(port))
            }
        };
        let tls = matches!(protocol.as_str(), "HTTPS" | "TLS");
        let certs: Vec<t::Certificate> = input.certificates.clone().unwrap_or_default();
        if tls && certs.is_empty() {
            return Err(validation(format!("A certificate must be specified for {protocol} listeners")));
        }
        if !tls && !certs.is_empty() {
            return Err(validation(format!("Certificates cannot be specified for {protocol} listeners")));
        }
        if certs.len() > 1 {
            return Err(errors::too_many_certificates("You can specify only one default certificate for a listener"));
        }
        let cert_arns: Vec<String> = certs.iter().filter_map(|c| c.certificate_arn.clone()).collect();
        self.check_certificates(ctx, &cert_arns)?;
        let ssl_policy = if tls {
            let p = input.ssl_policy.clone().unwrap_or_else(|| catalog::DEFAULT_SSL_POLICY.into());
            if catalog::ssl_policy(&p).is_none() {
                return Err(errors::ssl_policy_not_found(format!("SSL policy '{p}' not found")));
            }
            Some(p)
        } else if input.ssl_policy.is_some() {
            return Err(validation(format!("An SSL policy cannot be specified for {protocol} listeners")));
        } else {
            None
        };
        if let Some(alpn) = &input.alpn_policy {
            if protocol != "TLS" {
                return Err(errors::alpn_policy_not_supported("ALPN policies are only supported for TLS listeners"));
            }
            if alpn.len() != 1
                || !matches!(alpn[0].as_str(), "HTTP1Only" | "HTTP2Only" | "HTTP2Optional" | "HTTP2Preferred" | "None")
            {
                return Err(errors::alpn_policy_not_supported(format!(
                    "ALPN policy '{}' is not supported",
                    alpn.join(",")
                )));
            }
        }
        let mutual = self.check_mutual_authentication(ctx, &protocol, input.mutual_authentication.clone())?;
        let account = account_of(ctx);
        let id = names::hex_id(16);
        let arn = names::arn(ctx, &account, &format!("listener/{lb_path}/{id}"));
        self.authorize_create(ctx, "CreateListener", &arn, &tags)?;
        let out = self.with_region(ctx, |r| {
            let actions =
                super::actions::normalize(r, &input.load_balancer_arn, &lb_type, &protocol, &input.default_actions)?;
            if let Some(existing) =
                r.listeners.values().find(|l| l.lb_arn() == input.load_balancer_arn && l.listener.port == port)
            {
                let same = existing.protocol() == protocol
                    && existing.listener.default_actions.as_ref() == Some(&actions)
                    && existing.listener.certificates.clone().unwrap_or_default() == certs;
                if same {
                    return Ok(existing.listener.clone());
                }
                return Err(errors::duplicate_listener(format!(
                    "A listener already exists on this port for this load balancer '{}'",
                    input.load_balancer_arn
                )));
            }
            if lb_type == "gateway" && r.listeners.values().any(|l| l.lb_arn() == input.load_balancer_arn) {
                return Err(errors::duplicate_listener("A Gateway Load Balancer can have only one listener"));
            }
            let count = r.listeners.values().filter(|l| l.lb_arn() == input.load_balancer_arn).count();
            if count >= 50 {
                return Err(errors::too_many_listeners(
                    "You have reached the maximum number of listeners for this load balancer",
                ));
            }
            let listener = t::Listener {
                listener_arn: Some(arn.clone()),
                load_balancer_arn: Some(input.load_balancer_arn.clone()),
                port,
                protocol: (!protocol.is_empty()).then(|| protocol.clone()),
                certificates: tls.then(|| certs.clone()),
                ssl_policy: ssl_policy.clone(),
                default_actions: Some(actions.clone()),
                alpn_policy: if protocol == "TLS" {
                    Some(input.alpn_policy.clone().unwrap_or_else(|| vec!["None".into()]))
                } else {
                    None
                },
                mutual_authentication: mutual.clone(),
            };
            let rule_arn = names::arn(ctx, &account, &format!("listener-rule/{lb_path}/{id}/{}", names::hex_id(16)));
            r.rules.insert(
                rule_arn.clone(),
                RuleRecord {
                    rule: t::Rule {
                        rule_arn: Some(rule_arn.clone()),
                        priority: Some("default".into()),
                        conditions: Some(Vec::new()),
                        actions: Some(actions),
                        is_default: Some(true),
                        transforms: None,
                    },
                    listener_arn: arn.clone(),
                },
            );
            r.listeners.insert(
                arn.clone(),
                ListenerRecord {
                    listener: listener.clone(),
                    attributes: catalog::listener_attributes(&protocol),
                    extra_certificates: Vec::new(),
                    default_rule_arn: rule_arn,
                },
            );
            if !tags.is_empty() {
                r.tags.insert(arn.clone(), tags.clone());
            }
            Ok(listener)
        })?;
        self.claim_certificates(&arn, cert_arns);
        self.reconcile();
        let mut out = out;
        super::actions::redact(&mut out.default_actions);
        Ok(t::CreateListenerOutput { listeners: Some(vec![out]) })
    }

    fn check_mutual_authentication(
        &self,
        ctx: &RequestContext,
        protocol: &str,
        m: Option<t::MutualAuthenticationAttributes>,
    ) -> Result<Option<t::MutualAuthenticationAttributes>, ServiceError> {
        if protocol != "HTTPS" {
            if m.as_ref().and_then(|m| m.mode.as_deref()).is_some_and(|mode| mode != "off") {
                return Err(validation("Mutual authentication is only supported for HTTPS listeners"));
            }
            return Ok(None);
        }
        let mut m = m.unwrap_or_default();
        let mode = m.mode.clone().unwrap_or_else(|| "off".into());
        match mode.as_str() {
            "off" | "passthrough" => {
                if m.trust_store_arn.is_some() {
                    return Err(validation(format!(
                        "A trust store cannot be specified with mutual authentication mode '{mode}'"
                    )));
                }
            }
            "verify" => {
                let ts = m.trust_store_arn.clone().ok_or_else(|| {
                    validation("A trust store must be specified for mutual authentication mode 'verify'")
                })?;
                let status = self.with_region(ctx, |r| r.trust_stores.get(&ts).map(|s| s.store.status.clone()));
                match status {
                    None => return Err(errors::trust_store_not_found(format!("Trust store '{ts}' not found"))),
                    Some(s) if s.as_deref() != Some("ACTIVE") => {
                        return Err(errors::trust_store_not_ready(format!("Trust store '{ts}' is not active")))
                    }
                    _ => {}
                }
                m.ignore_client_certificate_expiry.get_or_insert(false);
                m.trust_store_association_status = Some("active".into());
                m.advertise_trust_store_ca_names.get_or_insert_with(|| "off".into());
            }
            _ => return Err(validation(format!("Mutual authentication mode '{mode}' is not valid"))),
        }
        m.mode = Some(mode);
        Ok(Some(m))
    }

    pub(crate) fn describe_listeners_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeListenersInput,
    ) -> Result<t::DescribeListenersOutput, ServiceError> {
        names::authorize(ctx, "DescribeListeners", "*", Default::default())?;
        let arns = input.listener_arns.unwrap_or_default();
        if input.load_balancer_arn.is_some() == !arns.is_empty() {
            return Err(validation("You must specify either listener ARNs or a load balancer ARN"));
        }
        let all = self.with_region(ctx, |r| -> Result<Vec<t::Listener>, ServiceError> {
            if let Some(lb) = &input.load_balancer_arn {
                super::lb::find_lb(r, lb)?;
                let mut v: Vec<_> =
                    r.listeners.values().filter(|l| l.lb_arn() == lb).map(|l| l.listener.clone()).collect();
                v.sort_by_key(|l| l.port);
                return Ok(v);
            }
            arns.iter().map(|a| find_listener(r, a).map(|l| l.listener.clone())).collect()
        })?;
        let (items, next) = names::page(&all, input.marker.as_deref(), input.page_size, 400)?;
        let mut items = items;
        items.iter_mut().for_each(|l| super::actions::redact(&mut l.default_actions));
        Ok(t::DescribeListenersOutput { listeners: Some(items), next_marker: next })
    }

    pub(crate) fn modify_listener_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyListenerInput,
    ) -> Result<t::ModifyListenerOutput, ServiceError> {
        self.authorize_on(ctx, "ModifyListener", &input.listener_arn)?;
        let (current, lb_type) = self.with_region(ctx, |r| {
            let l = find_listener(r, &input.listener_arn)?;
            let ty = r.load_balancers.get(l.lb_arn()).map(|x| x.ty().to_string()).unwrap_or_default();
            Ok::<_, ServiceError>((l.clone(), ty))
        })?;
        let mut listener = current.listener.clone();
        let protocol = input.protocol.clone().or(listener.protocol.clone()).unwrap_or_default();
        if lb_type != "gateway" && !protocols_for(&lb_type).contains(&protocol.as_str()) {
            return Err(errors::unsupported_protocol(format!(
                "Protocol '{protocol}' is not supported for load balancers of type '{lb_type}'"
            )));
        }
        let tls = matches!(protocol.as_str(), "HTTPS" | "TLS");
        let mut new_certs = Vec::new();
        if let Some(c) = &input.certificates {
            if c.len() > 1 {
                return Err(errors::too_many_certificates(
                    "You can specify only one default certificate for a listener",
                ));
            }
            new_certs = c.iter().filter_map(|c| c.certificate_arn.clone()).collect();
            self.check_certificates(ctx, &new_certs)?;
            listener.certificates = Some(c.clone());
        }
        if tls {
            if listener.certificates.as_ref().is_none_or(Vec::is_empty) {
                return Err(validation(format!("A certificate must be specified for {protocol} listeners")));
            }
            let p = input
                .ssl_policy
                .clone()
                .or(listener.ssl_policy.clone())
                .unwrap_or_else(|| catalog::DEFAULT_SSL_POLICY.into());
            if catalog::ssl_policy(&p).is_none() {
                return Err(errors::ssl_policy_not_found(format!("SSL policy '{p}' not found")));
            }
            listener.ssl_policy = Some(p);
        } else {
            listener.certificates = None;
            listener.ssl_policy = None;
        }
        if let Some(a) = &input.alpn_policy {
            if protocol != "TLS" {
                return Err(errors::alpn_policy_not_supported("ALPN policies are only supported for TLS listeners"));
            }
            listener.alpn_policy = Some(a.clone());
        } else if protocol != "TLS" {
            listener.alpn_policy = None;
        } else if listener.alpn_policy.is_none() {
            listener.alpn_policy = Some(vec!["None".into()]);
        }
        if input.mutual_authentication.is_some() || input.protocol.is_some() {
            let m = input.mutual_authentication.clone().or(listener.mutual_authentication.clone());
            listener.mutual_authentication = self.check_mutual_authentication(ctx, &protocol, m)?;
        }
        listener.protocol = (!protocol.is_empty()).then(|| protocol.clone());
        if let Some(p) = input.port {
            listener.port = Some(p);
        }
        let out = self.with_region(ctx, |r| {
            let actions = match &input.default_actions {
                Some(a) => super::actions::normalize(r, current.lb_arn(), &lb_type, &protocol, a)?,
                None => {
                    let existing = listener.default_actions.clone().unwrap_or_default();
                    super::actions::normalize(r, current.lb_arn(), &lb_type, &protocol, &existing)?
                }
            };
            if r.listeners.values().any(|l| {
                l.arn() != input.listener_arn && l.lb_arn() == current.lb_arn() && l.listener.port == listener.port
            }) {
                return Err(errors::duplicate_listener(format!(
                    "A listener already exists on this port for this load balancer '{}'",
                    current.lb_arn()
                )));
            }
            listener.default_actions = Some(actions.clone());
            let rec = r.listeners.get_mut(&input.listener_arn).ok_or_else(listener_not_found)?;
            if rec.protocol() != protocol {
                rec.attributes = catalog::listener_attributes(&protocol);
            }
            rec.listener = listener.clone();
            if !tls {
                rec.extra_certificates.clear();
            }
            let default_rule = rec.default_rule_arn.clone();
            if let Some(rule) = r.rules.get_mut(&default_rule) {
                rule.rule.actions = Some(actions);
            }
            Ok(listener.clone())
        })?;
        let old: Vec<String> =
            current.listener.certificates.iter().flatten().filter_map(|c| c.certificate_arn.clone()).collect();
        self.claim_certificates(&input.listener_arn, new_certs.clone());
        let dropped: Vec<String> = if tls {
            old.into_iter().filter(|c| !new_certs.contains(c) && input.certificates.is_some()).collect()
        } else {
            old.into_iter().chain(current.extra_certificates.iter().cloned()).collect()
        };
        self.release_certificates_keeping(&input.listener_arn, dropped);
        self.reconcile();
        let mut out = out;
        super::actions::redact(&mut out.default_actions);
        Ok(t::ModifyListenerOutput { listeners: Some(vec![out]) })
    }

    /// Release certificates the listener itself no longer uses either.
    fn release_certificates_keeping(&self, listener_arn: &str, dropped: Vec<String>) {
        let in_use: Vec<String> = {
            let st = self.lock();
            st.regions
                .values()
                .filter_map(|r| r.listeners.get(listener_arn))
                .flat_map(|l| {
                    l.listener
                        .certificates
                        .iter()
                        .flatten()
                        .filter_map(|c| c.certificate_arn.clone())
                        .chain(l.extra_certificates.iter().cloned())
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        self.release_certificates(listener_arn, dropped.into_iter().filter(|c| !in_use.contains(c)));
    }

    pub(crate) fn delete_listener_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteListenerInput,
    ) -> Result<t::DeleteListenerOutput, ServiceError> {
        self.authorize_on(ctx, "DeleteListener", &input.listener_arn)?;
        let removed = self.with_region(ctx, |r| {
            let l = r.listeners.remove(&input.listener_arn).ok_or_else(listener_not_found)?;
            r.tags.remove(&input.listener_arn);
            let rules: Vec<String> = r
                .rules
                .values()
                .filter(|x| x.listener_arn == input.listener_arn)
                .map(|x| x.arn().to_string())
                .collect();
            for rule in rules {
                r.rules.remove(&rule);
                r.tags.remove(&rule);
            }
            Ok::<_, ServiceError>(l)
        })?;
        self.release_certificates(
            &input.listener_arn,
            removed
                .listener
                .certificates
                .iter()
                .flatten()
                .filter_map(|c| c.certificate_arn.clone())
                .chain(removed.extra_certificates.iter().cloned()),
        );
        self.reconcile();
        Ok(t::DeleteListenerOutput {})
    }

    pub(crate) fn add_listener_certificates_op(
        &self,
        ctx: &RequestContext,
        input: t::AddListenerCertificatesInput,
    ) -> Result<t::AddListenerCertificatesOutput, ServiceError> {
        self.authorize_on(ctx, "AddListenerCertificates", &input.listener_arn)?;
        let arns: Vec<String> = input.certificates.iter().filter_map(|c| c.certificate_arn.clone()).collect();
        if input.certificates.iter().any(|c| c.is_default == Some(true)) {
            return Err(validation("You cannot add a default certificate with AddListenerCertificates"));
        }
        self.check_certificates(ctx, &arns)?;
        self.with_region(ctx, |r| {
            let l = r.listeners.get_mut(&input.listener_arn).ok_or_else(listener_not_found)?;
            if !matches!(l.protocol(), "HTTPS" | "TLS") {
                return Err(validation("Certificates can only be added to HTTPS and TLS listeners"));
            }
            for a in &arns {
                if !l.extra_certificates.contains(a) && l.default_certificate() != Some(a.as_str()) {
                    if l.extra_certificates.len() >= 25 {
                        return Err(errors::too_many_certificates(
                            "You have reached the maximum number of certificates for this listener",
                        ));
                    }
                    l.extra_certificates.push(a.clone());
                }
            }
            Ok(())
        })?;
        self.claim_certificates(&input.listener_arn, arns.clone());
        Ok(t::AddListenerCertificatesOutput {
            certificates: Some(
                arns.into_iter().map(|a| t::Certificate { certificate_arn: Some(a), is_default: None }).collect(),
            ),
        })
    }

    pub(crate) fn remove_listener_certificates_op(
        &self,
        ctx: &RequestContext,
        input: t::RemoveListenerCertificatesInput,
    ) -> Result<t::RemoveListenerCertificatesOutput, ServiceError> {
        self.authorize_on(ctx, "RemoveListenerCertificates", &input.listener_arn)?;
        let arns: Vec<String> = input.certificates.iter().filter_map(|c| c.certificate_arn.clone()).collect();
        self.with_region(ctx, |r| {
            let l = r.listeners.get_mut(&input.listener_arn).ok_or_else(listener_not_found)?;
            for a in &arns {
                if l.default_certificate() == Some(a.as_str()) {
                    return Err(errors::operation_not_permitted(
                        "You cannot remove the default certificate of a listener",
                    ));
                }
            }
            l.extra_certificates.retain(|c| !arns.contains(c));
            Ok(())
        })?;
        self.release_certificates_keeping(&input.listener_arn, arns);
        Ok(t::RemoveListenerCertificatesOutput {})
    }

    pub(crate) fn describe_listener_certificates_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeListenerCertificatesInput,
    ) -> Result<t::DescribeListenerCertificatesOutput, ServiceError> {
        names::authorize(ctx, "DescribeListenerCertificates", "*", Default::default())?;
        let all = self.with_region(ctx, |r| {
            let l = find_listener(r, &input.listener_arn)?;
            let mut v: Vec<t::Certificate> = l
                .default_certificate()
                .map(|d| t::Certificate { certificate_arn: Some(d.to_string()), is_default: Some(true) })
                .into_iter()
                .collect();
            v.extend(
                l.extra_certificates
                    .iter()
                    .map(|c| t::Certificate { certificate_arn: Some(c.clone()), is_default: Some(false) }),
            );
            Ok::<_, ServiceError>(v)
        })?;
        let (items, next) = names::page(&all, input.marker.as_deref(), input.page_size, 400)?;
        Ok(t::DescribeListenerCertificatesOutput { certificates: Some(items), next_marker: next })
    }

    pub(crate) fn describe_listener_attributes_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeListenerAttributesInput,
    ) -> Result<t::DescribeListenerAttributesOutput, ServiceError> {
        names::authorize(ctx, "DescribeListenerAttributes", "*", Default::default())?;
        self.with_region(ctx, |r| {
            let l = find_listener(r, &input.listener_arn)?;
            Ok(t::DescribeListenerAttributesOutput { attributes: Some(listener_attributes(l)) })
        })
    }

    pub(crate) fn modify_listener_attributes_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyListenerAttributesInput,
    ) -> Result<t::ModifyListenerAttributesOutput, ServiceError> {
        self.authorize_on(ctx, "ModifyListenerAttributes", &input.listener_arn)?;
        self.with_region(ctx, |r| {
            let l = r.listeners.get_mut(&input.listener_arn).ok_or_else(listener_not_found)?;
            let mut next = l.attributes.clone();
            for a in &input.attributes {
                let key = a.key.clone().unwrap_or_default();
                let value = a.value.clone().unwrap_or_default();
                if !l.attributes.contains_key(&key) {
                    return Err(validation(format!("Listener attribute key '{key}' is not recognized")));
                }
                if key == "tcp.idle_timeout.seconds" && value.parse::<u32>().map_or(true, |v| !(60..=6000).contains(&v))
                {
                    return Err(validation("The TCP idle timeout must be between 60 and 6000 seconds"));
                }
                if key == "routing.http.response.server.enabled" && !matches!(value.as_str(), "true" | "false") {
                    return Err(validation(format!("'{value}' is not a valid value for listener attribute '{key}'")));
                }
                next.insert(key, value);
            }
            l.attributes = next;
            Ok(t::ModifyListenerAttributesOutput { attributes: Some(listener_attributes(l)) })
        })
    }
}

fn listener_attributes(l: &ListenerRecord) -> Vec<t::ListenerAttribute> {
    l.attributes.iter().map(|(k, v)| t::ListenerAttribute { key: Some(k.clone()), value: Some(v.clone()) }).collect()
}
