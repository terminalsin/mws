//! Contact lists, contacts and their topic preferences, and the one-click
//! unsubscribe links list management adds to mail.

use mws_core::{RequestContext, ServiceError};

use crate::events::{EventKind, MailEvent, MailInfo};
use crate::names::{self, authorize};
use crate::state::{Contact, ContactList};
use crate::v2::types as t2;
use crate::{v2, Ses};

fn list_arn(ctx: &RequestContext, name: &str) -> String {
    names::arn(ctx, &format!("contact-list/{name}"))
}

fn missing(name: &str) -> ServiceError {
    v2::errors::not_found(format!("List with name {name} does not exist."))
}

fn check_topics(topics: &[t2::Topic]) -> Result<(), ServiceError> {
    if topics.len() > 20 {
        return Err(v2::errors::bad_request("A contact list can have at most 20 topics."));
    }
    for t in topics {
        if !matches!(t.default_subscription_status.as_str(), "OPT_IN" | "OPT_OUT") {
            return Err(v2::errors::bad_request(format!(
                "Invalid subscription status {}.",
                t.default_subscription_status
            )));
        }
    }
    Ok(())
}

fn check_preferences(list: &ContactList, prefs: &[t2::TopicPreference]) -> Result<(), ServiceError> {
    for p in prefs {
        if !list.topics.iter().any(|t| t.topic_name == p.topic_name) {
            return Err(v2::errors::bad_request(format!(
                "Topic {} does not exist in list {}.",
                p.topic_name, list.name
            )));
        }
    }
    Ok(())
}

impl Ses {
    fn with_list<T>(
        &self,
        ctx: &RequestContext,
        action: &str,
        name: &str,
        f: impl FnOnce(&mut ContactList) -> Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        let tags = self.with_region(ctx, |r| r.contact_lists.get(name).map(|l| l.tags.clone()));
        names::authorize_tagged(ctx, "2", action, &list_arn(ctx, name), &tags.clone().unwrap_or_default())?;
        self.with_region(ctx, |r| match r.contact_lists.get_mut(name) {
            Some(l) => f(l),
            None => Err(missing(name)),
        })
    }

    pub(crate) fn create_contact_list_v2(
        &self,
        ctx: &RequestContext,
        input: t2::CreateContactListRequest,
    ) -> Result<t2::CreateContactListResponse, ServiceError> {
        let tags = names::tags_pairs(input.tags.as_deref());
        names::authorize_create(ctx, "CreateContactList", &list_arn(ctx, &input.contact_list_name), &tags)?;
        names::check_tags(&tags)?;
        let topics = input.topics.unwrap_or_default();
        check_topics(&topics)?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            if r.contact_lists.contains_key(&input.contact_list_name) {
                return Err(v2::errors::already_exists(format!(
                    "List with name {} already exists.",
                    input.contact_list_name
                )));
            }
            if !r.contact_lists.is_empty() {
                return Err(v2::errors::limit_exceeded("An account can have only one contact list."));
            }
            r.contact_lists.insert(
                input.contact_list_name.clone(),
                ContactList {
                    name: input.contact_list_name,
                    topics,
                    description: input.description,
                    created: now,
                    updated: now,
                    tags: tags.into_iter().collect(),
                    contacts: Default::default(),
                },
            );
            Ok(Default::default())
        })
    }

    pub(crate) fn get_contact_list_v2(
        &self,
        ctx: &RequestContext,
        input: t2::GetContactListRequest,
    ) -> Result<t2::GetContactListResponse, ServiceError> {
        self.with_list(ctx, "GetContactList", &input.contact_list_name, |l| {
            Ok(t2::GetContactListResponse {
                contact_list_name: Some(l.name.clone()),
                topics: Some(l.topics.clone()),
                description: l.description.clone(),
                created_timestamp: Some(l.created),
                last_updated_timestamp: Some(l.updated),
                tags: Some(names::tag_list(&l.tags)),
            })
        })
    }

    pub(crate) fn update_contact_list_v2(
        &self,
        ctx: &RequestContext,
        input: t2::UpdateContactListRequest,
    ) -> Result<t2::UpdateContactListResponse, ServiceError> {
        if let Some(t) = &input.topics {
            check_topics(t)?;
        }
        let now = ctx.received_at;
        self.with_list(ctx, "UpdateContactList", &input.contact_list_name, |l| {
            if let Some(t) = input.topics {
                l.topics = t;
            }
            if input.description.is_some() {
                l.description = input.description;
            }
            l.updated = now;
            Ok(Default::default())
        })
    }

    pub(crate) fn delete_contact_list_v2(
        &self,
        ctx: &RequestContext,
        input: t2::DeleteContactListRequest,
    ) -> Result<t2::DeleteContactListResponse, ServiceError> {
        self.with_list(ctx, "DeleteContactList", &input.contact_list_name, |_| Ok(()))?;
        self.with_region(ctx, |r| r.contact_lists.remove(&input.contact_list_name));
        Ok(Default::default())
    }

    pub(crate) fn list_contact_lists_v2(
        &self,
        ctx: &RequestContext,
        input: t2::ListContactListsRequest,
    ) -> Result<t2::ListContactListsResponse, ServiceError> {
        authorize(ctx, "2", "ListContactLists", "*")?;
        names::check_token(input.next_token.as_deref())?;
        let all: Vec<t2::ContactList> = self.with_region(ctx, |r| {
            r.contact_lists
                .values()
                .map(|l| t2::ContactList {
                    contact_list_name: Some(l.name.clone()),
                    last_updated_timestamp: Some(l.updated),
                })
                .collect()
        });
        let (page, next) = names::paginate(&all, input.next_token.as_deref(), input.page_size, 100);
        Ok(t2::ListContactListsResponse { contact_lists: Some(page), next_token: next })
    }

    pub(crate) fn create_contact_v2(
        &self,
        ctx: &RequestContext,
        input: t2::CreateContactRequest,
    ) -> Result<t2::CreateContactResponse, ServiceError> {
        names::check_address(&input.email_address)
            .map_err(|m| v2::errors::bad_request(format!("Invalid email address: {m}")))?;
        let now = ctx.received_at;
        self.with_list(ctx, "CreateContact", &input.contact_list_name, |l| {
            let key = input.email_address.to_ascii_lowercase();
            if l.contacts.contains_key(&key) {
                return Err(v2::errors::already_exists(format!("Contact already exists in list {}.", l.name)));
            }
            let prefs = input.topic_preferences.unwrap_or_default();
            check_preferences(l, &prefs)?;
            l.contacts.insert(
                key,
                Contact {
                    email: input.email_address,
                    topic_preferences: prefs,
                    unsubscribe_all: input.unsubscribe_all,
                    attributes: input.attributes_data,
                    created: now,
                    updated: now,
                },
            );
            Ok(Default::default())
        })
    }

    pub(crate) fn get_contact_v2(
        &self,
        ctx: &RequestContext,
        input: t2::GetContactRequest,
    ) -> Result<t2::GetContactResponse, ServiceError> {
        self.with_list(ctx, "GetContact", &input.contact_list_name, |l| {
            let c = l
                .contacts
                .get(&input.email_address.to_ascii_lowercase())
                .ok_or_else(|| v2::errors::not_found(format!("Contact {} does not exist.", input.email_address)))?;
            Ok(t2::GetContactResponse {
                contact_list_name: Some(l.name.clone()),
                email_address: Some(c.email.clone()),
                topic_preferences: Some(c.topic_preferences.clone()),
                topic_default_preferences: Some(
                    l.topics
                        .iter()
                        .map(|t| t2::TopicPreference {
                            topic_name: t.topic_name.clone(),
                            subscription_status: t.default_subscription_status.clone(),
                        })
                        .collect(),
                ),
                unsubscribe_all: c.unsubscribe_all,
                attributes_data: c.attributes.clone(),
                created_timestamp: Some(c.created),
                last_updated_timestamp: Some(c.updated),
            })
        })
    }

    pub(crate) fn update_contact_v2(
        &self,
        ctx: &RequestContext,
        input: t2::UpdateContactRequest,
    ) -> Result<t2::UpdateContactResponse, ServiceError> {
        let now = ctx.received_at;
        self.with_list(ctx, "UpdateContact", &input.contact_list_name, |l| {
            if let Some(p) = &input.topic_preferences {
                check_preferences(l, p)?;
            }
            let c = l
                .contacts
                .get_mut(&input.email_address.to_ascii_lowercase())
                .ok_or_else(|| v2::errors::not_found(format!("Contact {} does not exist.", input.email_address)))?;
            if let Some(p) = input.topic_preferences {
                c.topic_preferences = p;
            }
            c.unsubscribe_all = input.unsubscribe_all;
            if input.attributes_data.is_some() {
                c.attributes = input.attributes_data;
            }
            c.updated = now;
            Ok(Default::default())
        })
    }

    pub(crate) fn delete_contact_v2(
        &self,
        ctx: &RequestContext,
        input: t2::DeleteContactRequest,
    ) -> Result<t2::DeleteContactResponse, ServiceError> {
        self.with_list(ctx, "DeleteContact", &input.contact_list_name, |l| {
            l.contacts
                .remove(&input.email_address.to_ascii_lowercase())
                .ok_or_else(|| v2::errors::not_found(format!("Contact {} does not exist.", input.email_address)))?;
            Ok(Default::default())
        })
    }

    pub(crate) fn list_contacts_v2(
        &self,
        ctx: &RequestContext,
        input: t2::ListContactsRequest,
    ) -> Result<t2::ListContactsResponse, ServiceError> {
        names::check_token(input.next_token.as_deref())?;
        let filter = input.filter.clone().unwrap_or_default();
        let all = self.with_list(ctx, "ListContacts", &input.contact_list_name, |l| {
            Ok(l.contacts
                .values()
                .filter(|c| {
                    let Some(status) = &filter.filtered_status else { return true };
                    let topic = filter.topic_filter.as_ref().and_then(|t| t.topic_name.clone());
                    let effective = match &topic {
                        Some(t) => c
                            .topic_preferences
                            .iter()
                            .find(|p| &p.topic_name == t)
                            .map(|p| p.subscription_status.clone())
                            .or_else(|| {
                                filter
                                    .topic_filter
                                    .as_ref()
                                    .map(|f| f.use_default_if_preference_unavailable)
                                    .filter(|b| *b)
                                    .and_then(|_| {
                                        l.topics
                                            .iter()
                                            .find(|x| &x.topic_name == t)
                                            .map(|x| x.default_subscription_status.clone())
                                    })
                            }),
                        None => Some(if c.unsubscribe_all { "OPT_OUT".into() } else { "OPT_IN".into() }),
                    };
                    effective.as_deref() == Some(status.as_str())
                })
                .map(|c| t2::Contact {
                    email_address: Some(c.email.clone()),
                    topic_preferences: Some(c.topic_preferences.clone()),
                    topic_default_preferences: Some(
                        l.topics
                            .iter()
                            .map(|t| t2::TopicPreference {
                                topic_name: t.topic_name.clone(),
                                subscription_status: t.default_subscription_status.clone(),
                            })
                            .collect(),
                    ),
                    unsubscribe_all: c.unsubscribe_all,
                    last_updated_timestamp: Some(c.updated),
                })
                .collect::<Vec<_>>())
        })?;
        let (page, next) = names::paginate(&all, input.next_token.as_deref(), input.page_size, 100);
        Ok(t2::ListContactsResponse { contacts: Some(page), next_token: next })
    }

    /// A recipient followed a `List-Unsubscribe` link.
    pub(crate) fn unsubscribe_link(&self, ctx: &RequestContext, token: &str) -> Option<()> {
        let link = self.lock().unsubscribe_links.get(token).cloned()?;
        let now = ctx.received_at;
        {
            let mut st = self.lock();
            let r = st.regions.entry(crate::state::region_key(&link.account, &link.region)).or_default();
            let l = r.contact_lists.get_mut(&link.contact_list)?;
            let c = l.contacts.entry(link.email.to_ascii_lowercase()).or_insert_with(|| Contact {
                email: link.email.clone(),
                created: now,
                ..Default::default()
            });
            match &link.topic {
                Some(t) => {
                    c.topic_preferences.retain(|p| &p.topic_name != t);
                    c.topic_preferences
                        .push(t2::TopicPreference { topic_name: t.clone(), subscription_status: "OPT_OUT".into() });
                }
                None => c.unsubscribe_all = true,
            }
            c.updated = now;
        }
        let mail = MailInfo {
            partition: ctx.partition.clone(),
            account: link.account.clone(),
            region: link.region.clone(),
            timestamp: now,
            message_id: link.message_id.clone(),
            destination: vec![link.email.clone()],
            configuration_set: link.configuration_set.clone(),
            ..Default::default()
        };
        let e = MailEvent {
            mail,
            kind: EventKind::Subscription {
                contact_list: link.contact_list.clone(),
                recipient: link.email.clone(),
                topic: link.topic.clone(),
                unsubscribe_all: link.topic.is_none(),
            },
            time: now,
        };
        self.publish_events(ctx, vec![e]);
        Some(())
    }
}
