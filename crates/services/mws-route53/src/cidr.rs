//! CIDR collections for IP-based routing.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use mws_core::{RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::state::{CidrCollection, State};
use crate::{arn, max_items, Route53};

fn no_such(id: &str) -> ServiceError {
    errors::no_such_cidr_collection(format!("The CIDR collection {id} does not exist."))
}

impl State {
    fn collection(&self, id: &str) -> Result<&CidrCollection, ServiceError> {
        self.cidr_collections.get(id).ok_or_else(|| no_such(id))
    }
}

impl CidrCollection {
    fn arn(&self, ctx: &RequestContext) -> String {
        arn(ctx, "cidrcollection", &self.id)
    }

    fn summary(&self, ctx: &RequestContext) -> types::CollectionSummary {
        types::CollectionSummary {
            arn: Some(self.arn(ctx)),
            id: Some(self.id.clone()),
            name: Some(self.name.clone()),
            version: Some(self.version),
        }
    }
}

/// Validate and canonicalize a CIDR block (`192.0.2.0/24`, `2001:db8::/48`).
fn parse_cidr(raw: &str) -> Result<String, ServiceError> {
    let bad = || errors::invalid_input(format!("Invalid input: {raw} is not a valid CIDR block."));
    let (ip, len) = raw.split_once('/').ok_or_else(bad)?;
    let ip: IpAddr = ip.parse().map_err(|_| bad())?;
    let len: u8 = len.parse().map_err(|_| bad())?;
    let (bits, max) = match ip {
        IpAddr::V4(v4) => (u32::from(v4) as u128, 32u8),
        IpAddr::V6(v6) => (u128::from(v6), 128u8),
    };
    // Route 53 accepts IPv4 /0-/24 and IPv6 /0-/48 with no host bits set.
    let longest = if max == 32 { 24 } else { 48 };
    if len > longest {
        return Err(bad());
    }
    let host_bits = max - len;
    if host_bits < 128 && bits & ((1u128 << host_bits) - 1) != 0 {
        return Err(bad());
    }
    Ok(format!("{ip}/{len}"))
}

fn page_start(token: Option<&str>) -> Result<usize, ServiceError> {
    match token {
        Some(t) => t.parse().map_err(|_| errors::invalid_pagination_token("The pagination token is not valid.")),
        None => Ok(0),
    }
}

impl Route53 {
    pub(crate) fn create_cidr_collection(
        &self,
        ctx: &RequestContext,
        input: types::CreateCidrCollectionRequest,
    ) -> Result<types::CreateCidrCollectionResponse, ServiceError> {
        self.authorize(ctx, "CreateCidrCollection", "*")?;
        let mut st = self.lock();
        if let Some(existing) = st.cidr_collections.values().find(|c| c.name == input.name) {
            if existing.caller_reference == input.caller_reference {
                // An idempotent retry.
                return Ok(types::CreateCidrCollectionResponse {
                    location: Some(format!("https://route53.amazonaws.com/2013-04-01/cidrcollection/{}", existing.id)),
                    collection: Some(types::CidrCollection {
                        arn: Some(existing.arn(ctx)),
                        id: Some(existing.id.clone()),
                        name: Some(existing.name.clone()),
                        version: Some(existing.version),
                    }),
                });
            }
            return Err(errors::cidr_collection_already_exists(format!(
                "A CIDR collection with the name {} already exists.",
                input.name
            )));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let c = CidrCollection {
            id: id.clone(),
            name: input.name,
            caller_reference: input.caller_reference,
            version: 1,
            locations: BTreeMap::new(),
        };
        let collection = types::CidrCollection {
            arn: Some(c.arn(ctx)),
            id: Some(id.clone()),
            name: Some(c.name.clone()),
            version: Some(1),
        };
        st.cidr_collections.insert(id.clone(), c);
        Ok(types::CreateCidrCollectionResponse {
            collection: Some(collection),
            location: Some(format!("https://route53.amazonaws.com/2013-04-01/cidrcollection/{id}")),
        })
    }

    pub(crate) fn change_cidr_collection(
        &self,
        ctx: &RequestContext,
        input: types::ChangeCidrCollectionRequest,
    ) -> Result<types::ChangeCidrCollectionResponse, ServiceError> {
        self.authorize(ctx, "ChangeCidrCollection", &arn(ctx, "cidrcollection", &input.id))?;
        // Validate everything before applying anything.
        let mut parsed = Vec::new();
        for change in &input.changes {
            let cidrs = change.cidr_list.iter().map(|c| parse_cidr(c)).collect::<Result<BTreeSet<_>, _>>()?;
            parsed.push((change.location_name.clone(), change.action.clone(), cidrs));
        }
        let mut st = self.lock();
        let in_use: BTreeSet<(String, String)> = st
            .zones
            .values()
            .flat_map(|z| z.records.values())
            .filter_map(|r| r.cidr_routing_config.as_ref())
            .filter(|c| c.collection_id == input.id)
            .map(|c| (c.collection_id.clone(), c.location_name.clone()))
            .collect();
        let c = st.cidr_collections.get_mut(&input.id).ok_or_else(|| no_such(&input.id))?;
        if let Some(v) = input.collection_version {
            if v != c.version {
                return Err(errors::cidr_collection_version_mismatch(
                    "The CIDR collection version you provided doesn't match the one in the ListCidrCollections operation.",
                ));
            }
        }
        let mut locations = c.locations.clone();
        for (location, action, cidrs) in parsed {
            match action.as_str() {
                "PUT" => locations.entry(location).or_default().extend(cidrs),
                "DELETE_IF_EXISTS" => {
                    if let Some(set) = locations.get_mut(&location) {
                        set.retain(|b| !cidrs.contains(b));
                        if set.is_empty() {
                            if in_use.contains(&(input.id.clone(), location.clone())) {
                                return Err(errors::cidr_block_in_use(format!(
                                    "This CIDR block is in use: the location {location} is referenced by a resource record set."
                                )));
                            }
                            locations.remove(&location);
                        }
                    }
                }
                other => return Err(errors::invalid_input(format!("Invalid input: unknown action {other}"))),
            }
        }
        c.locations = locations;
        c.version += 1;
        Ok(types::ChangeCidrCollectionResponse { id: uuid::Uuid::new_v4().to_string() })
    }

    pub(crate) fn delete_cidr_collection(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCidrCollectionRequest,
    ) -> Result<types::DeleteCidrCollectionResponse, ServiceError> {
        self.authorize(ctx, "DeleteCidrCollection", &arn(ctx, "cidrcollection", &input.id))?;
        let mut st = self.lock();
        if !st.collection(&input.id)?.locations.is_empty() {
            return Err(errors::cidr_collection_in_use(
                "This CIDR collection is in use, and isn't empty. Delete all CIDR blocks before deleting the collection.",
            ));
        }
        st.cidr_collections.remove(&input.id);
        Ok(types::DeleteCidrCollectionResponse {})
    }

    pub(crate) fn list_cidr_collections(
        &self,
        ctx: &RequestContext,
        input: types::ListCidrCollectionsRequest,
    ) -> Result<types::ListCidrCollectionsResponse, ServiceError> {
        self.authorize(ctx, "ListCidrCollections", "*")?;
        let limit = max_items(input.max_results, 100, 100);
        let start = page_start(input.next_token.as_deref())?;
        let st = self.lock();
        let mut all: Vec<&CidrCollection> = st.cidr_collections.values().collect();
        all.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(types::ListCidrCollectionsResponse {
            cidr_collections: Some(all.iter().skip(start).take(limit).map(|c| c.summary(ctx)).collect()),
            next_token: (start + limit < all.len()).then(|| (start + limit).to_string()),
        })
    }

    pub(crate) fn list_cidr_locations(
        &self,
        ctx: &RequestContext,
        input: types::ListCidrLocationsRequest,
    ) -> Result<types::ListCidrLocationsResponse, ServiceError> {
        self.authorize(ctx, "ListCidrLocations", &arn(ctx, "cidrcollection", &input.collection_id))?;
        let limit = max_items(input.max_results, 100, 100);
        let start = page_start(input.next_token.as_deref())?;
        let st = self.lock();
        let c = st.collection(&input.collection_id)?;
        let names: Vec<&String> = c.locations.keys().collect();
        Ok(types::ListCidrLocationsResponse {
            cidr_locations: Some(
                names
                    .iter()
                    .skip(start)
                    .take(limit)
                    .map(|n| types::LocationSummary { location_name: Some((*n).clone()) })
                    .collect(),
            ),
            next_token: (start + limit < names.len()).then(|| (start + limit).to_string()),
        })
    }

    pub(crate) fn list_cidr_blocks(
        &self,
        ctx: &RequestContext,
        input: types::ListCidrBlocksRequest,
    ) -> Result<types::ListCidrBlocksResponse, ServiceError> {
        self.authorize(ctx, "ListCidrBlocks", &arn(ctx, "cidrcollection", &input.collection_id))?;
        let limit = max_items(input.max_results, 100, 100);
        let start = page_start(input.next_token.as_deref())?;
        let st = self.lock();
        let c = st.collection(&input.collection_id)?;
        if let Some(l) = &input.location_name {
            if !c.locations.contains_key(l) {
                return Err(errors::no_such_cidr_location(format!("The CIDR collection location {l} does not exist.")));
            }
        }
        let blocks: Vec<types::CidrBlockSummary> = c
            .locations
            .iter()
            .filter(|(l, _)| input.location_name.as_ref().is_none_or(|want| want == *l))
            .flat_map(|(l, set)| {
                set.iter().map(move |b| types::CidrBlockSummary {
                    cidr_block: Some(b.clone()),
                    location_name: Some(l.clone()),
                })
            })
            .collect();
        Ok(types::ListCidrBlocksResponse {
            next_token: (start + limit < blocks.len()).then(|| (start + limit).to_string()),
            cidr_blocks: Some(blocks.into_iter().skip(start).take(limit).collect()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::parse_cidr;

    #[test]
    fn cidrs_are_checked() {
        assert_eq!(parse_cidr("192.0.2.0/24").unwrap(), "192.0.2.0/24");
        assert_eq!(parse_cidr("2001:db8::/48").unwrap(), "2001:db8::/48");
        assert!(parse_cidr("192.0.2.1/24").is_err());
        assert!(parse_cidr("192.0.2.0/28").is_err());
        assert!(parse_cidr("nope").is_err());
    }
}
