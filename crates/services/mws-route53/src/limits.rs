//! Account and resource limits, health checker IP ranges, the geolocation
//! catalogue, `TestDNSAnswer` and hosted zone features.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::{arn, max_items, names, strip_id, Route53};

pub const MAX_HEALTH_CHECKS_BY_OWNER: i64 = 200;
pub const MAX_HOSTED_ZONES_BY_OWNER: i64 = 500;
pub const MAX_REUSABLE_DELEGATION_SETS_BY_OWNER: i64 = 100;
pub const MAX_TRAFFIC_POLICIES_BY_OWNER: i64 = 50;
pub const MAX_TRAFFIC_POLICY_INSTANCES_BY_OWNER: i64 = 5;
pub const MAX_RRSETS_BY_ZONE: i64 = 10_000;
pub const MAX_VPCS_ASSOCIATED_BY_ZONE: i64 = 300;
pub const MAX_ZONES_BY_REUSABLE_DELEGATION_SET: i64 = 100;
pub const MAX_VERSIONS_PER_TRAFFIC_POLICY: usize = 1000;

/// The IP ranges Route 53 health checkers use (`ROUTE53_HEALTHCHECKS` in
/// AWS's published ip-ranges.json).
const CHECKER_IP_RANGES: &[&str] = &[
    "15.177.0.0/18",
    "54.183.255.128/26",
    "54.228.16.0/26",
    "54.232.40.64/26",
    "54.241.32.64/26",
    "54.243.31.192/26",
    "54.244.52.192/26",
    "54.245.168.0/26",
    "54.248.220.0/26",
    "54.250.253.192/26",
    "54.251.31.128/26",
    "54.252.79.128/26",
    "54.252.254.192/26",
    "54.255.254.192/26",
    "107.23.255.0/26",
    "176.34.159.192/26",
    "177.71.207.128/26",
];

const CONTINENTS: &[(&str, &str)] = &[
    ("AF", "Africa"),
    ("AN", "Antarctica"),
    ("AS", "Asia"),
    ("EU", "Europe"),
    ("NA", "North America"),
    ("OC", "Oceania"),
    ("SA", "South America"),
];

const COUNTRIES: &str = "*:Default|AD:Andorra|AE:United Arab Emirates|AF:Afghanistan|AG:Antigua and Barbuda|AI:Anguilla|AL:Albania|AM:Armenia|AO:Angola|AQ:Antarctica|AR:Argentina|AS:American Samoa|AT:Austria|AU:Australia|AW:Aruba|AX:Åland|AZ:Azerbaijan|BA:Bosnia and Herzegovina|BB:Barbados|BD:Bangladesh|BE:Belgium|BF:Burkina Faso|BG:Bulgaria|BH:Bahrain|BI:Burundi|BJ:Benin|BL:Saint Barthélemy|BM:Bermuda|BN:Brunei|BO:Bolivia|BQ:Bonaire|BR:Brazil|BS:Bahamas|BT:Bhutan|BW:Botswana|BY:Belarus|BZ:Belize|CA:Canada|CC:Cocos [Keeling] Islands|CD:Congo|CF:Central African Republic|CG:Republic of the Congo|CH:Switzerland|CI:Ivory Coast|CK:Cook Islands|CL:Chile|CM:Cameroon|CN:China|CO:Colombia|CR:Costa Rica|CU:Cuba|CV:Cape Verde|CW:Curaçao|CX:Christmas Island|CY:Cyprus|CZ:Czechia|DE:Germany|DJ:Djibouti|DK:Denmark|DM:Dominica|DO:Dominican Republic|DZ:Algeria|EC:Ecuador|EE:Estonia|EG:Egypt|ER:Eritrea|ES:Spain|ET:Ethiopia|FI:Finland|FJ:Fiji|FK:Falkland Islands|FM:Federated States of Micronesia|FO:Faroe Islands|FR:France|GA:Gabon|GB:United Kingdom|GD:Grenada|GE:Georgia|GF:French Guiana|GG:Guernsey|GH:Ghana|GI:Gibraltar|GL:Greenland|GM:Gambia|GN:Guinea|GP:Guadeloupe|GQ:Equatorial Guinea|GR:Greece|GS:South Georgia and the South Sandwich Islands|GT:Guatemala|GU:Guam|GW:Guinea-Bissau|GY:Guyana|HK:Hong Kong|HN:Honduras|HR:Croatia|HT:Haiti|HU:Hungary|ID:Indonesia|IE:Ireland|IL:Israel|IM:Isle of Man|IN:India|IO:British Indian Ocean Territory|IQ:Iraq|IR:Iran|IS:Iceland|IT:Italy|JE:Jersey|JM:Jamaica|JO:Hashemite Kingdom of Jordan|JP:Japan|KE:Kenya|KG:Kyrgyzstan|KH:Cambodia|KI:Kiribati|KM:Comoros|KN:Saint Kitts and Nevis|KP:North Korea|KR:Republic of Korea|KW:Kuwait|KY:Cayman Islands|KZ:Kazakhstan|LA:Laos|LB:Lebanon|LC:Saint Lucia|LI:Liechtenstein|LK:Sri Lanka|LR:Liberia|LS:Lesotho|LT:Republic of Lithuania|LU:Luxembourg|LV:Latvia|LY:Libya|MA:Morocco|MC:Monaco|MD:Republic of Moldova|ME:Montenegro|MF:Saint Martin|MG:Madagascar|MH:Marshall Islands|MK:North Macedonia|ML:Mali|MM:Myanmar [Burma]|MN:Mongolia|MO:Macao|MP:Northern Mariana Islands|MQ:Martinique|MR:Mauritania|MS:Montserrat|MT:Malta|MU:Mauritius|MV:Maldives|MW:Malawi|MX:Mexico|MY:Malaysia|MZ:Mozambique|NA:Namibia|NC:New Caledonia|NE:Niger|NF:Norfolk Island|NG:Nigeria|NI:Nicaragua|NL:Netherlands|NO:Norway|NP:Nepal|NR:Nauru|NU:Niue|NZ:New Zealand|OM:Oman|PA:Panama|PE:Peru|PF:French Polynesia|PG:Papua New Guinea|PH:Philippines|PK:Pakistan|PL:Poland|PM:Saint Pierre and Miquelon|PN:Pitcairn Islands|PR:Puerto Rico|PS:Palestine|PT:Portugal|PW:Palau|PY:Paraguay|QA:Qatar|RE:Réunion|RO:Romania|RS:Serbia|RU:Russia|RW:Rwanda|SA:Saudi Arabia|SB:Solomon Islands|SC:Seychelles|SD:Sudan|SE:Sweden|SG:Singapore|SH:Saint Helena|SI:Slovenia|SJ:Svalbard and Jan Mayen|SK:Slovakia|SL:Sierra Leone|SM:San Marino|SN:Senegal|SO:Somalia|SR:Suriname|SS:South Sudan|ST:São Tomé and Príncipe|SV:El Salvador|SX:Sint Maarten|SY:Syria|SZ:Swaziland|TC:Turks and Caicos Islands|TD:Chad|TF:French Southern Territories|TG:Togo|TH:Thailand|TJ:Tajikistan|TK:Tokelau|TL:East Timor|TM:Turkmenistan|TN:Tunisia|TO:Tonga|TR:Turkey|TT:Trinidad and Tobago|TV:Tuvalu|TW:Taiwan|TZ:Tanzania|UA:Ukraine|UG:Uganda|UM:U.S. Minor Outlying Islands|US:United States|UY:Uruguay|UZ:Uzbekistan|VA:Vatican City|VC:Saint Vincent and the Grenadines|VE:Venezuela|VG:British Virgin Islands|VI:U.S. Virgin Islands|VN:Vietnam|VU:Vanuatu|WF:Wallis and Futuna|WS:Samoa|XK:Kosovo|YE:Yemen|YT:Mayotte|ZA:South Africa|ZM:Zambia|ZW:Zimbabwe";

const US_STATES: &str = "AK:Alaska|AL:Alabama|AR:Arkansas|AZ:Arizona|CA:California|CO:Colorado|CT:Connecticut|DE:Delaware|FL:Florida|GA:Georgia|HI:Hawaii|IA:Iowa|ID:Idaho|IL:Illinois|IN:Indiana|KS:Kansas|KY:Kentucky|LA:Louisiana|MA:Massachusetts|MD:Maryland|ME:Maine|MI:Michigan|MN:Minnesota|MO:Missouri|MS:Mississippi|MT:Montana|NC:North Carolina|ND:North Dakota|NE:Nebraska|NH:New Hampshire|NJ:New Jersey|NM:New Mexico|NV:Nevada|NY:New York|OH:Ohio|OK:Oklahoma|OR:Oregon|PA:Pennsylvania|RI:Rhode Island|SC:South Carolina|SD:South Dakota|TN:Tennessee|TX:Texas|UT:Utah|VA:Virginia|VT:Vermont|WA:Washington|WI:Wisconsin|WV:West Virginia|WY:Wyoming";

fn pairs(table: &'static str) -> impl Iterator<Item = (&'static str, &'static str)> {
    table.split('|').filter_map(|p| p.split_once(':'))
}

/// Every geolocation in Route 53's listing order: continents, then
/// countries, each followed by its subdivisions.
fn catalogue() -> Vec<types::GeoLocationDetails> {
    let mut out: Vec<types::GeoLocationDetails> = CONTINENTS
        .iter()
        .map(|(c, n)| types::GeoLocationDetails {
            continent_code: Some(c.to_string()),
            continent_name: Some(n.to_string()),
            ..Default::default()
        })
        .collect();
    for (code, name) in pairs(COUNTRIES) {
        out.push(types::GeoLocationDetails {
            country_code: Some(code.into()),
            country_name: Some(name.into()),
            ..Default::default()
        });
        if code == "US" {
            for (sub, sub_name) in pairs(US_STATES) {
                out.push(types::GeoLocationDetails {
                    country_code: Some(code.into()),
                    country_name: Some(name.into()),
                    subdivision_code: Some(sub.into()),
                    subdivision_name: Some(sub_name.into()),
                    ..Default::default()
                });
            }
        }
    }
    out
}

fn geo_key(g: &types::GeoLocationDetails) -> (Option<&str>, Option<&str>, Option<&str>) {
    (g.continent_code.as_deref(), g.country_code.as_deref(), g.subdivision_code.as_deref())
}

impl Route53 {
    pub(crate) fn get_account_limit(
        &self,
        ctx: &RequestContext,
        input: types::GetAccountLimitRequest,
    ) -> Result<types::GetAccountLimitResponse, ServiceError> {
        self.authorize(ctx, "GetAccountLimit", "*")?;
        let st = self.lock();
        let (value, count) = match input.r#type.as_str() {
            "MAX_HEALTH_CHECKS_BY_OWNER" => (MAX_HEALTH_CHECKS_BY_OWNER, st.health_checks.len()),
            "MAX_HOSTED_ZONES_BY_OWNER" => (MAX_HOSTED_ZONES_BY_OWNER, st.zones.len()),
            "MAX_REUSABLE_DELEGATION_SETS_BY_OWNER" => {
                (MAX_REUSABLE_DELEGATION_SETS_BY_OWNER, st.delegation_sets.len())
            }
            "MAX_TRAFFIC_POLICIES_BY_OWNER" => (MAX_TRAFFIC_POLICIES_BY_OWNER, st.traffic_policies.len()),
            "MAX_TRAFFIC_POLICY_INSTANCES_BY_OWNER" => {
                (MAX_TRAFFIC_POLICY_INSTANCES_BY_OWNER, st.traffic_policy_instances.len())
            }
            other => return Err(errors::invalid_input(format!("Invalid limit type: {other}"))),
        };
        Ok(types::GetAccountLimitResponse {
            limit: types::AccountLimit { r#type: input.r#type, value },
            count: count as i64,
        })
    }

    pub(crate) fn get_hosted_zone_limit(
        &self,
        ctx: &RequestContext,
        input: types::GetHostedZoneLimitRequest,
    ) -> Result<types::GetHostedZoneLimitResponse, ServiceError> {
        let id = strip_id(&input.hosted_zone_id);
        self.authorize(ctx, "GetHostedZoneLimit", &arn(ctx, "hostedzone", id))?;
        let st = self.lock();
        let zone = st.zone(id)?;
        let (value, count) = match input.r#type.as_str() {
            "MAX_RRSETS_BY_ZONE" => (MAX_RRSETS_BY_ZONE, zone.records.len()),
            "MAX_VPCS_ASSOCIATED_BY_ZONE" => {
                if !zone.private {
                    return Err(errors::hosted_zone_not_private(
                        "The specified hosted zone is a public hosted zone, not a private hosted zone.",
                    ));
                }
                (MAX_VPCS_ASSOCIATED_BY_ZONE, zone.vpcs.len())
            }
            other => return Err(errors::invalid_input(format!("Invalid limit type: {other}"))),
        };
        Ok(types::GetHostedZoneLimitResponse {
            limit: types::HostedZoneLimit { r#type: input.r#type, value },
            count: count as i64,
        })
    }

    pub(crate) fn get_checker_ip_ranges(
        &self,
        ctx: &RequestContext,
        _input: types::GetCheckerIpRangesRequest,
    ) -> Result<types::GetCheckerIpRangesResponse, ServiceError> {
        self.authorize(ctx, "GetCheckerIpRanges", "*")?;
        Ok(types::GetCheckerIpRangesResponse {
            checker_ip_ranges: CHECKER_IP_RANGES.iter().map(|s| s.to_string()).collect(),
        })
    }

    pub(crate) fn get_geo_location(
        &self,
        ctx: &RequestContext,
        input: types::GetGeoLocationRequest,
    ) -> Result<types::GetGeoLocationResponse, ServiceError> {
        self.authorize(ctx, "GetGeoLocation", "*")?;
        let wanted =
            (input.continent_code.as_deref(), input.country_code.as_deref(), input.subdivision_code.as_deref());
        match wanted {
            (None, None, _) => {
                return Err(errors::invalid_input(
                    "Invalid input: Either a ContinentCode or a CountryCode must be specified.",
                ))
            }
            (Some(_), Some(_), _) | (Some(_), None, Some(_)) => {
                return Err(errors::invalid_input(
                    "Invalid input: ContinentCode cannot be specified with CountryCode or SubdivisionCode.",
                ))
            }
            _ => {}
        }
        catalogue()
            .into_iter()
            .find(|g| geo_key(g) == wanted)
            .map(|geo_location_details| types::GetGeoLocationResponse { geo_location_details })
            .ok_or_else(|| errors::no_such_geo_location("The specified geo location does not exist."))
    }

    pub(crate) fn list_geo_locations(
        &self,
        ctx: &RequestContext,
        input: types::ListGeoLocationsRequest,
    ) -> Result<types::ListGeoLocationsResponse, ServiceError> {
        self.authorize(ctx, "ListGeoLocations", "*")?;
        let limit = max_items(input.max_items, 100, 100);
        let all = catalogue();
        let start = (
            input.start_continent_code.as_deref(),
            input.start_country_code.as_deref(),
            input.start_subdivision_code.as_deref(),
        );
        let from = match start {
            (None, None, None) => 0,
            _ => all
                .iter()
                .position(|g| geo_key(g) == start)
                .ok_or_else(|| errors::invalid_input("Invalid input: The start location does not exist."))?,
        };
        let rest = &all[from..];
        let next = rest.get(limit);
        Ok(types::ListGeoLocationsResponse {
            geo_location_details_list: rest.iter().take(limit).cloned().collect(),
            is_truncated: next.is_some(),
            next_continent_code: next.and_then(|g| g.continent_code.clone()),
            next_country_code: next.and_then(|g| g.country_code.clone()),
            next_subdivision_code: next.and_then(|g| g.subdivision_code.clone()),
            max_items: limit as i32,
        })
    }

    pub(crate) fn test_dns_answer(
        &self,
        ctx: &RequestContext,
        input: types::TestDNSAnswerRequest,
    ) -> Result<types::TestDNSAnswerResponse, ServiceError> {
        let id = strip_id(&input.hosted_zone_id);
        self.authorize(ctx, "TestDNSAnswer", "*")?;
        let st = self.lock();
        let zone = st.zone(id)?;
        if zone.private {
            return Err(errors::invalid_input("Invalid input: TestDNSAnswer only supports public hosted zones."));
        }
        let name = names::normalize(&input.record_name)
            .ok_or_else(|| errors::invalid_input(format!("{} is not a valid DNS name", input.record_name)))?;
        if !names::in_zone(&name, &zone.name) {
            return Err(errors::invalid_input(format!(
                "Invalid input: {} is not in the hosted zone {}",
                input.record_name,
                names::display(&zone.name)
            )));
        }
        let at_name: Vec<&types::ResourceRecordSet> = zone.records.values().filter(|r| r.name == name).collect();
        let mut data = Vec::new();
        for r in at_name.iter().filter(|r| r.r#type == input.record_type) {
            match &r.alias_target {
                Some(alias) => {
                    let target = names::normalize(&alias.dns_name).unwrap_or_default();
                    for (_, records) in st.zones.iter().map(|(k, z)| (k, &z.records)) {
                        for t in records.values().filter(|t| t.name == target && t.r#type == r.r#type) {
                            data.extend(t.resource_records.iter().flatten().map(|v| v.value.clone()));
                        }
                    }
                }
                None => data.extend(r.resource_records.iter().flatten().map(|v| v.value.clone())),
            }
        }
        let response_code = if at_name.is_empty() { "NXDOMAIN" } else { "NOERROR" };
        Ok(types::TestDNSAnswerResponse {
            nameserver: zone.name_servers.first().cloned().unwrap_or_default(),
            record_name: input.record_name,
            record_type: input.record_type,
            record_data: data,
            response_code: response_code.into(),
            protocol: "UDP".into(),
        })
    }

    pub(crate) fn update_hosted_zone_features(
        &self,
        ctx: &RequestContext,
        input: types::UpdateHostedZoneFeaturesRequest,
    ) -> Result<types::UpdateHostedZoneFeaturesResponse, ServiceError> {
        let id = strip_id(&input.hosted_zone_id);
        self.authorize(ctx, "UpdateHostedZoneFeatures", &arn(ctx, "hostedzone", id))?;
        let mut st = self.lock();
        let zone = st.zone_mut(id)?;
        if let Some(enable) = input.enable_accelerated_recovery {
            if zone.private {
                return Err(errors::invalid_input(
                    "Invalid input: Accelerated recovery is only supported for public hosted zones.",
                ));
            }
            zone.accelerated_recovery = enable;
        }
        Ok(types::UpdateHostedZoneFeaturesResponse {})
    }
}
