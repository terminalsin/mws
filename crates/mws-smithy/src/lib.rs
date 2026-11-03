//! A small reader for Smithy JSON AST models.
//!
//! AWS publishes every service model in this format
//! (<https://github.com/aws/api-models-aws>). This crate resolves shape ids,
//! the Smithy prelude, and the traits code generation needs. It has no
//! knowledge of any particular service or protocol.
//!
//! Spec: <https://smithy.io/2.0/spec/json-ast.html>

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{Map, Value};

pub type Traits = Map<String, Value>;

#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("reading model: {0}")]
    Io(#[from] std::io::Error),
    #[error("parsing model JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid model: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShapeType {
    Blob,
    Boolean,
    String,
    Enum,
    Byte,
    Short,
    Integer,
    IntEnum,
    Long,
    Float,
    Double,
    BigInteger,
    BigDecimal,
    Timestamp,
    Document,
    List,
    Set,
    Map,
    Structure,
    Union,
    Operation,
    Service,
    Resource,
}

impl ShapeType {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "blob" => Self::Blob,
            "boolean" => Self::Boolean,
            "string" => Self::String,
            "enum" => Self::Enum,
            "byte" => Self::Byte,
            "short" => Self::Short,
            "integer" => Self::Integer,
            "intEnum" => Self::IntEnum,
            "long" => Self::Long,
            "float" => Self::Float,
            "double" => Self::Double,
            "bigInteger" => Self::BigInteger,
            "bigDecimal" => Self::BigDecimal,
            "timestamp" => Self::Timestamp,
            "document" => Self::Document,
            "list" => Self::List,
            "set" => Self::Set,
            "map" => Self::Map,
            "structure" => Self::Structure,
            "union" => Self::Union,
            "operation" => Self::Operation,
            "service" => Self::Service,
            "resource" => Self::Resource,
            _ => return None,
        })
    }

    /// Scalar shapes that serialize as a single value.
    pub fn is_simple(self) -> bool {
        !matches!(
            self,
            Self::List
                | Self::Set
                | Self::Map
                | Self::Structure
                | Self::Union
                | Self::Operation
                | Self::Service
                | Self::Resource
        )
    }
}

#[derive(Debug, Clone)]
pub struct Member {
    pub name: String,
    pub target: String,
    pub traits: Traits,
}

impl Member {
    pub fn has_trait(&self, name: &str) -> bool {
        self.traits.contains_key(&qualify_trait(name))
    }
    pub fn get_trait(&self, name: &str) -> Option<&Value> {
        self.traits.get(&qualify_trait(name))
    }
}

#[derive(Debug, Clone)]
pub struct Shape {
    pub id: String,
    pub ty: ShapeType,
    pub traits: Traits,
    /// Structure, union and enum members, in model order.
    pub members: Vec<Member>,
    /// List element.
    pub member: Option<Member>,
    /// Map key and value.
    pub key: Option<Member>,
    pub value: Option<Member>,
    /// Operation input/output (absent means `smithy.api#Unit`).
    pub input: Option<String>,
    pub output: Option<String>,
    pub errors: Vec<String>,
    /// Service and resource children.
    pub operations: Vec<String>,
    pub resources: Vec<String>,
    pub version: Option<String>,
}

impl Shape {
    /// The part after `#`.
    pub fn name(&self) -> &str {
        local_name(&self.id)
    }
    pub fn has_trait(&self, name: &str) -> bool {
        self.traits.contains_key(&qualify_trait(name))
    }
    pub fn get_trait(&self, name: &str) -> Option<&Value> {
        self.traits.get(&qualify_trait(name))
    }
}

/// `length` / `range` constraint bounds.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Bounds {
    pub min: Option<f64>,
    pub max: Option<f64>,
}

impl Bounds {
    pub fn from_trait(v: Option<&Value>) -> Option<Self> {
        let v = v?;
        Some(Self { min: v.get("min").and_then(Value::as_f64), max: v.get("max").and_then(Value::as_f64) })
    }
}

pub fn local_name(id: &str) -> &str {
    id.rsplit_once('#').map(|(_, n)| n).unwrap_or(id)
}

/// Trait names without a namespace are taken to be in `smithy.api`.
fn qualify_trait(name: &str) -> String {
    if name.contains('#') {
        name.to_string()
    } else {
        format!("smithy.api#{name}")
    }
}

#[derive(Debug, Clone)]
pub struct Model {
    shapes: BTreeMap<String, Shape>,
}

impl Model {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ModelError> {
        let text = std::fs::read_to_string(path)?;
        Self::parse(&text)
    }

    pub fn parse(json: &str) -> Result<Self, ModelError> {
        let root: Value = serde_json::from_str(json)?;
        let shapes = root
            .get("shapes")
            .and_then(Value::as_object)
            .ok_or_else(|| ModelError::Invalid("missing `shapes`".into()))?;
        let mut out = BTreeMap::new();
        for (id, v) in shapes {
            out.insert(id.clone(), parse_shape(id, v)?);
        }
        let mut model = Self { shapes: out };
        model.add_prelude();
        Ok(model)
    }

    pub fn shape(&self, id: &str) -> Option<&Shape> {
        self.shapes.get(id)
    }

    /// Like [`Model::shape`], but panics with a useful message. For codegen.
    pub fn expect(&self, id: &str) -> &Shape {
        self.shape(id).unwrap_or_else(|| panic!("shape `{id}` is not in the model"))
    }

    pub fn shapes(&self) -> impl Iterator<Item = &Shape> {
        self.shapes.values()
    }

    /// The single service shape in a per-service AWS model.
    pub fn service(&self) -> Result<&Shape, ModelError> {
        let mut services = self.shapes.values().filter(|s| s.ty == ShapeType::Service);
        let svc = services.next().ok_or_else(|| ModelError::Invalid("no service shape".into()))?;
        if services.next().is_some() {
            return Err(ModelError::Invalid("more than one service shape".into()));
        }
        Ok(svc)
    }

    /// Every operation bound to the service, directly or through resources,
    /// sorted by name.
    pub fn operations(&self, service: &Shape) -> Vec<&Shape> {
        let mut ids = Vec::new();
        let mut stack: Vec<&Shape> = vec![service];
        while let Some(s) = stack.pop() {
            ids.extend(s.operations.iter().cloned());
            for r in &s.resources {
                stack.push(self.expect(r));
            }
        }
        let mut ops: Vec<&Shape> = ids.iter().map(|id| self.expect(id)).collect();
        ops.sort_by(|a, b| a.name().cmp(b.name()));
        ops.dedup_by(|a, b| a.id == b.id);
        ops
    }

    fn add_prelude(&mut self) {
        let prelude = [
            ("String", ShapeType::String),
            ("Blob", ShapeType::Blob),
            ("BigInteger", ShapeType::BigInteger),
            ("BigDecimal", ShapeType::BigDecimal),
            ("Timestamp", ShapeType::Timestamp),
            ("Document", ShapeType::Document),
            ("Boolean", ShapeType::Boolean),
            ("PrimitiveBoolean", ShapeType::Boolean),
            ("Byte", ShapeType::Byte),
            ("PrimitiveByte", ShapeType::Byte),
            ("Short", ShapeType::Short),
            ("PrimitiveShort", ShapeType::Short),
            ("Integer", ShapeType::Integer),
            ("PrimitiveInteger", ShapeType::Integer),
            ("Long", ShapeType::Long),
            ("PrimitiveLong", ShapeType::Long),
            ("Float", ShapeType::Float),
            ("PrimitiveFloat", ShapeType::Float),
            ("Double", ShapeType::Double),
            ("PrimitiveDouble", ShapeType::Double),
            ("Unit", ShapeType::Structure),
        ];
        for (name, ty) in prelude {
            let id = format!("smithy.api#{name}");
            self.shapes.entry(id.clone()).or_insert_with(|| Shape {
                id,
                ty,
                traits: Traits::new(),
                members: vec![],
                member: None,
                key: None,
                value: None,
                input: None,
                output: None,
                errors: vec![],
                operations: vec![],
                resources: vec![],
                version: None,
            });
        }
    }
}

pub const UNIT: &str = "smithy.api#Unit";

fn parse_shape(id: &str, v: &Value) -> Result<Shape, ModelError> {
    let ty_str = v.get("type").and_then(Value::as_str).unwrap_or_default();
    let ty =
        ShapeType::parse(ty_str).ok_or_else(|| ModelError::Invalid(format!("{id}: unknown shape type `{ty_str}`")))?;
    let traits = v.get("traits").and_then(Value::as_object).cloned().unwrap_or_default();
    let members = v
        .get("members")
        .and_then(Value::as_object)
        .map(|m| m.iter().map(|(name, mv)| parse_member(name, mv)).collect())
        .unwrap_or_default();
    let target = |key: &str| v.get(key).and_then(|t| t.get("target")).and_then(Value::as_str).map(str::to_string);
    let targets = |key: &str| {
        v.get(key)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|t| t.get("target").and_then(Value::as_str).map(str::to_string)).collect())
            .unwrap_or_default()
    };
    Ok(Shape {
        id: id.to_string(),
        ty,
        traits,
        members,
        member: v.get("member").map(|m| parse_member("member", m)),
        key: v.get("key").map(|m| parse_member("key", m)),
        value: v.get("value").map(|m| parse_member("value", m)),
        input: target("input").filter(|t| t != UNIT),
        output: target("output").filter(|t| t != UNIT),
        errors: targets("errors"),
        // Resources also bind operations through lifecycle members and
        // `collectionOperations`.
        operations: {
            let mut ops: Vec<String> = targets("operations");
            ops.extend(targets("collectionOperations"));
            for key in ["create", "put", "read", "update", "delete", "list"] {
                ops.extend(target(key));
            }
            ops
        },
        resources: targets("resources"),
        version: v.get("version").and_then(Value::as_str).map(str::to_string),
    })
}

fn parse_member(name: &str, v: &Value) -> Member {
    Member {
        name: name.to_string(),
        target: v.get("target").and_then(Value::as_str).unwrap_or_default().to_string(),
        traits: v.get("traits").and_then(Value::as_object).cloned().unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODEL: &str = r##"{
      "smithy": "2.0",
      "shapes": {
        "ex#Svc": {"type": "service", "version": "2020-01-01", "operations": [{"target": "ex#B"}, {"target": "ex#A"}],
                   "traits": {"aws.protocols#awsQuery": {}, "smithy.api#xmlNamespace": {"uri": "https://ex/"}}},
        "ex#A": {"type": "operation", "input": {"target": "ex#AIn"}, "output": {"target": "smithy.api#Unit"}},
        "ex#B": {"type": "operation", "errors": [{"target": "ex#Oops"}]},
        "ex#AIn": {"type": "structure", "members": {"Z": {"target": "smithy.api#String", "traits": {"smithy.api#required": {}}}, "A": {"target": "ex#Names"}}},
        "ex#Names": {"type": "list", "member": {"target": "smithy.api#String"}, "traits": {"smithy.api#length": {"min": 1, "max": 3}}},
        "ex#Oops": {"type": "structure", "members": {}, "traits": {"smithy.api#error": "client"}}
      }
    }"##;

    #[test]
    fn loads_service_operations_and_members() {
        let m = Model::parse(MODEL).unwrap();
        let svc = m.service().unwrap();
        assert_eq!(svc.version.as_deref(), Some("2020-01-01"));
        assert!(svc.has_trait("aws.protocols#awsQuery"));
        let ops: Vec<_> = m.operations(svc).iter().map(|o| o.name().to_string()).collect();
        assert_eq!(ops, ["A", "B"]);
        let a = m.expect("ex#A");
        assert_eq!(a.input.as_deref(), Some("ex#AIn"));
        assert_eq!(a.output, None, "Unit output is treated as no output");
        let input = m.expect("ex#AIn");
        assert_eq!(
            input.members.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(),
            ["Z", "A"],
            "member order is preserved"
        );
        assert!(input.members[0].has_trait("required"));
        let names = m.expect("ex#Names");
        assert_eq!(Bounds::from_trait(names.get_trait("length")), Some(Bounds { min: Some(1.0), max: Some(3.0) }));
        assert_eq!(m.expect("ex#B").errors, ["ex#Oops"]);
        assert_eq!(m.expect("smithy.api#PrimitiveBoolean").ty, ShapeType::Boolean);
    }
}
