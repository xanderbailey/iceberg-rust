// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//! UTC timestamp timezone coercion for Arrow schemas.
//!
//! Arrow engines may produce timestamps with timezone "UTC" while Iceberg's
//! canonical Arrow schema uses "+00:00". This module walks a source schema with
//! an [`ArrowSchemaVisitor`] and produces a coerced schema where UTC-equivalent
//! timezones are normalized to match the target, so callers can then cast the
//! data with their own machinery. This follows the same pattern as
//! [`crate::arrow::int96`].

use std::sync::Arc;

use arrow_schema::{
    DataType, Field, FieldRef, Fields, Schema as ArrowSchema, SchemaRef as ArrowSchemaRef,
};

use crate::arrow::schema::{ArrowSchemaVisitor, DEFAULT_MAP_FIELD_NAME, visit_schema};
use crate::{Error, ErrorKind, Result};

/// Returns `source_schema` with timestamp fields whose only difference from the matching field
/// in `target_schema` is a UTC-equivalent timezone alias (e.g. "UTC" vs "+00:00") relabelled to
/// the target's timezone. All other fields — including genuine type differences such as `Int32`
/// vs `Int64` — are left unchanged. Recurses through struct, list, and map types.
///
/// This produces the coerced schema without any data, so callers can apply the actual cast with
/// their own machinery (e.g. DataFusion's `BatchAdapter`) or advertise it as an execution plan
/// node's output schema.
pub fn coerce_timestamp_tz_schema(
    source_schema: &ArrowSchemaRef,
    target_schema: &ArrowSchemaRef,
) -> Result<ArrowSchemaRef> {
    let mut visitor = TimestampTzCoercionVisitor::new(target_schema);
    let coerced = visit_schema(source_schema, &mut visitor)?;
    // If no field was relabelled, every subtree returned its original `Arc` unchanged, so
    // hand back the source schema as-is rather than allocating an identical copy.
    Ok(if visitor.changed {
        Arc::new(coerced)
    } else {
        Arc::clone(source_schema)
    })
}

/// Visitor that walks the source (batch) schema and produces a coerced schema
/// where UTC-equivalent timestamp timezones are normalized to match the target.
///
/// For each primitive field, if the source has `Timestamp(unit, Some(tz))` and the
/// target has the same unit but a different UTC-equivalent timezone, we output
/// the target's timezone in the coerced schema.
struct TimestampTzCoercionVisitor<'a> {
    target_schema: &'a ArrowSchemaRef,
    field_stack: Vec<FieldRef>,
    /// The target type matching each field currently on the stack, borrowed from
    /// `target_schema` (no clone). `None` means the source field has no counterpart in the
    /// target — such fields are always left unchanged.
    target_field_stack: Vec<Option<&'a DataType>>,
    changed: bool,
}

impl<'a> TimestampTzCoercionVisitor<'a> {
    fn new(target_schema: &'a ArrowSchemaRef) -> Self {
        Self {
            target_schema,
            field_stack: Vec::new(),
            target_field_stack: Vec::new(),
            changed: false,
        }
    }

    fn current_target_type(&self) -> Option<&'a DataType> {
        self.target_field_stack.last().copied().flatten()
    }
}

impl ArrowSchemaVisitor for TimestampTzCoercionVisitor<'_> {
    // Returning the field as an `Arc` (rather than an owned `Field`) lets an unchanged subtree
    // hand back its original, shared field with no allocation and no metadata clone. Only a
    // subtree that actually contains a relabelled timestamp is rebuilt.
    type T = FieldRef;
    type U = ArrowSchema;

    fn before_field(&mut self, field: &FieldRef) -> Result<()> {
        self.field_stack.push(field.clone());

        let target_type = if self.target_field_stack.is_empty() {
            self.target_schema
                .field_with_name(field.name())
                .ok()
                .map(|f| f.data_type())
        } else {
            match self.current_target_type() {
                Some(DataType::Struct(fields)) => {
                    fields.find(field.name()).map(|(_, f)| f.data_type())
                }
                _ => None,
            }
        };
        self.target_field_stack.push(target_type);
        Ok(())
    }

    fn after_field(&mut self, _field: &FieldRef) -> Result<()> {
        self.field_stack.pop();
        self.target_field_stack.pop();
        Ok(())
    }

    fn before_list_element(&mut self, field: &FieldRef) -> Result<()> {
        self.field_stack.push(field.clone());
        let target_type = match self.current_target_type() {
            Some(DataType::List(f) | DataType::LargeList(f) | DataType::FixedSizeList(f, _)) => {
                Some(f.data_type())
            }
            _ => None,
        };
        self.target_field_stack.push(target_type);
        Ok(())
    }

    fn after_list_element(&mut self, _field: &FieldRef) -> Result<()> {
        self.field_stack.pop();
        self.target_field_stack.pop();
        Ok(())
    }

    fn before_map_key(&mut self, field: &FieldRef) -> Result<()> {
        self.field_stack.push(field.clone());
        let target_type = self.map_entry_target_type().map(|(key, _)| key);
        self.target_field_stack.push(target_type);
        Ok(())
    }

    fn after_map_key(&mut self, _field: &FieldRef) -> Result<()> {
        self.field_stack.pop();
        self.target_field_stack.pop();
        Ok(())
    }

    fn before_map_value(&mut self, field: &FieldRef) -> Result<()> {
        self.field_stack.push(field.clone());
        let target_type = self.map_entry_target_type().map(|(_, value)| value);
        self.target_field_stack.push(target_type);
        Ok(())
    }

    fn after_map_value(&mut self, _field: &FieldRef) -> Result<()> {
        self.field_stack.pop();
        self.target_field_stack.pop();
        Ok(())
    }

    fn schema(&mut self, schema: &ArrowSchema, values: Vec<FieldRef>) -> Result<ArrowSchema> {
        Ok(ArrowSchema::new_with_metadata(
            Fields::from(values),
            schema.metadata().clone(),
        ))
    }

    fn r#struct(&mut self, fields: &Fields, results: Vec<FieldRef>) -> Result<FieldRef> {
        let field_info = self
            .field_stack
            .last()
            .ok_or_else(|| Error::new(ErrorKind::Unexpected, "Field stack underflow in struct"))?;
        // If every child came back as the same `Arc` we handed in, nothing was relabelled and we
        // can return the field untouched.
        if fields_unchanged(fields, &results) {
            return Ok(field_info.clone());
        }
        Ok(rebuild_field(
            field_info,
            DataType::Struct(Fields::from(results)),
        ))
    }

    fn list(&mut self, list: &DataType, value: FieldRef) -> Result<FieldRef> {
        let field_info = self
            .field_stack
            .last()
            .ok_or_else(|| Error::new(ErrorKind::Unexpected, "Field stack underflow in list"))?;
        let list_type = match list {
            DataType::List(f) => {
                if Arc::ptr_eq(f, &value) {
                    return Ok(field_info.clone());
                }
                DataType::List(value)
            }
            DataType::LargeList(f) => {
                if Arc::ptr_eq(f, &value) {
                    return Ok(field_info.clone());
                }
                DataType::LargeList(value)
            }
            DataType::FixedSizeList(f, size) => {
                if Arc::ptr_eq(f, &value) {
                    return Ok(field_info.clone());
                }
                DataType::FixedSizeList(value, *size)
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::Unexpected,
                    format!("Expected list type, got {list}"),
                ));
            }
        };
        Ok(rebuild_field(field_info, list_type))
    }

    fn map(&mut self, map: &DataType, key_value: FieldRef, value: FieldRef) -> Result<FieldRef> {
        let field_info = self
            .field_stack
            .last()
            .ok_or_else(|| Error::new(ErrorKind::Unexpected, "Field stack underflow in map"))?;
        let (entries, sorted) = match map {
            DataType::Map(entries, sorted) => (entries, *sorted),
            _ => {
                return Err(Error::new(
                    ErrorKind::Unexpected,
                    format!("Expected map type, got {map}"),
                ));
            }
        };
        // Neither key nor value was relabelled: return the map field untouched.
        if let DataType::Struct(fields) = entries.data_type()
            && fields.len() == 2
            && Arc::ptr_eq(&fields[0], &key_value)
            && Arc::ptr_eq(&fields[1], &value)
        {
            return Ok(field_info.clone());
        }
        let struct_field = Field::new(
            DEFAULT_MAP_FIELD_NAME,
            DataType::Struct(Fields::from(vec![key_value, value])),
            false,
        );
        Ok(rebuild_field(
            field_info,
            DataType::Map(Arc::new(struct_field), sorted),
        ))
    }

    fn primitive(&mut self, p: &DataType) -> Result<FieldRef> {
        let field_info = self.field_stack.last().ok_or_else(|| {
            Error::new(ErrorKind::Unexpected, "Field stack underflow in primitive")
        })?;

        if let (
            DataType::Timestamp(unit, Some(src_tz)),
            Some(DataType::Timestamp(target_unit, Some(target_tz))),
        ) = (p, self.current_target_type())
            && unit == target_unit
            && src_tz != target_tz
            && is_utc(src_tz)
            && is_utc(target_tz)
        {
            self.changed = true;
            return Ok(rebuild_field(
                field_info,
                DataType::Timestamp(*unit, Some(target_tz.clone())),
            ));
        }

        // Unchanged: hand back the shared source field without allocating or cloning metadata.
        Ok(field_info.clone())
    }
}

impl<'a> TimestampTzCoercionVisitor<'a> {
    /// The (key, value) target types of the map currently on top of the target stack, if the
    /// current target is a well-formed map. Callers pick the entry they need.
    fn map_entry_target_type(&self) -> Option<(&'a DataType, &'a DataType)> {
        match self.current_target_type() {
            Some(DataType::Map(entries, _)) => match entries.data_type() {
                DataType::Struct(fields) if fields.len() == 2 => {
                    Some((fields[0].data_type(), fields[1].data_type()))
                }
                _ => None,
            },
            _ => None,
        }
    }
}

/// A subtree is unchanged iff every child field is the exact same `Arc` the visitor was handed.
fn fields_unchanged(original: &Fields, results: &[FieldRef]) -> bool {
    original.len() == results.len()
        && original
            .iter()
            .zip(results)
            .all(|(orig, result)| Arc::ptr_eq(orig, result))
}

/// Rebuild a field with a new data type, preserving its name, nullability, and metadata.
fn rebuild_field(field: &FieldRef, data_type: DataType) -> FieldRef {
    Arc::new(
        Field::new(field.name(), data_type, field.is_nullable())
            .with_metadata(field.metadata().clone()),
    )
}

fn is_utc(tz: &str) -> bool {
    matches!(tz, "UTC" | "+00:00")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arrow_schema::{DataType, Field, Fields, TimeUnit};

    use super::*;

    fn schema(fields: Vec<Field>) -> ArrowSchemaRef {
        Arc::new(arrow_schema::Schema::new(fields))
    }

    fn ts(unit: TimeUnit, tz: &str) -> DataType {
        DataType::Timestamp(unit, Some(tz.into()))
    }

    #[test]
    fn test_noop_when_matching() {
        let s = schema(vec![Field::new("x", DataType::Int32, false)]);
        let result = coerce_timestamp_tz_schema(&s, &s).unwrap();
        assert_eq!(result, s);
    }

    #[test]
    fn test_unchanged_schema_reuses_source_arc() {
        // When nothing is relabelled, the coerced schema should be the very same `Arc` as the
        // source — no reallocation of the schema, its fields, or their metadata.
        let source = schema(vec![
            Field::new("id", DataType::Int32, false),
            Field::new(
                "s",
                DataType::Struct(Fields::from(vec![Field::new(
                    "inner",
                    ts(TimeUnit::Microsecond, "UTC"),
                    true,
                )])),
                false,
            ),
        ]);
        // Target matches exactly, so no coercion happens.
        let result = coerce_timestamp_tz_schema(&source, &source).unwrap();
        assert!(
            Arc::ptr_eq(&result, &source),
            "unchanged schema must be returned without reallocation"
        );
    }

    #[test]
    fn test_only_changed_fields_are_reallocated() {
        // A schema with one coerced timestamp and one untouched field: the untouched field's
        // `Arc` must be preserved, while the coerced one is a fresh allocation.
        let untouched = Arc::new(Field::new("id", DataType::Int32, false));
        let source = Arc::new(arrow_schema::Schema::new(vec![
            Arc::clone(&untouched),
            Arc::new(Field::new("ts", ts(TimeUnit::Microsecond, "UTC"), true)),
        ]));
        let target = schema(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("ts", ts(TimeUnit::Microsecond, "+00:00"), true),
        ]);
        let result = coerce_timestamp_tz_schema(&source, &target).unwrap();

        assert!(
            Arc::ptr_eq(&result.fields()[0], &untouched),
            "untouched field must keep its original Arc"
        );
        assert_eq!(
            result.fields()[1].data_type(),
            &ts(TimeUnit::Microsecond, "+00:00")
        );
    }

    #[test]
    fn test_passes_through_non_utc_mismatches() {
        // A genuine type difference (Int32 vs Utf8) must be left as-is, not cast.
        let source = schema(vec![Field::new("x", DataType::Int32, false)]);
        let target = schema(vec![Field::new("x", DataType::Utf8, false)]);
        let result = coerce_timestamp_tz_schema(&source, &target).unwrap();
        assert_eq!(result, source);
    }

    #[test]
    fn test_coerce_utc_to_plus_zero() {
        let source = schema(vec![Field::new(
            "ts",
            ts(TimeUnit::Microsecond, "UTC"),
            true,
        )]);
        let target = schema(vec![Field::new(
            "ts",
            ts(TimeUnit::Microsecond, "+00:00"),
            true,
        )]);
        let result = coerce_timestamp_tz_schema(&source, &target).unwrap();
        assert_eq!(result, target);
    }

    #[test]
    fn test_coerce_plus_zero_to_utc() {
        let source = schema(vec![Field::new(
            "ts",
            ts(TimeUnit::Nanosecond, "+00:00"),
            true,
        )]);
        let target = schema(vec![Field::new(
            "ts",
            ts(TimeUnit::Nanosecond, "UTC"),
            true,
        )]);
        let result = coerce_timestamp_tz_schema(&source, &target).unwrap();
        assert_eq!(result, target);
    }

    #[test]
    fn test_no_coerce_different_units() {
        // Same UTC-equivalent timezone but different units: not a timezone-only difference,
        // so leave the source unchanged.
        let source = schema(vec![Field::new(
            "ts",
            ts(TimeUnit::Microsecond, "UTC"),
            true,
        )]);
        let target = schema(vec![Field::new(
            "ts",
            ts(TimeUnit::Nanosecond, "+00:00"),
            true,
        )]);
        let result = coerce_timestamp_tz_schema(&source, &target).unwrap();
        assert_eq!(result, source);
    }

    #[test]
    fn test_no_coerce_non_utc_timezone() {
        // "America/New_York" is not UTC-equivalent, so it must not be relabelled.
        let source = schema(vec![Field::new(
            "ts",
            ts(TimeUnit::Microsecond, "America/New_York"),
            true,
        )]);
        let target = schema(vec![Field::new(
            "ts",
            ts(TimeUnit::Microsecond, "+00:00"),
            true,
        )]);
        let result = coerce_timestamp_tz_schema(&source, &target).unwrap();
        assert_eq!(result, source);
    }

    #[test]
    fn test_coerce_timestamp_nested_in_struct() {
        let struct_field = |tz: &str| {
            Field::new(
                "s",
                DataType::Struct(Fields::from(vec![
                    Field::new("id", DataType::Int32, false),
                    Field::new("ts", ts(TimeUnit::Microsecond, tz), true),
                ])),
                false,
            )
        };
        let source = schema(vec![struct_field("UTC")]);
        let target = schema(vec![struct_field("+00:00")]);
        let result = coerce_timestamp_tz_schema(&source, &target).unwrap();
        assert_eq!(result, target);
    }

    #[test]
    fn test_coerce_timestamp_nested_in_list() {
        let list_field = |tz: &str| {
            Field::new(
                "ts_list",
                DataType::List(Arc::new(Field::new(
                    "item",
                    ts(TimeUnit::Microsecond, tz),
                    true,
                ))),
                false,
            )
        };
        let source = schema(vec![list_field("UTC")]);
        let target = schema(vec![list_field("+00:00")]);
        let result = coerce_timestamp_tz_schema(&source, &target).unwrap();
        assert_eq!(result, target);
    }
}
