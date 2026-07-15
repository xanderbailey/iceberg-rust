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

//! Coercion of input batches to an Iceberg table's Arrow schema.

use std::fmt::{Debug, Formatter};
use std::sync::Arc;

use datafusion::arrow::datatypes::SchemaRef as ArrowSchemaRef;
use datafusion::common::Result as DFResult;
use datafusion::error::DataFusionError;
use datafusion::execution::{SendableRecordBatchStream, TaskContext};
use datafusion::physical_expr::EquivalenceProperties;
use datafusion::physical_expr_adapter::BatchAdapterFactory;
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, ExecutionPlanProperties, PlanProperties,
};
use futures::StreamExt;
use iceberg::arrow::coerce_timestamp_tz_schema;

use crate::to_datafusion_error;

/// An execution plan node that normalizes timestamp timezones to an Iceberg table's.
///
/// DataFusion emits timestamps labelled `"UTC"`, while the Iceberg spec normalizes
/// `timestamptz` to a `"+00:00"` offset. These are logically equal but not physically equal,
/// and downstream stages compare physical Arrow types (partition value calculation and the
/// Parquet writer both reject the mismatch), so we relabel up front.
///
/// The coercion is **timezone-only**: [`coerce_timestamp_tz_schema`] walks the input schema
/// (recursing through struct/list/map) and relabels only timestamp fields whose sole
/// difference from the table is a UTC-equivalent timezone alias. Every other column —
/// including a genuine type difference such as `Int32` where the table expects `Int64` — is
/// left unchanged, so such mismatches surface as real errors downstream rather than being
/// silently (and possibly lossily) cast here. That timezone-aligned schema is both the
/// node's advertised output and the target handed to DataFusion's [`BatchAdapterFactory`],
/// which builds the adapter once and applies it to every batch.
///
/// This node is deliberately opaque (not a `ProjectionExec`) so DataFusion's projection-fusion
/// optimizer will not merge it into a downstream projection and re-route consumers back to the
/// un-coerced source columns.
pub(crate) struct CoerceSchemaExec {
    input: Arc<dyn ExecutionPlan>,
    table_schema: ArrowSchemaRef,
    /// The schema this node advertises: the input schema with only UTC-equivalent timestamp
    /// timezones aligned to `table_schema`.
    output_schema: ArrowSchemaRef,
    plan_properties: Arc<PlanProperties>,
}

impl CoerceSchemaExec {
    /// Create a node that relabels `input`'s timestamp timezones to match `table_schema`.
    pub(crate) fn try_new(
        input: Arc<dyn ExecutionPlan>,
        table_schema: ArrowSchemaRef,
    ) -> DFResult<Self> {
        let output_schema = coerce_timestamp_tz_schema(&input.schema(), &table_schema)
            .map_err(to_datafusion_error)?;
        let plan_properties = Arc::new(PlanProperties::new(
            EquivalenceProperties::new(Arc::clone(&output_schema)),
            input.output_partitioning().clone(),
            EmissionType::Incremental,
            Boundedness::Bounded,
        ));
        Ok(Self {
            input,
            table_schema,
            output_schema,
            plan_properties,
        })
    }
}

impl Debug for CoerceSchemaExec {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "CoerceSchemaExec")
    }
}

impl DisplayAs for CoerceSchemaExec {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "CoerceSchemaExec")
    }
}

impl ExecutionPlan for CoerceSchemaExec {
    fn name(&self) -> &str {
        "CoerceSchemaExec"
    }

    fn properties(&self) -> &Arc<PlanProperties> {
        &self.plan_properties
    }

    fn maintains_input_order(&self) -> Vec<bool> {
        vec![true]
    }

    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        vec![&self.input]
    }

    fn with_new_children(
        self: Arc<Self>,
        children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> DFResult<Arc<dyn ExecutionPlan>> {
        if children.len() != 1 {
            return Err(DataFusionError::Internal(format!(
                "CoerceSchemaExec expects exactly one child, but provided {}",
                children.len()
            )));
        }
        Ok(Arc::new(CoerceSchemaExec::try_new(
            Arc::clone(&children[0]),
            Arc::clone(&self.table_schema),
        )?))
    }

    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> DFResult<SendableRecordBatchStream> {
        let input_stream = self.input.execute(partition, context)?;
        let output_schema = Arc::clone(&self.output_schema);

        // Build the adapter once from the stream schema; the target is the timezone-aligned
        // output schema.
        let adapter = BatchAdapterFactory::new(Arc::clone(&output_schema))
            .make_adapter(&input_stream.schema())?;
        let stream = input_stream.map(move |batch| adapter.adapt_batch(&batch?));

        Ok(Box::pin(RecordBatchStreamAdapter::new(
            output_schema,
            stream,
        )))
    }
}

#[cfg(test)]
mod tests {
    use datafusion::arrow::array::{Int32Array, RecordBatch, TimestampMicrosecondArray};
    use datafusion::arrow::datatypes::{DataType, Field, Schema as ArrowSchema, TimeUnit};
    use datafusion::catalog::memory::MemorySourceConfig;
    use datafusion::physical_plan::common::collect;
    use datafusion::prelude::SessionContext;

    use super::*;

    #[tokio::test]
    async fn coerces_utc_timestamp_to_plus_zero_offset() {
        // Source batch labelled "UTC" (as DataFusion emits it).
        let source_schema = Arc::new(ArrowSchema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new(
                "ts",
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                false,
            ),
        ]));
        let batch = RecordBatch::try_new(Arc::clone(&source_schema), vec![
            Arc::new(Int32Array::from(vec![1, 2])),
            Arc::new(TimestampMicrosecondArray::from(vec![0_i64, 1_000_000]).with_timezone("UTC")),
        ])
        .unwrap();

        let source =
            MemorySourceConfig::try_new_exec(&[vec![batch]], Arc::clone(&source_schema), None)
                .unwrap();

        // Target schema uses the Iceberg "+00:00" offset.
        let target_schema = Arc::new(ArrowSchema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new(
                "ts",
                DataType::Timestamp(TimeUnit::Microsecond, Some("+00:00".into())),
                false,
            ),
        ]));

        let exec = Arc::new(CoerceSchemaExec::try_new(source, Arc::clone(&target_schema)).unwrap());
        let ctx = SessionContext::new();
        let stream = exec.execute(0, ctx.task_ctx()).unwrap();
        let batches = collect(stream).await.unwrap();

        assert_eq!(batches.len(), 1);
        // The executed batch's actual array type is relabelled to "+00:00" (not just the
        // advertised schema), which is what downstream partition and write stages require.
        assert_eq!(
            batches[0]
                .schema()
                .field_with_name("ts")
                .unwrap()
                .data_type(),
            &DataType::Timestamp(TimeUnit::Microsecond, Some("+00:00".into()))
        );
        assert_eq!(
            batches[0]
                .column(0)
                .as_any()
                .downcast_ref::<Int32Array>()
                .unwrap()
                .values(),
            &[1, 2]
        );
    }

    #[tokio::test]
    async fn does_not_cast_int_to_long() {
        // Input column is Int32 while the table declares Int64. This is a genuine type
        // difference (not a timezone label), so the node must NOT silently widen it — the
        // column has to pass through as Int32 so the mismatch is caught downstream instead.
        let source_schema = Arc::new(ArrowSchema::new(vec![Field::new(
            "id",
            DataType::Int32,
            false,
        )]));
        let batch = RecordBatch::try_new(Arc::clone(&source_schema), vec![Arc::new(
            Int32Array::from(vec![1, 2]),
        )])
        .unwrap();
        let source =
            MemorySourceConfig::try_new_exec(&[vec![batch]], Arc::clone(&source_schema), None)
                .unwrap();

        let table_schema = Arc::new(ArrowSchema::new(vec![Field::new(
            "id",
            DataType::Int64,
            false,
        )]));

        let exec = Arc::new(CoerceSchemaExec::try_new(source, Arc::clone(&table_schema)).unwrap());

        // The node advertises the column unchanged (Int32), not the table's Int64.
        assert_eq!(
            exec.schema().field_with_name("id").unwrap().data_type(),
            &DataType::Int32,
            "int must not be widened to long by the coercion node"
        );

        let ctx = SessionContext::new();
        let stream = exec.execute(0, ctx.task_ctx()).unwrap();
        let batches = collect(stream).await.unwrap();

        // The executed batch is still Int32 — no silent widening happened.
        assert_eq!(
            batches[0]
                .schema()
                .field_with_name("id")
                .unwrap()
                .data_type(),
            &DataType::Int32,
            "int must not be silently cast to long"
        );
    }

    #[tokio::test]
    async fn coerces_timestamp_nested_in_struct() {
        use datafusion::arrow::array::StructArray;
        use datafusion::arrow::datatypes::Fields;

        // A "UTC" timestamp nested inside a struct — the case the earlier flat (top-level
        // only) implementation missed; the schema visitor recurses into it.
        let ts_field_utc = Field::new(
            "ts",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            false,
        );
        let source_struct = DataType::Struct(Fields::from(vec![
            Field::new("id", DataType::Int32, false),
            ts_field_utc.clone(),
        ]));
        let source_schema = Arc::new(ArrowSchema::new(vec![Field::new(
            "s",
            source_struct.clone(),
            false,
        )]));

        let struct_array = StructArray::from(vec![
            (
                Arc::new(Field::new("id", DataType::Int32, false)),
                Arc::new(Int32Array::from(vec![1, 2])) as _,
            ),
            (
                Arc::new(ts_field_utc),
                Arc::new(
                    TimestampMicrosecondArray::from(vec![0_i64, 1_000_000]).with_timezone("UTC"),
                ) as _,
            ),
        ]);
        let batch =
            RecordBatch::try_new(Arc::clone(&source_schema), vec![Arc::new(struct_array)]).unwrap();
        let source =
            MemorySourceConfig::try_new_exec(&[vec![batch]], Arc::clone(&source_schema), None)
                .unwrap();

        // Table declares the nested timestamp with the "+00:00" offset.
        let table_schema = Arc::new(ArrowSchema::new(vec![Field::new(
            "s",
            DataType::Struct(Fields::from(vec![
                Field::new("id", DataType::Int32, false),
                Field::new(
                    "ts",
                    DataType::Timestamp(TimeUnit::Microsecond, Some("+00:00".into())),
                    false,
                ),
            ])),
            false,
        )]));

        let exec = Arc::new(CoerceSchemaExec::try_new(source, Arc::clone(&table_schema)).unwrap());
        let ctx = SessionContext::new();
        let stream = exec.execute(0, ctx.task_ctx()).unwrap();
        let batches = collect(stream).await.unwrap();

        // The nested timestamp is relabelled to "+00:00" in the executed batch.
        let schema = batches[0].schema();
        let DataType::Struct(fields) = schema.field_with_name("s").unwrap().data_type() else {
            panic!("expected struct");
        };
        let (_, ts) = fields.find("ts").unwrap();
        assert_eq!(
            ts.data_type(),
            &DataType::Timestamp(TimeUnit::Microsecond, Some("+00:00".into()))
        );
    }
}
