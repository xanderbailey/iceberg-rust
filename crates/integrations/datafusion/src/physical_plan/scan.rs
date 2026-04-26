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

use std::any::Any;
use std::pin::Pin;
use std::sync::Arc;
use std::vec;

use datafusion::arrow::array::{
    ArrayRef, Int32Array, Int64Array, RecordBatch, StringArray,
};
use datafusion::arrow::datatypes::{
    DataType, Field, Schema as ArrowSchema, SchemaRef as ArrowSchemaRef,
};
use datafusion::error::Result as DFResult;
use datafusion::execution::{SendableRecordBatchStream, TaskContext};
use datafusion::physical_expr::EquivalenceProperties;
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{DisplayAs, ExecutionPlan, Partitioning, PlanProperties};
use datafusion::prelude::Expr;
use futures::{Stream, StreamExt, TryStreamExt};
use iceberg::arrow::ArrowReaderBuilder;
use iceberg::expr::Predicate;
use iceberg::scan::{ChangelogOperation, ChangelogScanTask, FileScanTask};
use iceberg::table::Table;

use super::expr_to_predicate::convert_filters_to_predicate;
use crate::to_datafusion_error;

/// Describes which snapshot(s) to scan.
#[derive(Debug, Clone)]
pub(crate) enum ScanRange {
    /// Scan the current (latest) snapshot.
    Latest,
    /// Scan a specific point-in-time snapshot.
    PointInTime(i64),
    /// Incremental append scan between two snapshots.
    Incremental {
        from: i64,
        to: Option<i64>,
        from_inclusive: bool,
    },
    /// Changelog scan between two snapshots.
    /// Returns data with extra columns: `_change_type`, `_change_ordinal`, `_commit_snapshot_id`.
    Changelog {
        from: i64,
        to: Option<i64>,
        from_inclusive: bool,
    },
}

/// Manages the scanning process of an Iceberg [`Table`], encapsulating the
/// necessary details and computed properties required for execution planning.
#[derive(Debug)]
pub struct IcebergTableScan {
    /// A table in the catalog.
    table: Table,
    /// Which snapshot(s) to scan.
    scan_range: ScanRange,
    /// Stores certain, often expensive to compute,
    /// plan properties used in query optimization.
    plan_properties: Arc<PlanProperties>,
    /// Projection column names, None means all columns
    projection: Option<Vec<String>>,
    /// Filters to apply to the table scan
    predicates: Option<Predicate>,
    /// Optional limit on the number of rows to return
    limit: Option<usize>,
}

impl IcebergTableScan {
    /// Creates a new [`IcebergTableScan`] object.
    pub(crate) fn new(
        table: Table,
        scan_range: ScanRange,
        schema: ArrowSchemaRef,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        limit: Option<usize>,
    ) -> Self {
        let output_schema = match projection {
            None => schema.clone(),
            Some(projection) => Arc::new(schema.project(projection).unwrap()),
        };
        let plan_properties = Self::compute_properties(output_schema.clone());
        let projection = get_column_names(schema.clone(), projection);
        let predicates = convert_filters_to_predicate(filters);

        Self {
            table,
            scan_range,
            plan_properties,
            projection,
            predicates,
            limit,
        }
    }

    pub fn table(&self) -> &Table {
        &self.table
    }

    #[cfg(test)]
    pub(crate) fn scan_range(&self) -> &ScanRange {
        &self.scan_range
    }

    pub fn projection(&self) -> Option<&[String]> {
        self.projection.as_deref()
    }

    pub fn predicates(&self) -> Option<&Predicate> {
        self.predicates.as_ref()
    }

    pub fn limit(&self) -> Option<usize> {
        self.limit
    }

    /// Computes [`PlanProperties`] used in query optimization.
    fn compute_properties(schema: ArrowSchemaRef) -> Arc<PlanProperties> {
        // TODO:
        // This is more or less a placeholder, to be replaced
        // once we support output-partitioning
        Arc::new(PlanProperties::new(
            EquivalenceProperties::new(schema),
            Partitioning::UnknownPartitioning(1),
            EmissionType::Incremental,
            Boundedness::Bounded,
        ))
    }
}

impl ExecutionPlan for IcebergTableScan {
    fn name(&self) -> &str {
        "IcebergTableScan"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan + 'static>> {
        vec![]
    }

    fn with_new_children(
        self: Arc<Self>,
        _children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> DFResult<Arc<dyn ExecutionPlan>> {
        Ok(self)
    }

    fn properties(&self) -> &Arc<PlanProperties> {
        &self.plan_properties
    }

    fn execute(
        &self,
        _partition: usize,
        _context: Arc<TaskContext>,
    ) -> DFResult<SendableRecordBatchStream> {
        let fut = get_batch_stream(
            self.table.clone(),
            self.scan_range.clone(),
            self.projection.clone(),
            self.predicates.clone(),
        );
        let stream = futures::stream::once(fut).try_flatten();

        // Apply limit if specified
        let limited_stream: Pin<Box<dyn Stream<Item = DFResult<RecordBatch>> + Send>> =
            if let Some(limit) = self.limit {
                let mut remaining = limit;
                Box::pin(stream.try_filter_map(move |batch| {
                    futures::future::ready(if remaining == 0 {
                        Ok(None)
                    } else if batch.num_rows() <= remaining {
                        remaining -= batch.num_rows();
                        Ok(Some(batch))
                    } else {
                        let limited_batch = batch.slice(0, remaining);
                        remaining = 0;
                        Ok(Some(limited_batch))
                    })
                }))
            } else {
                Box::pin(stream)
            };

        Ok(Box::pin(RecordBatchStreamAdapter::new(
            self.schema(),
            limited_stream,
        )))
    }
}

impl DisplayAs for IcebergTableScan {
    fn fmt_as(
        &self,
        _t: datafusion::physical_plan::DisplayFormatType,
        f: &mut std::fmt::Formatter,
    ) -> std::fmt::Result {
        write!(
            f,
            "IcebergTableScan projection:[{}] predicate:[{}]",
            self.projection
                .clone()
                .map_or(String::new(), |v| v.join(",")),
            self.predicates
                .clone()
                .map_or(String::from(""), |p| format!("{p}"))
        )
    }
}

/// Asynchronously retrieves a stream of [`RecordBatch`] instances
/// from a given table.
///
/// This function initializes a [`TableScan`], builds it,
/// and then converts it into a stream of Arrow [`RecordBatch`]es.
///
/// Supports regular scans, incremental scans, and changelog scans.
async fn get_batch_stream(
    table: Table,
    scan_range: ScanRange,
    column_names: Option<Vec<String>>,
    predicates: Option<Predicate>,
) -> DFResult<Pin<Box<dyn Stream<Item = DFResult<RecordBatch>> + Send>>> {
    // Apply column selection, predicates, and build a TableScan.
    macro_rules! configure_and_build {
        ($builder:expr) => {{
            let mut b = $builder;
            b = match column_names {
                Some(names) => b.select(names),
                None => b.select_all(),
            };
            if let Some(pred) = predicates {
                b = b.with_filter(pred);
            }
            b.build().map_err(to_datafusion_error)?
        }};
    }

    // Changelog scans use a different path — they produce ChangelogScanTasks
    // that need metadata columns appended.
    if let ScanRange::Changelog {
        from,
        to,
        from_inclusive,
    } = scan_range
    {
        return get_changelog_batch_stream(table, from, to, from_inclusive, column_names, predicates)
            .await;
    }

    let table_scan = match scan_range {
        ScanRange::Incremental {
            from,
            to,
            from_inclusive,
        } => {
            let scan_builder = if from_inclusive {
                table.incremental_append_scan_inclusive(from, to)
            } else {
                table.incremental_append_scan(from, to)
            };
            configure_and_build!(scan_builder)
        }
        ScanRange::Latest => configure_and_build!(table.scan()),
        ScanRange::PointInTime(snapshot_id) => {
            configure_and_build!(table.scan().snapshot_id(snapshot_id))
        }
        ScanRange::Changelog { .. } => unreachable!(),
    };

    let stream = table_scan
        .to_arrow()
        .await
        .map_err(to_datafusion_error)?
        .map_err(to_datafusion_error);
    Ok(Box::pin(stream))
}

/// Reads changelog tasks and appends metadata columns to each batch.
async fn get_changelog_batch_stream(
    table: Table,
    from: i64,
    to: Option<i64>,
    from_inclusive: bool,
    column_names: Option<Vec<String>>,
    predicates: Option<Predicate>,
) -> DFResult<Pin<Box<dyn Stream<Item = DFResult<RecordBatch>> + Send>>> {
    let mut builder = if from_inclusive {
        table.incremental_changelog_scan_inclusive(from, to)
    } else {
        table.incremental_changelog_scan(from, to)
    };

    // Filter out changelog metadata columns — they don't exist in the table schema
    // and are appended after reading the data files.
    let changelog_meta_cols = ["_change_type", "_change_ordinal", "_commit_snapshot_id"];
    builder = match column_names {
        Some(names) => {
            let data_names: Vec<String> = names
                .into_iter()
                .filter(|n| !changelog_meta_cols.contains(&n.as_str()))
                .collect();
            if data_names.is_empty() {
                builder.select_empty()
            } else {
                builder.select(data_names)
            }
        }
        None => builder.select_all(),
    };

    if let Some(pred) = predicates {
        builder = builder.with_filter(pred);
    }

    let changelog_scan = builder.build().map_err(to_datafusion_error)?;

    let tasks: Vec<ChangelogScanTask> = changelog_scan
        .plan_files()
        .await
        .map_err(to_datafusion_error)?
        .try_collect()
        .await
        .map_err(to_datafusion_error)?;

    let file_io = table.file_io().clone();

    // Process each task: read its data file, then append metadata columns.
    let stream = futures::stream::iter(tasks)
        .then(move |task| {
            let file_io = file_io.clone();
            async move {
                let operation = task.operation;
                let change_ordinal = task.change_ordinal;
                let commit_snapshot_id = task.commit_snapshot_id;

                // Convert to FileScanTask for reading.
                let file_scan_task = changelog_task_to_file_scan_task(task);
                let task_stream = Box::pin(futures::stream::once(async { Ok(file_scan_task) }));

                let reader = ArrowReaderBuilder::new(file_io)
                    .build()
                    .read(task_stream)
                    .map_err(to_datafusion_error)?;

                // Append metadata columns to each batch from this task.
                let batches: Vec<RecordBatch> = reader
                    .map_err(to_datafusion_error)
                    .and_then(move |batch| {
                        futures::future::ready(append_changelog_columns(
                            batch,
                            operation,
                            change_ordinal,
                            commit_snapshot_id,
                        ))
                    })
                    .try_collect()
                    .await?;

                Ok::<_, datafusion::error::DataFusionError>(futures::stream::iter(
                    batches.into_iter().map(Ok),
                ))
            }
        })
        .try_flatten();

    Ok(Box::pin(stream))
}

fn changelog_task_to_file_scan_task(task: ChangelogScanTask) -> FileScanTask {
    FileScanTask {
        data_file_path: task.data_file_path,
        data_file_format: task.data_file_format,
        file_size_in_bytes: task.file_size_in_bytes,
        start: task.start,
        length: task.length,
        record_count: task.record_count,
        schema: task.schema,
        project_field_ids: task.project_field_ids,
        predicate: task.predicate,
        deletes: vec![],
        partition: task.partition,
        partition_spec: task.partition_spec,
        name_mapping: None,
        case_sensitive: true,
    }
}

fn append_changelog_columns(
    batch: RecordBatch,
    operation: ChangelogOperation,
    change_ordinal: i32,
    commit_snapshot_id: i64,
) -> DFResult<RecordBatch> {
    let num_rows = batch.num_rows();

    let change_type_value = match operation {
        ChangelogOperation::Insert => "INSERT",
        ChangelogOperation::Delete => "DELETE",
    };

    let change_type_col: ArrayRef =
        Arc::new(StringArray::from(vec![change_type_value; num_rows]));
    let change_ordinal_col: ArrayRef =
        Arc::new(Int32Array::from(vec![change_ordinal; num_rows]));
    let commit_snapshot_col: ArrayRef =
        Arc::new(Int64Array::from(vec![commit_snapshot_id; num_rows]));

    let mut fields = batch.schema().fields().to_vec();
    fields.push(Arc::new(Field::new("_change_type", DataType::Utf8, false)));
    fields.push(Arc::new(Field::new(
        "_change_ordinal",
        DataType::Int32,
        false,
    )));
    fields.push(Arc::new(Field::new(
        "_commit_snapshot_id",
        DataType::Int64,
        false,
    )));

    let new_schema = Arc::new(ArrowSchema::new(fields));

    let mut columns = batch.columns().to_vec();
    columns.push(change_type_col);
    columns.push(change_ordinal_col);
    columns.push(commit_snapshot_col);

    RecordBatch::try_new(new_schema, columns).map_err(|e| {
        datafusion::error::DataFusionError::ArrowError(Box::new(e), None)
    })
}

/// Returns the Arrow schema for a changelog scan: the base table schema
/// plus `_change_type`, `_change_ordinal`, and `_commit_snapshot_id`.
pub(crate) fn changelog_schema(base_schema: &ArrowSchemaRef) -> ArrowSchemaRef {
    let mut fields = base_schema.fields().to_vec();
    fields.push(Arc::new(Field::new("_change_type", DataType::Utf8, false)));
    fields.push(Arc::new(Field::new(
        "_change_ordinal",
        DataType::Int32,
        false,
    )));
    fields.push(Arc::new(Field::new(
        "_commit_snapshot_id",
        DataType::Int64,
        false,
    )));
    Arc::new(ArrowSchema::new(fields))
}

fn get_column_names(
    schema: ArrowSchemaRef,
    projection: Option<&Vec<usize>>,
) -> Option<Vec<String>> {
    projection.map(|v| {
        v.iter()
            .map(|p| schema.field(*p).name().clone())
            .collect::<Vec<String>>()
    })
}
