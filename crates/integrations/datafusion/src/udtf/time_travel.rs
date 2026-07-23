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

//! A DataFusion user-defined table function (UDTF) for Iceberg time travel.
//!
//! Time travel is a *per-query* concern: a query either reads the current table
//! state or a specific historical snapshot. Modelling it as mutable state on a
//! long-lived [`IcebergTableProvider`] is awkward — the same registered table
//! would read one snapshot but write to another, and its advertised schema
//! (cached at construction from the *current* schema) would disagree with the
//! historical data being scanned.
//!
//! A UDTF sidesteps both problems. The snapshot is named at the call site:
//!
//! ```sql
//! SELECT * FROM iceberg_snapshot('db.orders', 3821550127947089009);
//! ```
//!
//! Each call resolves that snapshot fresh and returns an
//! [`IcebergStaticTableProvider`], which recomputes the Arrow schema *for that
//! snapshot* (honoring schema evolution) and is read-only by construction.
//!
//! # Registration
//!
//! ```ignore
//! let ctx = SessionContext::new();
//! ctx.register_udtf(
//!     "iceberg_snapshot",
//!     Arc::new(IcebergSnapshotFunction::new(catalog)),
//! );
//! ```

use std::sync::Arc;

use datafusion::catalog::{TableFunctionImpl, TableProvider};
use datafusion::common::{DataFusionError, ScalarValue, plan_datafusion_err, plan_err};
use datafusion::logical_expr::Expr;
use iceberg::{Catalog, NamespaceIdent, TableIdent};
use tokio::runtime::Handle;

use crate::error::to_datafusion_error;
use crate::table::IcebergStaticTableProvider;

/// A UDTF that reads a named Iceberg table pinned to a specific snapshot.
///
/// Invoked as `iceberg_snapshot('<namespace>.<table>', <snapshot_id>)`. The
/// namespace may be multi-level (dot-separated), e.g. `'a.b.orders'` resolves to
/// namespace `a.b` and table `orders`.
///
/// The function holds the [`Catalog`] used to resolve the table; the snapshot id
/// is supplied per call, so a single registration serves every snapshot of every
/// table in the catalog.
#[derive(Debug)]
pub struct IcebergSnapshotFunction {
    catalog: Arc<dyn Catalog>,
}

impl IcebergSnapshotFunction {
    /// Creates a new time-travel table function backed by `catalog`.
    pub fn new(catalog: Arc<dyn Catalog>) -> Self {
        Self { catalog }
    }

    /// Splits `"a.b.orders"` into the namespace `a.b` and table name `orders`.
    fn parse_table_ident(reference: &str) -> Result<TableIdent, DataFusionError> {
        let mut parts: Vec<&str> = reference.split('.').filter(|p| !p.is_empty()).collect();
        let name = parts.pop().ok_or_else(|| {
            plan_datafusion_err!("iceberg_snapshot: empty table reference '{reference}'")
        })?;
        if parts.is_empty() {
            return plan_err!(
                "iceberg_snapshot: table reference '{reference}' must be qualified with a namespace, e.g. 'namespace.table'"
            );
        }
        let namespace = NamespaceIdent::from_vec(parts.iter().map(|s| s.to_string()).collect())
            .map_err(to_datafusion_error)?;
        Ok(TableIdent::new(namespace, name.to_string()))
    }

    /// Resolves the two positional arguments: `(table_reference, snapshot_id)`.
    fn parse_args(args: &[Expr]) -> Result<(TableIdent, i64), DataFusionError> {
        let [table_arg, snapshot_arg] = args else {
            return plan_err!(
                "iceberg_snapshot expects exactly 2 arguments: (table_reference, snapshot_id), got {}",
                args.len()
            );
        };

        let reference = match table_arg {
            // single quotes -> Utf8 literal; double quotes -> parsed as a column
            Expr::Literal(ScalarValue::Utf8(Some(s)), _)
            | Expr::Literal(ScalarValue::LargeUtf8(Some(s)), _) => s.as_str(),
            Expr::Column(column) => column.name.as_str(),
            other => {
                return plan_err!(
                    "iceberg_snapshot: first argument must be a string table reference, got {other}"
                );
            }
        };

        let snapshot_id = match snapshot_arg {
            Expr::Literal(ScalarValue::Int64(Some(v)), _) => *v,
            Expr::Literal(ScalarValue::Int32(Some(v)), _) => *v as i64,
            Expr::Literal(ScalarValue::UInt64(Some(v)), _) => *v as i64,
            other => {
                return plan_err!(
                    "iceberg_snapshot: second argument must be an integer snapshot id, got {other}"
                );
            }
        };

        Ok((Self::parse_table_ident(reference)?, snapshot_id))
    }

    /// Loads the table and builds a snapshot-pinned static provider.
    ///
    /// Kept `async` so the resolution logic is testable directly; [`Self::call`]
    /// bridges it onto the synchronous [`TableFunctionImpl`] surface.
    async fn resolve(
        catalog: Arc<dyn Catalog>,
        table_ident: TableIdent,
        snapshot_id: i64,
    ) -> Result<Arc<dyn TableProvider>, DataFusionError> {
        let table = catalog
            .load_table(&table_ident)
            .await
            .map_err(to_datafusion_error)?;
        let provider = IcebergStaticTableProvider::try_new_from_table_snapshot(table, snapshot_id)
            .await
            .map_err(to_datafusion_error)?;
        Ok(Arc::new(provider) as Arc<dyn TableProvider>)
    }
}

impl TableFunctionImpl for IcebergSnapshotFunction {
    fn call(&self, args: &[Expr]) -> Result<Arc<dyn TableProvider>, DataFusionError> {
        let (table_ident, snapshot_id) = Self::parse_args(args)?;
        let catalog = self.catalog.clone();

        // `TableFunctionImpl::call` is synchronous, but resolving a table and its
        // per-snapshot schema is async. Planning always runs inside a Tokio
        // runtime here, so hand the resolution back to that runtime without
        // blocking a worker thread. This mirrors the async->sync bridge the
        // distributed (Ballista) codec needs at decode time.
        let fut = Self::resolve(catalog, table_ident, snapshot_id);
        tokio::task::block_in_place(|| Handle::current().block_on(fut))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use datafusion::assert_batches_sorted_eq;
    use datafusion::prelude::SessionContext;
    use iceberg::memory::{MEMORY_CATALOG_WAREHOUSE, MemoryCatalogBuilder};
    use iceberg::spec::{NestedField, PrimitiveType, Schema, Type};
    use iceberg::{CatalogBuilder, TableCreation};
    use tempfile::TempDir;

    use super::*;

    async fn test_catalog() -> (Arc<dyn Catalog>, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let warehouse = temp_dir.path().to_str().unwrap().to_string();
        let catalog = MemoryCatalogBuilder::default()
            .load(
                "memory",
                HashMap::from([(MEMORY_CATALOG_WAREHOUSE.to_string(), warehouse.clone())]),
            )
            .await
            .unwrap();

        let namespace = NamespaceIdent::new("db".to_string());
        catalog
            .create_namespace(&namespace, HashMap::new())
            .await
            .unwrap();

        let schema = Schema::builder()
            .with_schema_id(0)
            .with_fields(vec![
                NestedField::required(1, "id", Type::Primitive(PrimitiveType::Int)).into(),
                NestedField::required(2, "name", Type::Primitive(PrimitiveType::String)).into(),
            ])
            .build()
            .unwrap();
        let creation = TableCreation::builder()
            .name("t".to_string())
            .location(format!("{warehouse}/t"))
            .schema(schema)
            .properties(HashMap::new())
            .build();
        catalog.create_table(&namespace, creation).await.unwrap();

        (Arc::new(catalog), temp_dir)
    }

    #[test]
    fn parse_table_ident_requires_namespace() {
        assert!(IcebergSnapshotFunction::parse_table_ident("orders").is_err());

        let ident = IcebergSnapshotFunction::parse_table_ident("a.b.orders").unwrap();
        assert_eq!(ident.name(), "orders");
        assert_eq!(ident.namespace().as_ref(), &[
            "a".to_string(),
            "b".to_string()
        ]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn iceberg_snapshot_time_travels_per_query() {
        let (catalog, _tmp) = test_catalog().await;
        let table_ident = TableIdent::new(NamespaceIdent::new("db".to_string()), "t".to_string());

        // Register the catalog-backed provider once; write two snapshots through it.
        let provider = crate::table::IcebergTableProvider::try_new(
            catalog.clone(),
            NamespaceIdent::new("db".to_string()),
            "t".to_string(),
        )
        .await
        .unwrap();

        let ctx = SessionContext::new();
        ctx.register_table("t", Arc::new(provider)).unwrap();
        ctx.register_udtf(
            "iceberg_snapshot",
            Arc::new(IcebergSnapshotFunction::new(catalog.clone())),
        );

        ctx.sql("INSERT INTO t VALUES (1, 'a')")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        let first_snapshot = catalog
            .load_table(&table_ident)
            .await
            .unwrap()
            .metadata()
            .current_snapshot()
            .unwrap()
            .snapshot_id();

        ctx.sql("INSERT INTO t VALUES (2, 'b')")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();

        // The live registration reads current state: both rows.
        let current = ctx
            .sql("SELECT * FROM t")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        assert_batches_sorted_eq!(
            [
                "+----+------+",
                "| id | name |",
                "+----+------+",
                "| 1  | a    |",
                "| 2  | b    |",
                "+----+------+",
            ],
            &current
        );

        // The UDTF pins a snapshot for that query only — no mutation of the
        // registered table, and the very next query is back to current state.
        let historical = ctx
            .sql(&format!(
                "SELECT * FROM iceberg_snapshot('db.t', {first_snapshot})"
            ))
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        assert_batches_sorted_eq!(
            [
                "+----+------+",
                "| id | name |",
                "+----+------+",
                "| 1  | a    |",
                "+----+------+",
            ],
            &historical
        );

        // Registered table is untouched by the time-travel query.
        let after = ctx
            .sql("SELECT * FROM t")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        assert_batches_sorted_eq!(
            [
                "+----+------+",
                "| id | name |",
                "+----+------+",
                "| 1  | a    |",
                "| 2  | b    |",
                "+----+------+",
            ],
            &after
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn iceberg_snapshot_rejects_unknown_snapshot() {
        let (catalog, _tmp) = test_catalog().await;
        let ctx = SessionContext::new();
        ctx.register_udtf(
            "iceberg_snapshot",
            Arc::new(IcebergSnapshotFunction::new(catalog)),
        );
        let err = ctx
            .sql("SELECT * FROM iceberg_snapshot('db.t', 999)")
            .await
            .expect_err("unknown snapshot id should error");
        assert!(err.to_string().contains("999"), "got: {err}");
    }
}
