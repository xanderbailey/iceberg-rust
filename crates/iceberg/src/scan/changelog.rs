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

//! Changelog scan for reading inserted and deleted data between snapshots.

use std::sync::Arc;

use futures::channel::mpsc::{Sender, channel};
use futures::{SinkExt, StreamExt, TryStreamExt};

use crate::delete_file_index::DeleteFileIndex;
use crate::expr::visitors::inclusive_metrics_evaluator::InclusiveMetricsEvaluator;
use crate::runtime::spawn;
use crate::scan::context::{ManifestEntryContext, PlanContext};
use crate::scan::incremental::ChangelogSnapshotSet;
use crate::scan::task::{ChangelogOperation, ChangelogScanTask, ChangelogScanTaskStream};
use crate::spec::{DataContentType, ManifestContentType, ManifestStatus};
use crate::{Error, ErrorKind, Result};

/// A changelog scan that produces [`ChangelogScanTask`]s annotated with
/// INSERT/DELETE operations, ordinals, and commit snapshot IDs.
pub struct ChangelogScan {
    pub(crate) plan_context: Option<PlanContext>,
    pub(crate) changelog_set: Arc<ChangelogSnapshotSet>,
    pub(crate) concurrency_limit_manifest_files: usize,
    pub(crate) concurrency_limit_manifest_entries: usize,
}

impl std::fmt::Debug for ChangelogScan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChangelogScan")
            .field("plan_context", &self.plan_context)
            .field("changelog_set", &self.changelog_set)
            .finish_non_exhaustive()
    }
}

impl ChangelogScan {
    /// Returns a stream of [`ChangelogScanTask`]s.
    ///
    /// Each task represents a data file change (insertion or deletion) in
    /// the changelog range. Tasks carry an `operation`, `change_ordinal`,
    /// and `commit_snapshot_id`.
    ///
    /// Returns an error if any snapshot in the range has delete manifests,
    /// as delete files are not yet supported in changelog scans.
    pub async fn plan_files(&self) -> Result<ChangelogScanTaskStream> {
        let Some(plan_context) = self.plan_context.as_ref() else {
            return Ok(Box::pin(futures::stream::empty()));
        };

        let manifest_list = plan_context.get_manifest_list().await?;

        // Validate: no delete manifests in the changelog range.
        for manifest_file in manifest_list.entries() {
            if manifest_file.content == ManifestContentType::Deletes
                && self.changelog_set.contains(manifest_file.added_snapshot_id)
            {
                return Err(Error::new(
                    ErrorKind::FeatureUnsupported,
                    "Delete files are not supported in changelog scans",
                ));
            }
        }

        let concurrency_limit_manifest_files = self.concurrency_limit_manifest_files;
        let concurrency_limit_manifest_entries = self.concurrency_limit_manifest_entries;

        // Since we rejected delete manifests above, we only have data manifests.
        // Use a dummy delete channel that will never receive entries.
        let (manifest_entry_data_ctx_tx, manifest_entry_data_ctx_rx) =
            channel(concurrency_limit_manifest_files);
        let (manifest_entry_delete_ctx_tx, _manifest_entry_delete_ctx_rx) =
            channel::<ManifestEntryContext>(1);

        let (changelog_task_tx, changelog_task_rx) = channel(concurrency_limit_manifest_entries);

        let (delete_file_idx, _delete_file_tx) = DeleteFileIndex::new();

        let manifest_file_contexts = plan_context.build_manifest_file_contexts(
            manifest_list,
            manifest_entry_data_ctx_tx,
            delete_file_idx,
            manifest_entry_delete_ctx_tx,
        )?;

        let mut channel_for_manifest_error = changelog_task_tx.clone();

        // Concurrently load manifests and stream entries.
        spawn(async move {
            let result = futures::stream::iter(manifest_file_contexts)
                .try_for_each_concurrent(concurrency_limit_manifest_files, |ctx| async move {
                    ctx.fetch_manifest_and_stream_manifest_entries().await
                })
                .await;

            if let Err(error) = result {
                let _ = channel_for_manifest_error.send(Err(error)).await;
            }
        });

        // Process data manifest entries into ChangelogScanTasks.
        let changelog_set = self.changelog_set.clone();
        let mut channel_for_entry_error = changelog_task_tx.clone();

        spawn(async move {
            let result = manifest_entry_data_ctx_rx
                .map(|me_ctx| Ok((me_ctx, changelog_task_tx.clone(), changelog_set.clone())))
                .try_for_each_concurrent(
                    concurrency_limit_manifest_entries,
                    |(manifest_entry_context, tx, set)| async move {
                        spawn(async move {
                            Self::process_changelog_entry(manifest_entry_context, tx, &set).await
                        })
                        .await
                    },
                )
                .await;

            if let Err(error) = result {
                let _ = channel_for_entry_error.send(Err(error)).await;
            }
        });

        Ok(changelog_task_rx.boxed())
    }

    async fn process_changelog_entry(
        manifest_entry_context: ManifestEntryContext,
        mut changelog_task_tx: Sender<Result<ChangelogScanTask>>,
        changelog_set: &ChangelogSnapshotSet,
    ) -> Result<()> {
        // Unlike TableScan, do NOT skip DELETED entries — they represent deletions.

        if manifest_entry_context.manifest_entry.content_type() != DataContentType::Data {
            return Err(Error::new(
                ErrorKind::FeatureUnsupported,
                "Encountered an entry for a delete file in a data file manifest",
            ));
        }

        // Apply partition and metrics filtering (same as TableScan).
        if let Some(ref bound_predicates) = manifest_entry_context.bound_predicates {
            let crate::scan::BoundPredicates {
                snapshot_bound_predicate,
                partition_bound_predicate,
            } = bound_predicates.as_ref();

            let expression_evaluator = manifest_entry_context
                .expression_evaluator_cache
                .get(
                    manifest_entry_context.partition_spec_id,
                    partition_bound_predicate,
                )?;

            if !expression_evaluator.eval(manifest_entry_context.manifest_entry.data_file())? {
                return Ok(());
            }

            if !InclusiveMetricsEvaluator::eval(
                snapshot_bound_predicate,
                manifest_entry_context.manifest_entry.data_file(),
                false,
            )? {
                return Ok(());
            }
        }

        // Determine operation from manifest entry status.
        let operation = match manifest_entry_context.manifest_entry.status() {
            ManifestStatus::Added => ChangelogOperation::Insert,
            ManifestStatus::Deleted => ChangelogOperation::Delete,
            ManifestStatus::Existing => {
                // Should have been filtered out by manifest_entry_filter,
                // but skip defensively.
                return Ok(());
            }
        };

        let snapshot_id = manifest_entry_context
            .manifest_entry
            .snapshot_id()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::DataInvalid,
                    "Changelog entry missing snapshot_id",
                )
            })?;

        let change_ordinal = changelog_set.ordinal_for(snapshot_id);

        let entry = &manifest_entry_context.manifest_entry;
        let task = ChangelogScanTask {
            data_file_path: entry.file_path().to_string(),
            data_file_format: entry.file_format(),
            file_size_in_bytes: entry.file_size_in_bytes(),
            start: 0,
            length: entry.file_size_in_bytes(),
            record_count: Some(entry.record_count()),
            schema: manifest_entry_context.snapshot_schema,
            project_field_ids: manifest_entry_context.field_ids.to_vec(),
            predicate: manifest_entry_context
                .bound_predicates
                .map(|x| x.as_ref().snapshot_bound_predicate.clone()),
            partition: Some(entry.data_file.partition.clone()),
            partition_spec: None,
            operation,
            change_ordinal,
            commit_snapshot_id: snapshot_id,
        };

        changelog_task_tx.send(Ok(task)).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use futures::TryStreamExt;

    use super::*;
    use crate::scan::incremental::ChangelogSnapshotSet;
    use crate::scan::tests::TableTestFixture;

    #[test]
    fn test_changelog_scan_builds() {
        let table = TableTestFixture::new_with_deep_history().table;

        let s1_id = 3051729675574597004_i64;
        let result = table.incremental_changelog_scan(s1_id, None).build();
        assert!(result.is_ok(), "Changelog scan should build successfully");
    }

    #[test]
    fn test_changelog_scan_invalid_from_exclusive() {
        let table = TableTestFixture::new().table;

        let result = table.incremental_changelog_scan(999999999, None).build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not an ancestor"));
    }

    #[test]
    fn test_changelog_scan_invalid_from_inclusive() {
        let table = TableTestFixture::new().table;

        let result = table
            .incremental_changelog_scan_inclusive(999999999, None)
            .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_changelog_scan_empty_range() {
        let table = TableTestFixture::new().table;
        let current_id = table.metadata().current_snapshot().unwrap().snapshot_id();

        let result = table
            .incremental_changelog_scan(current_id, Some(current_id))
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_changelog_set_excludes_replace_includes_overwrite() {
        // Deep history: S1(append) -> S2(append) -> S3(append) -> S4(overwrite) -> S5(append)
        let table = TableTestFixture::new_with_deep_history().table;

        let s1_id = 3051729675574597004_i64;
        let s2_id = 3055729675574597004_i64;
        let s3_id = 3056729675574597004_i64;
        let s4_id = 3057729675574597004_i64; // overwrite
        let s5_id = 3059729675574597004_i64;

        let set =
            ChangelogSnapshotSet::build(&table.metadata_ref(), s1_id, s5_id, false).unwrap();

        // S1 is excluded (from-snapshot, exclusive)
        assert!(!set.contains(s1_id));
        // S2, S3 (append), S4 (overwrite), S5 (append) are all included
        assert!(set.contains(s2_id));
        assert!(set.contains(s3_id));
        assert!(set.contains(s4_id), "OVERWRITE should be included");
        assert!(set.contains(s5_id));
    }

    #[test]
    fn test_changelog_set_ordinal_assignment() {
        let table = TableTestFixture::new_with_deep_history().table;

        let s1_id = 3051729675574597004_i64;
        let s2_id = 3055729675574597004_i64;
        let s3_id = 3056729675574597004_i64;
        let s4_id = 3057729675574597004_i64;
        let s5_id = 3059729675574597004_i64;

        let set =
            ChangelogSnapshotSet::build(&table.metadata_ref(), s1_id, s5_id, false).unwrap();

        // Ordinals assigned oldest-first: S2=0, S3=1, S4=2, S5=3
        assert_eq!(set.ordinal_for(s2_id), 0);
        assert_eq!(set.ordinal_for(s3_id), 1);
        assert_eq!(set.ordinal_for(s4_id), 2);
        assert_eq!(set.ordinal_for(s5_id), 3);
    }

    #[tokio::test]
    async fn test_changelog_scan_plan_files_returns_tasks() {
        // Deep history: S1(append) -> S2(append) -> S3(append) -> S4(overwrite) -> S5(append)
        // Each snapshot adds one file. Changelog from S1 (exclusive) to S5 should
        // return all 4 files (S2–S5) as INSERT tasks. (S4 is overwrite but still
        // produces an ADDED entry in its manifest.)
        let mut fixture = TableTestFixture::new_with_deep_history();
        fixture.setup_manifest_files_deep_history().await;

        let s1_id = 3051729675574597004_i64;
        let s5_id = 3059729675574597004_i64;

        let scan = fixture
            .table
            .incremental_changelog_scan(s1_id, Some(s5_id))
            .build()
            .unwrap();

        let mut tasks: Vec<_> = scan
            .plan_files()
            .await
            .unwrap()
            .try_collect()
            .await
            .unwrap();

        tasks.sort_by(|a, b| a.data_file_path.cmp(&b.data_file_path));

        // 4 files: s2, s3, s4 (overwrite), s5
        assert_eq!(tasks.len(), 4, "Should return 4 changelog tasks");

        let file_names: Vec<&str> = tasks
            .iter()
            .map(|t| t.data_file_path.rsplit('/').next().unwrap())
            .collect();
        assert_eq!(
            file_names,
            vec!["s2.parquet", "s3.parquet", "s4.parquet", "s5.parquet"]
        );

        // All entries are ADDED in our manifests, so all should be INSERT
        for task in &tasks {
            assert_eq!(task.operation, ChangelogOperation::Insert);
        }
    }

    #[tokio::test]
    async fn test_changelog_scan_ordinals_on_tasks() {
        let mut fixture = TableTestFixture::new_with_deep_history();
        fixture.setup_manifest_files_deep_history().await;

        let s1_id = 3051729675574597004_i64;
        let s2_id = 3055729675574597004_i64;
        let s3_id = 3056729675574597004_i64;
        let s4_id = 3057729675574597004_i64;
        let s5_id = 3059729675574597004_i64;

        let scan = fixture
            .table
            .incremental_changelog_scan(s1_id, Some(s5_id))
            .build()
            .unwrap();

        let tasks: Vec<_> = scan
            .plan_files()
            .await
            .unwrap()
            .try_collect()
            .await
            .unwrap();

        // Verify ordinals and commit snapshot IDs
        for task in &tasks {
            match task.commit_snapshot_id {
                id if id == s2_id => assert_eq!(task.change_ordinal, 0),
                id if id == s3_id => assert_eq!(task.change_ordinal, 1),
                id if id == s4_id => assert_eq!(task.change_ordinal, 2),
                id if id == s5_id => assert_eq!(task.change_ordinal, 3),
                other => panic!("Unexpected commit_snapshot_id: {other}"),
            }
        }
    }

    #[tokio::test]
    async fn test_changelog_scan_partial_range() {
        let mut fixture = TableTestFixture::new_with_deep_history();
        fixture.setup_manifest_files_deep_history().await;

        let s2_id = 3055729675574597004_i64;
        let s3_id = 3056729675574597004_i64;

        let scan = fixture
            .table
            .incremental_changelog_scan(s2_id, Some(s3_id))
            .build()
            .unwrap();

        let tasks: Vec<_> = scan
            .plan_files()
            .await
            .unwrap()
            .try_collect()
            .await
            .unwrap();

        assert_eq!(tasks.len(), 1);
        assert!(tasks[0].data_file_path.ends_with("s3.parquet"));
        assert_eq!(tasks[0].operation, ChangelogOperation::Insert);
        assert_eq!(tasks[0].change_ordinal, 0);
        assert_eq!(tasks[0].commit_snapshot_id, s3_id);
    }
}
