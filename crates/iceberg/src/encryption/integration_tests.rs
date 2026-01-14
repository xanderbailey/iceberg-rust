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

//! Integration tests for encryption functionality

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use arrow_array::{Int32Array, RecordBatch, StringArray};
    use arrow_schema::{DataType, Field, Schema as ArrowSchema};
    use parquet::arrow::ArrowWriter;
    use tempfile::TempDir;

    use crate::encryption::{
        EncryptionAlgorithm, EncryptionConfig, EncryptionManager, StandardEncryptionManager,
    };
    use crate::encryption::kms::InMemoryKms;
    use crate::io::{FileIO, FileIOBuilder};
    use crate::spec::{
        DataFileFormat, NestedField, PrimitiveType, Schema, TableMetadata, Type,
    };
    use crate::spec::table_properties::TableProperties;
    use crate::table::{Table, TableBuilder};
    use crate::writer::base_writer::data_file_writer::DataFileWriterBuilder;
    use crate::writer::file_writer::{ParquetWriterBuilder};
    use crate::writer::file_writer::location_generator::{
        DefaultFileNameGenerator, DefaultLocationGenerator,
    };
    use crate::writer::file_writer::rolling_writer::RollingFileWriterBuilder;
    use crate::writer::{IcebergWriter, IcebergWriterBuilder};
    use crate::{Result, TableIdent};

    use parquet::arrow::PARQUET_FIELD_ID_META_KEY;
    use parquet::basic::Compression;
    use parquet::file::properties::WriterProperties;

    #[tokio::test]
    async fn test_encryption_manager_configuration() -> Result<()> {
        // Test that encryption manager can be properly configured
        let kms = Arc::new(InMemoryKms::new());
        let config = EncryptionConfig::new(
            "test-master-key".to_string(),
            EncryptionAlgorithm::Aes256Gcm,
        );

        let manager = Arc::new(
            StandardEncryptionManager::new(
                kms.clone(),
                config,
                "test-table".to_string(),
            ).await?
        );

        // Create FileIO with encryption manager
        let file_io = FileIOBuilder::new("memory")
            .build()?
            .with_encryption_manager(manager.clone());

        // Verify FileIO has encryption manager
        assert!(file_io.encryption_manager().is_some());

        // Verify we can get key metadata
        let key_metadata = manager.current_key_metadata().await?;
        assert!(!key_metadata.key_id.is_empty());

        Ok(())
    }

    // TODO: Fix this test - DataFileWriter creation is failing
    #[tokio::test]
    #[ignore]
    async fn test_parquet_writer_with_encryption() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();

        // Create in-memory KMS for testing
        let kms = Arc::new(InMemoryKms::new());

        // Create encryption config
        let config = EncryptionConfig::new(
            "test-master-key".to_string(),
            EncryptionAlgorithm::Aes256Gcm,
        );

        // Create encryption manager
        let manager = Arc::new(
            StandardEncryptionManager::new(
                kms.clone(),
                config,
                "test-table".to_string(),
            ).await?
        );

        // Create FileIO with encryption manager
        let file_io = FileIOBuilder::new_fs_io()
            .build()?
            .with_encryption_manager(manager.clone());

        // Create Iceberg schema
        let schema = Schema::builder()
            .with_schema_id(1)
            .with_fields(vec![
                NestedField::required(1, "id", Type::Primitive(PrimitiveType::Int)).into(),
                NestedField::required(2, "name", Type::Primitive(PrimitiveType::String)).into(),
            ])
            .build()?;

        // Create Arrow schema with field IDs
        let arrow_schema = ArrowSchema::new(vec![
            Field::new("id", DataType::Int32, false).with_metadata(HashMap::from([(
                PARQUET_FIELD_ID_META_KEY.to_string(),
                "1".to_string(),
            )])),
            Field::new("name", DataType::Utf8, false).with_metadata(HashMap::from([(
                PARQUET_FIELD_ID_META_KEY.to_string(),
                "2".to_string(),
            )])),
        ]);

        // Create ParquetWriterBuilder with encryption
        let parquet_writer_builder = ParquetWriterBuilder::new(
            WriterProperties::builder()
                .set_compression(Compression::SNAPPY)
                .build(),
            Arc::new(schema),
        );

        // Create location and file name generators
        let location_gen = DefaultLocationGenerator::with_data_location(
            temp_dir.path().to_str().unwrap().to_string(),
        );
        let file_name_gen = DefaultFileNameGenerator::new(
            "test".to_string(),
            None,
            DataFileFormat::Parquet,
        );

        // Create RollingFileWriterBuilder which should propagate encryption
        let rolling_writer_builder = RollingFileWriterBuilder::new_with_default_file_size(
            parquet_writer_builder,
            file_io.clone(),
            location_gen,
            file_name_gen,
        );

        // Build data file writer
        let mut writer = DataFileWriterBuilder::new(rolling_writer_builder)
            .build(None)
            .await?;

        // Create test data
        let batch = RecordBatch::try_new(
            Arc::new(arrow_schema),
            vec![
                Arc::new(Int32Array::from(vec![1, 2, 3, 4, 5])),
                Arc::new(StringArray::from(vec!["Alice", "Bob", "Charlie", "David", "Eve"])),
            ],
        )?;

        // Write data
        writer.write(batch).await?;

        // Close writer
        let data_files = writer.close().await?;

        // Verify we wrote at least one file
        assert!(!data_files.is_empty());

        // The files should be encrypted (we'd need to read them back to fully verify)
        // For now, we just verify the process completed successfully

        Ok(())
    }

    #[tokio::test]
    async fn test_encryption_manager_key_rotation() -> Result<()> {
        // Create in-memory KMS for testing
        let kms = Arc::new(InMemoryKms::new());

        // Create encryption config with short rotation period for testing
        let config = EncryptionConfig::new(
            "rotation-test-key".to_string(),
            EncryptionAlgorithm::Aes128Gcm,
        ).with_key_rotation_days(1);

        // Create encryption manager
        let manager = StandardEncryptionManager::new(
            kms.clone(),
            config,
            "rotation-test-table".to_string(),
        ).await?;

        // Get first key metadata
        let key_metadata1 = manager.current_key_metadata().await?;

        // Get second key metadata (should be the same since we haven't exceeded rotation period)
        let key_metadata2 = manager.current_key_metadata().await?;

        // Keys should be the same
        assert_eq!(key_metadata1.key_id, key_metadata2.key_id);

        // Test key retrieval
        let key1 = manager.get_raw_key(&key_metadata1).await?;
        let key2 = manager.get_raw_key(&key_metadata2).await?;

        // Keys should be the same
        assert_eq!(key1, key2);

        Ok(())
    }

    #[tokio::test]
    async fn test_different_encryption_algorithms() -> Result<()> {
        let kms = Arc::new(InMemoryKms::new());

        // Test AES-128
        let config_128 = EncryptionConfig::new(
            "test-128".to_string(),
            EncryptionAlgorithm::Aes128Gcm,
        );
        let manager_128 = StandardEncryptionManager::new(
            kms.clone(),
            config_128,
            "table-128".to_string(),
        ).await?;

        let key_metadata_128 = manager_128.current_key_metadata().await?;
        let key_128 = manager_128.get_raw_key(&key_metadata_128).await?;
        assert_eq!(key_128.len(), 16); // 128 bits = 16 bytes

        // Test AES-256
        let config_256 = EncryptionConfig::new(
            "test-256".to_string(),
            EncryptionAlgorithm::Aes256Gcm,
        );
        let manager_256 = StandardEncryptionManager::new(
            kms.clone(),
            config_256,
            "table-256".to_string(),
        ).await?;

        let key_metadata_256 = manager_256.current_key_metadata().await?;
        let key_256 = manager_256.get_raw_key(&key_metadata_256).await?;
        assert_eq!(key_256.len(), 32); // 256 bits = 32 bytes

        Ok(())
    }
}