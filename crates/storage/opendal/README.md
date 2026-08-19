<!--
  ~ Licensed to the Apache Software Foundation (ASF) under one
  ~ or more contributor license agreements.  See the NOTICE file
  ~ distributed with this work for additional information
  ~ regarding copyright ownership.  The ASF licenses this file
  ~ to you under the Apache License, Version 2.0 (the
  ~ "License"); you may not use this file except in compliance
  ~ with the License.  You may obtain a copy of the License at
  ~
  ~   http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
-->

# iceberg-storage-opendal

OpenDAL-based storage backend implementations for [Apache Iceberg Rust](https://rust.iceberg.apache.org/).

## Supported Storage Backends

| Storage Backend      | Feature Flag     | Status          | Description                                   |
| -------------------- | ---------------- | --------------- | --------------------------------------------- |
| Memory               | `opendal-memory` | ✅ Stable       | In-memory storage for testing and development |
| Local Filesystem     | `opendal-fs`     | ✅ Stable       | Local filesystem storage                      |
| Amazon S3            | `opendal-s3`     | ✅ Stable       | Amazon S3 storage                             |
| Google Cloud Storage | `opendal-gcs`    | ✅ Stable       | Google Cloud Storage                          |
| Hugging Face         | `opendal-hf`     | ✅ Stable       | Hugging Face buckets and repositories         |
| Alibaba Cloud OSS    | `opendal-oss`    | 🧪 Experimental | Alibaba Cloud Object Storage Service          |
| Azure Datalake       | `opendal-azdls`  | 🧪 Experimental | Azure Datalake Storage v2                     |

You can enable all stable storage backends at once using the `opendal-all` feature flag.

> Note that `opendal-oss` and `opendal-azdls` are currently experimental and not included in `opendal-all`.

## Usage

Add the crate to your `Cargo.toml` with the feature flags for the backends you need:

```toml
[dependencies]
iceberg = { version = "x.y.z" }
iceberg-storage-opendal = { version = "x.y.z", features = ["opendal-s3"] }
iceberg-catalog-rest = { version = "x.y.z" }
```

Then pass an `OpenDalStorageFactory` to your catalog builder:

```rust
use std::collections::HashMap;
use std::sync::Arc;

use iceberg::{Catalog, CatalogBuilder, TableIdent};
use iceberg_catalog_rest::{RestCatalogBuilder, REST_CATALOG_PROP_URI};
use iceberg_storage_opendal::OpenDalStorageFactory;

#[tokio::main]
async fn main() -> iceberg::Result<()> {
    let catalog = RestCatalogBuilder::default()
        .with_storage_factory(Arc::new(OpenDalStorageFactory::S3 {
            customized_credential_load: None,
        }))
        .load(
            "my_catalog",
            HashMap::from([
                (REST_CATALOG_PROP_URI.to_string(), "http://localhost:8181".to_string()),
            ]),
        )
        .await?;

    let table = catalog
        .load_table(&TableIdent::from_strs(["my_namespace", "my_table"])?)
        .await?;

    let scan = table.scan().select_all().build()?;
    let stream = scan.to_arrow().await?;

    Ok(())
}
```

## OpenDAL configuration

OpenDAL properties are supplied through the catalog or `FileIOBuilder` storage
configuration. They are not persisted as Iceberg table properties.

The following properties configure OpenDAL's timeout and retry layers for every
storage backend. Omitted properties retain OpenDAL's defaults.

| Property | OpenDAL setting |
| --- | --- |
| `opendal.timeout-ms` | Control-operation timeout |
| `opendal.io-timeout-ms` | Per-I/O timeout |
| `opendal.retry.max-times` | Maximum retry count |
| `opendal.retry.min-delay-ms` | Minimum retry delay |
| `opendal.retry.max-delay-ms` | Maximum retry delay |
| `opendal.retry.factor` | Exponential backoff factor |
| `opendal.retry.jitter` | Whether retry jitter is enabled (off by default) |

An invalid value is rejected when the storage is built. Keys outside this table
are ignored, so a misspelled property silently has no effect.

```rust
let file_io = FileIOBuilder::new(Arc::new(OpenDalStorageFactory::S3 {
    customized_credential_load: None,
}))
.with_prop("opendal.io-timeout-ms", "120000")
.with_prop("opendal.retry.max-times", "5")
.build()?;
```

The same settings apply when a storage is constructed directly, via
`OpenDalStorage::new(backend, &props)`.
