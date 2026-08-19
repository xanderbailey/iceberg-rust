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

use std::collections::HashMap;
use std::time::Duration;

use iceberg::{Error, ErrorKind, Result};
use iceberg_property_macro::Properties;
use opendal::layers::{RetryLayer, TimeoutLayer};
use serde::{Deserialize, Serialize};

/// OpenDAL per-I/O timeout in milliseconds.
pub const OPENDAL_IO_TIMEOUT_MS: &str = "opendal.io-timeout-ms";
/// OpenDAL control-operation timeout in milliseconds.
pub const OPENDAL_TIMEOUT_MS: &str = "opendal.timeout-ms";
/// OpenDAL maximum number of retries.
pub const OPENDAL_RETRY_MAX_TIMES: &str = "opendal.retry.max-times";
/// OpenDAL minimum retry delay in milliseconds.
pub const OPENDAL_RETRY_MIN_DELAY_MS: &str = "opendal.retry.min-delay-ms";
/// OpenDAL maximum retry delay in milliseconds.
pub const OPENDAL_RETRY_MAX_DELAY_MS: &str = "opendal.retry.max-delay-ms";
/// OpenDAL exponential retry factor.
pub const OPENDAL_RETRY_FACTOR: &str = "opendal.retry.factor";
/// Whether OpenDAL retry jitter is enabled.
pub const OPENDAL_RETRY_JITTER: &str = "opendal.retry.jitter";

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize, Properties)]
pub(crate) struct OpenDalStorageSettings {
    #[property(key = OPENDAL_TIMEOUT_MS, default = None, parse_with = parse_positive_duration)]
    pub(crate) timeout: Option<Duration>,
    #[property(key = OPENDAL_IO_TIMEOUT_MS, default = None, parse_with = parse_positive_duration)]
    pub(crate) io_timeout: Option<Duration>,
    #[property(key = OPENDAL_RETRY_MAX_TIMES, default = None)]
    pub(crate) retry_max_times: Option<usize>,
    #[property(key = OPENDAL_RETRY_MIN_DELAY_MS, default = None, parse_with = parse_duration)]
    pub(crate) retry_min_delay: Option<Duration>,
    #[property(key = OPENDAL_RETRY_MAX_DELAY_MS, default = None, parse_with = parse_duration)]
    pub(crate) retry_max_delay: Option<Duration>,
    #[property(key = OPENDAL_RETRY_FACTOR, default = None, parse_with = parse_retry_factor)]
    pub(crate) retry_factor: Option<f32>,
    #[property(key = OPENDAL_RETRY_JITTER, default = false)]
    pub(crate) retry_jitter: bool,
}

impl OpenDalStorageSettings {
    pub(crate) fn from_props(props: &HashMap<String, String>) -> Result<Self> {
        let settings = Self::from_properties(props)?;
        if settings
            .retry_min_delay
            .zip(settings.retry_max_delay)
            .is_some_and(|(min_delay, max_delay)| min_delay > max_delay)
        {
            return Err(Error::new(
                ErrorKind::DataInvalid,
                format!(
                    "{OPENDAL_RETRY_MAX_DELAY_MS} must be greater than or equal to {OPENDAL_RETRY_MIN_DELAY_MS}"
                ),
            ));
        }
        Ok(settings)
    }

    pub(crate) fn timeout_layer(&self) -> TimeoutLayer {
        let mut layer = TimeoutLayer::new();
        if let Some(timeout) = self.timeout {
            layer = layer.with_timeout(timeout);
        }
        if let Some(io_timeout) = self.io_timeout {
            layer = layer.with_io_timeout(io_timeout);
        }
        layer
    }

    pub(crate) fn retry_layer(&self) -> RetryLayer {
        let mut layer = RetryLayer::new();
        if let Some(max_times) = self.retry_max_times {
            layer = layer.with_max_times(max_times);
        }
        if let Some(min_delay) = self.retry_min_delay {
            layer = layer.with_min_delay(min_delay);
        }
        if let Some(max_delay) = self.retry_max_delay {
            layer = layer.with_max_delay(max_delay);
        }
        if let Some(factor) = self.retry_factor {
            layer = layer.with_factor(factor);
        }
        if self.retry_jitter {
            layer = layer.with_jitter();
        }
        layer
    }
}

fn parse_positive_duration(value: &str) -> Result<Duration> {
    let duration = parse_duration(value)?;
    if duration.is_zero() {
        return Err(Error::new(
            ErrorKind::DataInvalid,
            "Expected a positive integer number of milliseconds",
        ));
    }
    Ok(duration)
}

fn parse_duration(value: &str) -> Result<Duration> {
    value
        .parse::<u64>()
        .map(Duration::from_millis)
        .map_err(|_| {
            Error::new(
                ErrorKind::DataInvalid,
                "Expected a non-negative integer number of milliseconds",
            )
        })
}

fn parse_retry_factor(value: &str) -> Result<f32> {
    let factor = value.parse::<f32>().map_err(|_| {
        Error::new(
            ErrorKind::DataInvalid,
            "Expected a finite number greater than or equal to 1",
        )
    })?;
    if !factor.is_finite() || factor < 1.0 {
        return Err(Error::new(
            ErrorKind::DataInvalid,
            "Expected a finite number greater than or equal to 1",
        ));
    }
    Ok(factor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opendal_settings_parse_valid() {
        assert_eq!(
            OpenDalStorageSettings::from_props(&HashMap::new()).unwrap(),
            OpenDalStorageSettings::default()
        );

        let props = HashMap::from([
            (OPENDAL_TIMEOUT_MS.to_string(), "60000".to_string()),
            (OPENDAL_IO_TIMEOUT_MS.to_string(), "45500".to_string()),
            (OPENDAL_RETRY_MAX_TIMES.to_string(), "7".to_string()),
            (OPENDAL_RETRY_MIN_DELAY_MS.to_string(), "250".to_string()),
            (OPENDAL_RETRY_MAX_DELAY_MS.to_string(), "30000".to_string()),
            (OPENDAL_RETRY_FACTOR.to_string(), "1.5".to_string()),
            (OPENDAL_RETRY_JITTER.to_string(), "TRUE".to_string()),
        ]);
        assert_eq!(
            OpenDalStorageSettings::from_props(&props).unwrap(),
            OpenDalStorageSettings {
                timeout: Some(Duration::from_millis(60_000)),
                io_timeout: Some(Duration::from_millis(45_500)),
                retry_max_times: Some(7),
                retry_min_delay: Some(Duration::from_millis(250)),
                retry_max_delay: Some(Duration::from_millis(30_000)),
                retry_factor: Some(1.5),
                retry_jitter: true,
            }
        );
    }

    #[test]
    fn test_opendal_settings_parse_invalid() {
        for (key, value) in [
            (OPENDAL_TIMEOUT_MS, "0"),
            (OPENDAL_IO_TIMEOUT_MS, "-1"),
            (OPENDAL_RETRY_MAX_TIMES, "1.5"),
            (OPENDAL_RETRY_MIN_DELAY_MS, "-1"),
            (OPENDAL_RETRY_MAX_DELAY_MS, "invalid"),
            (OPENDAL_RETRY_FACTOR, "0.5"),
            (OPENDAL_RETRY_FACTOR, "NaN"),
            (OPENDAL_RETRY_JITTER, "1"),
        ] {
            let props = HashMap::from([(key.to_string(), value.to_string())]);
            let error = OpenDalStorageSettings::from_props(&props).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::DataInvalid);
            assert!(format!("{error}").contains(key));
        }

        let props = HashMap::from([
            (OPENDAL_RETRY_MIN_DELAY_MS.to_string(), "1000".to_string()),
            (OPENDAL_RETRY_MAX_DELAY_MS.to_string(), "500".to_string()),
        ]);
        let error = OpenDalStorageSettings::from_props(&props).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DataInvalid);
        assert!(error.message().contains(OPENDAL_RETRY_MAX_DELAY_MS));
    }
}
