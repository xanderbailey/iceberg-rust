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
use std::str::FromStr;
use std::time::Duration;

use iceberg::{Error, ErrorKind, Result};
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct OpenDalStorageSettings {
    pub(crate) timeout: Option<Duration>,
    pub(crate) io_timeout: Option<Duration>,
    pub(crate) retry_max_times: Option<usize>,
    pub(crate) retry_min_delay: Option<Duration>,
    pub(crate) retry_max_delay: Option<Duration>,
    pub(crate) retry_factor: Option<f32>,
    pub(crate) retry_jitter: bool,
}

impl OpenDalStorageSettings {
    pub(crate) fn from_props(props: &HashMap<String, String>) -> Result<Self> {
        let timeout = parse_duration_property(props, OPENDAL_TIMEOUT_MS, false)?;
        let io_timeout = parse_duration_property(props, OPENDAL_IO_TIMEOUT_MS, false)?;
        let retry_max_times =
            parse_property(props, OPENDAL_RETRY_MAX_TIMES, "a non-negative integer")?;
        let retry_min_delay = parse_duration_property(props, OPENDAL_RETRY_MIN_DELAY_MS, true)?;
        let retry_max_delay = parse_duration_property(props, OPENDAL_RETRY_MAX_DELAY_MS, true)?;
        let retry_factor = parse_property::<f32>(
            props,
            OPENDAL_RETRY_FACTOR,
            "a finite number greater than or equal to 1",
        )?;
        if retry_factor.is_some_and(|factor| !factor.is_finite() || factor < 1.0) {
            return Err(invalid_property(
                props,
                OPENDAL_RETRY_FACTOR,
                "a finite number greater than or equal to 1",
            ));
        }
        if retry_min_delay
            .zip(retry_max_delay)
            .is_some_and(|(min_delay, max_delay)| min_delay > max_delay)
        {
            return Err(invalid_property(
                props,
                OPENDAL_RETRY_MAX_DELAY_MS,
                "a duration greater than or equal to the minimum retry delay",
            ));
        }
        let retry_jitter = parse_bool_property(props, OPENDAL_RETRY_JITTER)?.unwrap_or_default();

        Ok(Self {
            timeout,
            io_timeout,
            retry_max_times,
            retry_min_delay,
            retry_max_delay,
            retry_factor,
            retry_jitter,
        })
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

fn parse_property<T: FromStr>(
    props: &HashMap<String, String>,
    key: &str,
    expected: &str,
) -> Result<Option<T>> {
    props
        .get(key)
        .map(|value| {
            value
                .parse()
                .map_err(|_| invalid_property(props, key, expected))
        })
        .transpose()
}

fn parse_duration_property(
    props: &HashMap<String, String>,
    key: &str,
    allow_zero: bool,
) -> Result<Option<Duration>> {
    let expected = if allow_zero {
        "a non-negative integer number of milliseconds"
    } else {
        "a positive integer number of milliseconds"
    };
    let millis = parse_property::<u64>(props, key, expected)?;
    if !allow_zero && millis == Some(0) {
        return Err(invalid_property(props, key, expected));
    }
    Ok(millis.map(Duration::from_millis))
}

fn parse_bool_property(props: &HashMap<String, String>, key: &str) -> Result<Option<bool>> {
    props
        .get(key)
        .map(|value| match value.to_ascii_lowercase().as_str() {
            "true" | "t" | "1" | "on" => Ok(true),
            "false" | "f" | "0" | "off" => Ok(false),
            _ => Err(invalid_property(props, key, "a boolean")),
        })
        .transpose()
}

fn invalid_property(props: &HashMap<String, String>, key: &str, expected: &str) -> Error {
    let value = props.get(key).map(String::as_str).unwrap_or_default();
    Error::new(
        ErrorKind::DataInvalid,
        format!("Invalid {key}: {value}. Expected {expected}"),
    )
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
            (OPENDAL_RETRY_JITTER.to_string(), "true".to_string()),
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
            (OPENDAL_RETRY_JITTER, "invalid"),
        ] {
            let props = HashMap::from([(key.to_string(), value.to_string())]);
            let error = OpenDalStorageSettings::from_props(&props).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::DataInvalid);
            assert!(error.message().contains(key));
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
