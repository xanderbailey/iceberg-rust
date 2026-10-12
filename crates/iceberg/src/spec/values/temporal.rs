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

//! Temporal value conversions for dates, times, and timestamps

use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, NaiveTime, TimeDelta, TimeZone, Utc};

use crate::error::{Result, invalid_data};

pub(crate) const ISO_DATE_FORMAT: &str = "%Y-%m-%d";
pub(crate) const ISO_TIMESTAMP_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%.f";
pub(crate) const ISO_TIMESTAMPTZ_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%.f+00:00";

/// Calendar dates repeat every 400 years, which span exactly 146,097 days.
const YEARS_PER_GREGORIAN_CYCLE: i64 = 400;
const DAYS_PER_GREGORIAN_CYCLE: i64 = 146_097;
const MICROS_PER_DAY: i128 = 86_400_000_000;

/// A year within chrono's range that is congruent to every folded year modulo 400, so that
/// month, day and leap-year behaviour are preserved by the fold.
const FOLD_ANCHOR_YEAR: i64 = 2000;

/// Rewrites an ISO-8601 value whose year carries an explicit sign into an equivalent value
/// inside chrono's year range, returning it alongside the number of days folded away.
///
/// Iceberg stores `date` as an `i32` day count and `timestamp` as an `i64` microsecond count,
/// both of which reach years that chrono cannot represent (its range is roughly -262144 to
/// +262142). Java's `DateTimeFormatter.ISO_LOCAL_DATE` writes any year outside 0000-9999 with
/// a sign prefix, so such values do appear in single-value JSON. Folding the year by whole
/// 400-year cycles brings it into range without changing the month, day or leap-year status.
///
/// Returns `None` when the year carries no sign, in which case it is at most four digits and
/// chrono can parse the value directly.
fn fold_expanded_year(value: &str) -> Option<(String, i64)> {
    let (negative, rest) = match value.as_bytes().first()? {
        b'+' => (false, &value[1..]),
        b'-' => (true, &value[1..]),
        _ => return None,
    };

    // An `i32` year comfortably covers the whole `i32` day and `i64` microsecond ranges, and
    // keeps the day count below from overflowing on absurd input.
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    let magnitude: i32 = rest[..digits].parse().ok()?;
    let year = i64::from(if negative { -magnitude } else { magnitude });

    let folded = FOLD_ANCHOR_YEAR + year.rem_euclid(YEARS_PER_GREGORIAN_CYCLE);
    let cycles = (year - FOLD_ANCHOR_YEAR).div_euclid(YEARS_PER_GREGORIAN_CYCLE);

    Some((
        format!("{folded:04}{}", &rest[digits..]),
        cycles * DAYS_PER_GREGORIAN_CYCLE,
    ))
}

/// Renders a year the way chrono and Java's `ISO_LOCAL_DATE` do: zero-padded to four digits
/// within 0000-9999, and sign-prefixed outside that range.
fn format_year(year: i64) -> String {
    if (0..=9999).contains(&year) {
        format!("{year:04}")
    } else {
        format!("{year:+05}")
    }
}

/// Replaces the four-digit year chrono rendered for a folded value with the true year.
///
/// Folding always lands in the years 1970-2369, so the year occupies exactly the first four
/// characters of `formatted`.
fn unfold_year(formatted: &str, folded_year: i32, cycles: i64) -> String {
    let year = i64::from(folded_year) + cycles * YEARS_PER_GREGORIAN_CYCLE;
    format!("{}{}", format_year(year), &formatted[4..])
}

/// Parses an ISO-8601 timestamp into microseconds since the Unix epoch, accepting years
/// outside chrono's range. See [`fold_expanded_year`].
fn iso_datetime_to_micros(value: &str, format: &str) -> Result<i64> {
    let Some((folded, folded_days)) = fold_expanded_year(value) else {
        return Ok(timestamp::datetime_to_microseconds(
            &NaiveDateTime::parse_from_str(value, format)?,
        ));
    };

    let micros = i128::from(timestamp::datetime_to_microseconds(
        &NaiveDateTime::parse_from_str(&folded, format)?,
    )) + i128::from(folded_days) * MICROS_PER_DAY;

    micros.try_into().map_err(|_| {
        invalid_data!("Timestamp is outside the representable microsecond range: {value}")
    })
}

/// Renders microseconds since the Unix epoch as an ISO-8601 timestamp, for any `i64`.
///
/// chrono cannot represent every instant an `i64` microsecond count can address, so fold the
/// value by whole 400-year cycles before formatting and restore the year afterwards.
fn micros_to_iso_datetime(micros: i64, format: &str) -> String {
    const MICROS_PER_CYCLE: i128 = DAYS_PER_GREGORIAN_CYCLE as i128 * MICROS_PER_DAY;

    let cycles = i128::from(micros).div_euclid(MICROS_PER_CYCLE);
    if cycles == 0 {
        return timestamp::microseconds_to_datetime(micros)
            .format(format)
            .to_string();
    }

    let folded = i128::from(micros).rem_euclid(MICROS_PER_CYCLE) as i64;
    let datetime = timestamp::microseconds_to_datetime(folded);

    unfold_year(
        &datetime.format(format).to_string(),
        datetime.year(),
        cycles as i64,
    )
}

pub(crate) mod date {
    use super::*;

    /// Parses an ISO-8601 date into days since the Unix epoch, accepting years outside
    /// chrono's range. See [`fold_expanded_year`].
    pub(crate) fn iso_date_to_days(value: &str) -> Result<i32> {
        let Some((folded, folded_days)) = fold_expanded_year(value) else {
            return Ok(date_to_days(&NaiveDate::parse_from_str(
                value,
                ISO_DATE_FORMAT,
            )?));
        };

        let days = i64::from(date_to_days(&NaiveDate::parse_from_str(
            &folded,
            ISO_DATE_FORMAT,
        )?)) + folded_days;

        days.try_into()
            .map_err(|_| invalid_data!("Date is outside the representable day range: {value}"))
    }

    /// Renders days since the Unix epoch as an ISO-8601 date, for any `i32`.
    ///
    /// chrono cannot represent every date an `i32` day count can address, so fold the value by
    /// whole 400-year cycles before formatting and restore the year afterwards.
    pub(crate) fn days_to_iso_date(days: i32) -> String {
        let cycles = i64::from(days).div_euclid(DAYS_PER_GREGORIAN_CYCLE);
        if cycles == 0 {
            return days_to_date(days).to_string();
        }

        let folded = i64::from(days).rem_euclid(DAYS_PER_GREGORIAN_CYCLE) as i32;
        let date = days_to_date(folded);

        unfold_year(&date.to_string(), date.year(), cycles)
    }

    pub(crate) fn date_to_days(date: &NaiveDate) -> i32 {
        date.signed_duration_since(
            // This is always the same and shouldn't fail
            NaiveDate::from_ymd_opt(1970, 1, 1).unwrap(),
        )
        .num_days() as i32
    }

    pub(crate) fn days_to_date(days: i32) -> NaiveDate {
        // This shouldn't fail until the year 262000
        (DateTime::UNIX_EPOCH + TimeDelta::try_days(days as i64).unwrap())
            .naive_utc()
            .date()
    }

    /// Returns unix epoch.
    pub(crate) fn unix_epoch() -> DateTime<Utc> {
        Utc.timestamp_nanos(0)
    }

    /// Creates date literal from `NaiveDate`, assuming it's utc timezone.
    pub(crate) fn date_from_naive_date(date: NaiveDate) -> i32 {
        (date - unix_epoch().date_naive()).num_days() as i32
    }
}

pub(crate) mod time {
    use super::*;

    pub(crate) fn time_to_microseconds(time: &NaiveTime) -> i64 {
        time.signed_duration_since(
            // This is always the same and shouldn't fail
            NaiveTime::from_num_seconds_from_midnight_opt(0, 0).unwrap(),
        )
        .num_microseconds()
        .unwrap()
    }

    pub(crate) fn microseconds_to_time(micros: i64) -> NaiveTime {
        let (secs, rem) = (micros / 1_000_000, micros % 1_000_000);

        NaiveTime::from_num_seconds_from_midnight_opt(secs as u32, rem as u32 * 1_000).unwrap()
    }
}

pub(crate) mod timestamp {
    use super::*;

    pub(crate) fn datetime_to_microseconds(time: &NaiveDateTime) -> i64 {
        time.and_utc().timestamp_micros()
    }

    /// Parses an ISO-8601 timestamp without a zone offset into microseconds since the Unix
    /// epoch, accepting years outside chrono's range. See [`fold_expanded_year`].
    pub(crate) fn iso_timestamp_to_micros(value: &str) -> Result<i64> {
        iso_datetime_to_micros(value, ISO_TIMESTAMP_FORMAT)
    }

    /// Renders microseconds since the Unix epoch as an ISO-8601 timestamp without a zone
    /// offset, for any `i64`. See [`micros_to_iso_datetime`].
    pub(crate) fn micros_to_iso_timestamp(micros: i64) -> String {
        micros_to_iso_datetime(micros, ISO_TIMESTAMP_FORMAT)
    }

    pub(crate) fn microseconds_to_datetime(micros: i64) -> NaiveDateTime {
        // This shouldn't fail until the year 262000
        DateTime::from_timestamp_micros(micros).unwrap().naive_utc()
    }

    pub(crate) fn nanoseconds_to_datetime(nanos: i64) -> NaiveDateTime {
        DateTime::from_timestamp_nanos(nanos).naive_utc()
    }

    /// Nanoseconds since the Unix epoch, or `None` if outside the representable `i64` range
    /// (roughly the years 1678–2262).
    pub(crate) fn datetime_to_nanoseconds(time: &NaiveDateTime) -> Option<i64> {
        time.and_utc().timestamp_nanos_opt()
    }
}

pub(crate) mod timestamptz {
    use super::*;

    /// Parses an ISO-8601 timestamp with a `+00:00` offset into microseconds since the Unix
    /// epoch, accepting years outside chrono's range. See [`fold_expanded_year`].
    pub(crate) fn iso_timestamptz_to_micros(value: &str) -> Result<i64> {
        iso_datetime_to_micros(value, ISO_TIMESTAMPTZ_FORMAT)
    }

    /// Renders microseconds since the Unix epoch as an ISO-8601 timestamp with a `+00:00`
    /// offset, for any `i64`. See [`micros_to_iso_datetime`].
    pub(crate) fn micros_to_iso_timestamptz(micros: i64) -> String {
        micros_to_iso_datetime(micros, ISO_TIMESTAMPTZ_FORMAT)
    }

    pub(crate) fn microseconds_to_datetimetz(micros: i64) -> DateTime<Utc> {
        // Returns None only outside chrono's range (~year -262144 to +262142);
        // unreachable for any realistic Iceberg timestamp.
        DateTime::from_timestamp_micros(micros).expect(
            "timestamp micros outside chrono's representable range (~year -262144..+262142)",
        )
    }

    pub(crate) fn nanoseconds_to_datetimetz(nanos: i64) -> DateTime<Utc> {
        DateTime::from_timestamp_nanos(nanos)
    }

    /// Nanoseconds since the Unix epoch, or `None` if outside the representable `i64` range
    /// (roughly the years 1678–2262).
    pub(crate) fn datetimetz_to_nanoseconds(time: &DateTime<Utc>) -> Option<i64> {
        time.timestamp_nanos_opt()
    }
}
