//! Scheduled scans (desktop; the app keeps running in the tray).

use crate::i18n::t;
use crate::settings::Schedule;
use crate::state::AppState;
use chrono::{DateTime, Datelike, Duration as ChronoDuration, Local, TimeZone};
use seccom_engine::util::now_unix;
use std::time::Duration;
use tauri::{AppHandle, Manager, Runtime};

/// Missed runs are caught up when the app starts within this window.
const CATCH_UP_HOURS: i64 = 12;

/// The most recent scheduled moment that is not in the future.
fn last_slot(s: &Schedule, now: DateTime<Local>) -> Option<DateTime<Local>> {
    let today = now.date_naive().and_hms_opt(s.hour as u32, s.minute as u32, 0)?;
    let mut slot = Local.from_local_datetime(&today).earliest()?;
    if slot > now {
        slot -= ChronoDuration::days(1);
    }
    if s.frequency == "weekly" {
        for _ in 0..7 {
            if slot.weekday().num_days_from_monday() == s.weekday as u32 {
                break;
            }
            slot -= ChronoDuration::days(1);
        }
    }
    Some(slot)
}

/// Next scheduled run (UNIX seconds), for display.
pub fn next_run(s: &Schedule) -> Option<u64> {
    if !s.enabled {
        return None;
    }
    let now = Local::now();
    let last = last_slot(s, now)?;
    let step = if s.frequency == "weekly" { 7 } else { 1 };
    let next = last + ChronoDuration::days(step);
    Some(next.timestamp().max(0) as u64)
}

fn is_due(s: &Schedule, now: DateTime<Local>) -> bool {
    if !s.enabled {
        return false;
    }
    let Some(slot) = last_slot(s, now) else { return false };
    let slot_ts = slot.timestamp().max(0) as u64;
    s.last_run < slot_ts && now.signed_duration_since(slot) < ChronoDuration::hours(CATCH_UP_HOURS)
}

pub fn spawn<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    let _ = std::thread::Builder::new().name("seccom-scheduler".into()).spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(30));
            let state = app.state::<AppState>();
            let mut settings = state.settings();
            if !is_due(&settings.schedule, Local::now()) {
                continue;
            }
            if state.scan.lock().map(|s| s.is_some()).unwrap_or(true) {
                continue; // try again later
            }
            settings.schedule.last_run = now_unix();
            let kind = settings.schedule.kind.clone();
            if let Err(e) = state.save_settings(settings) {
                log::warn!("cannot save schedule state: {e}");
                continue;
            }
            if crate::scan::start(&app, &kind, Vec::new(), "scheduled").is_ok() {
                let lang = crate::i18n::lang(&state);
                crate::notify::notify(&app, t(lang, "scheduled"), "");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(y: i32, m: u32, d: u32, h: u32, min: u32) -> DateTime<Local> {
        Local.with_ymd_and_hms(y, m, d, h, min, 0).earliest().unwrap()
    }

    #[test]
    fn daily_and_weekly_slots() {
        let mut s = Schedule { enabled: true, frequency: "daily".into(), hour: 12, minute: 30, ..Default::default() };
        // 2026-10-14 is a Wednesday.
        let now = at(2026, 10, 14, 13, 0);
        assert_eq!(last_slot(&s, now).unwrap(), at(2026, 10, 14, 12, 30));
        assert!(is_due(&s, now));
        s.last_run = at(2026, 10, 14, 12, 31).timestamp() as u64;
        assert!(!is_due(&s, now));

        let s = Schedule { enabled: true, frequency: "weekly".into(), weekday: 0, hour: 9, minute: 0, ..Default::default() };
        assert_eq!(last_slot(&s, now).unwrap(), at(2026, 10, 12, 9, 0));
        // Too long ago to catch up.
        assert!(!is_due(&s, now));
    }
}
