//! Backend strings (tray menu, notifications). The UI has its own catalog.

use crate::state::AppState;

pub fn lang(state: &AppState) -> &'static str {
    let s = state.settings();
    match s.language.as_str() {
        "ru" => "ru",
        "en" => "en",
        _ => match tauri_plugin_os::locale() {
            Some(l) if l.to_lowercase().starts_with("ru") || l.to_lowercase().starts_with("kk") => "ru",
            Some(_) => "en",
            None => "ru",
        },
    }
}

pub fn t(lang: &str, key: &str) -> &'static str {
    let ru = lang == "ru";
    match key {
        "tray_open" => {
            if ru {
                "Открыть SecCorp"
            } else {
                "Open SecCorp"
            }
        }
        "tray_quick_scan" => {
            if ru {
                "Быстрая проверка"
            } else {
                "Quick scan"
            }
        }
        "tray_realtime" => {
            if ru {
                "Защита в реальном времени"
            } else {
                "Real-time protection"
            }
        }
        "tray_quit" => {
            if ru {
                "Выход"
            } else {
                "Quit"
            }
        }
        "tray_tooltip" => {
            if ru {
                "SecCorp — защита включена"
            } else {
                "SecCorp — protection is on"
            }
        }
        "threat_title" => {
            if ru {
                "Обнаружена угроза"
            } else {
                "Threat detected"
            }
        }
        "threat_quarantined" => {
            if ru {
                "Файл перемещён в карантин"
            } else {
                "The file was moved to quarantine"
            }
        }
        "threat_action_needed" => {
            if ru {
                "Откройте SecCorp, чтобы обезвредить угрозу"
            } else {
                "Open SecCorp to neutralize the threat"
            }
        }
        "scan_done" => {
            if ru {
                "Проверка завершена"
            } else {
                "Scan complete"
            }
        }
        "scan_limited" => {
            if ru {
                "Рабочий стол, Документы, Загрузки и данные приложений не проверены: включите для SecCorp «Полный доступ к диску»."
            } else {
                "Desktop, Documents, Downloads and app data were skipped: give SecCorp Full Disk Access."
            }
        }
        "scan_clean" => {
            if ru {
                "Угроз не найдено"
            } else {
                "No threats found"
            }
        }
        "scan_threats" => {
            if ru {
                "Найдено угроз: {n}"
            } else {
                "Threats found: {n}"
            }
        }
        "background" => {
            if ru {
                "SecCorp продолжает защищать компьютер в фоне"
            } else {
                "SecCorp keeps protecting your computer in the background"
            }
        }
        "android_status_title" => {
            if ru {
                "Защита SecCorp включена"
            } else {
                "SecCorp protection is on"
            }
        }
        "android_status_text" => {
            if ru {
                "Новые приложения и загрузки проверяются автоматически"
            } else {
                "New apps and downloads are checked automatically"
            }
        }
        "scheduled" => {
            if ru {
                "Плановая проверка запущена"
            } else {
                "Scheduled scan started"
            }
        }
        "db_updated" => {
            if ru {
                "Базы сигнатур обновлены"
            } else {
                "Signature database updated"
            }
        }
        _ => "",
    }
}
