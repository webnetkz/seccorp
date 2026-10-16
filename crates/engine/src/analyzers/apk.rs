//! Android packages: binary `AndroidManifest.xml` parsing and a permission
//! based privacy-risk score (used for APK files and for installed apps).

use super::Finding;
use crate::util::{le_u16, le_u32};
use serde::Serialize;
use std::io::{Cursor, Read};

const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_TYPE: u16 = 0x0003;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;

const ATTR_NAME: u32 = 0x0101_0003;
const ATTR_PERMISSION: u32 = 0x0101_0006;
const ATTR_DEBUGGABLE: u32 = 0x0101_000f;

const TYPE_STRING: u8 = 0x03;
const TYPE_INT_BOOLEAN: u8 = 0x12;

/// Facts read from a manifest.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestInfo {
    pub package: String,
    pub permissions: Vec<String>,
    pub debuggable: bool,
    pub accessibility_service: bool,
    pub device_admin: bool,
    pub notification_listener: bool,
}

/// Risk assessment of an Android app.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApkRisk {
    pub manifest: ManifestInfo,
    /// 0..=45
    pub score: u32,
    /// Machine-readable reason codes (translated by the GUI).
    pub reasons: Vec<String>,
}

fn parse_string_pool(chunk: &[u8]) -> Option<Vec<String>> {
    let header_size = le_u16(chunk, 2)? as usize;
    let count = (le_u32(chunk, 8)? as usize).min(200_000);
    let flags = le_u32(chunk, 16)?;
    let strings_start = le_u32(chunk, 20)? as usize;
    let utf8 = flags & (1 << 8) != 0;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = le_u32(chunk, header_size + i * 4)? as usize;
        let mut p = strings_start.checked_add(off)?;
        let s = if utf8 {
            // char length (1-2 bytes), then byte length (1-2 bytes)
            let skip_len = |p: &mut usize| -> Option<usize> {
                let b0 = *chunk.get(*p)? as usize;
                if b0 & 0x80 != 0 {
                    let b1 = *chunk.get(*p + 1)? as usize;
                    *p += 2;
                    Some(((b0 & 0x7F) << 8) | b1)
                } else {
                    *p += 1;
                    Some(b0)
                }
            };
            skip_len(&mut p)?;
            let len = skip_len(&mut p)?;
            String::from_utf8_lossy(chunk.get(p..p + len)?).into_owned()
        } else {
            let mut len = le_u16(chunk, p)? as usize;
            p += 2;
            if len & 0x8000 != 0 {
                len = ((len & 0x7FFF) << 16) | le_u16(chunk, p)? as usize;
                p += 2;
            }
            let units: Vec<u16> = (0..len).map(|k| le_u16(chunk, p + k * 2)).collect::<Option<_>>()?;
            String::from_utf16_lossy(&units)
        };
        out.push(s);
    }
    Some(out)
}

struct Attr {
    name: String,
    res_id: u32,
    string: Option<String>,
    data_type: u8,
    data: u32,
}

fn parse_element(chunk: &[u8], strings: &[String], res_map: &[u32], info: &mut ManifestInfo) -> Option<()> {
    let hsize = le_u16(chunk, 2)? as usize;
    let name_idx = le_u32(chunk, hsize + 4)? as usize;
    let attr_start = le_u16(chunk, hsize + 8)? as usize;
    let attr_size = (le_u16(chunk, hsize + 10)? as usize).max(20);
    let attr_count = (le_u16(chunk, hsize + 12)? as usize).min(512);
    let element = strings.get(name_idx).map(String::as_str).unwrap_or("");

    let mut attrs = Vec::with_capacity(attr_count);
    for i in 0..attr_count {
        let a = hsize + attr_start + i * attr_size;
        let n = le_u32(chunk, a + 4)? as usize;
        let raw = le_u32(chunk, a + 8)?;
        let data_type = *chunk.get(a + 15)?;
        let data = le_u32(chunk, a + 16)?;
        let string = if raw != u32::MAX {
            strings.get(raw as usize).cloned()
        } else if data_type == TYPE_STRING {
            strings.get(data as usize).cloned()
        } else {
            None
        };
        attrs.push(Attr {
            name: strings.get(n).cloned().unwrap_or_default(),
            res_id: res_map.get(n).copied().unwrap_or(0),
            string,
            data_type,
            data,
        });
    }
    let find = |name: &str, id: u32| attrs.iter().find(|a| (id != 0 && a.res_id == id) || a.name == name);

    match element {
        "manifest" => {
            if let Some(p) = attrs.iter().find(|a| a.name == "package").and_then(|a| a.string.clone()) {
                info.package = p;
            }
        }
        "uses-permission" | "uses-permission-sdk-23" | "uses-permission-sdk-m" => {
            if let Some(p) = find("name", ATTR_NAME).and_then(|a| a.string.clone())
                && !info.permissions.contains(&p)
            {
                info.permissions.push(p);
            }
        }
        "application" => {
            if let Some(a) = find("debuggable", ATTR_DEBUGGABLE) {
                info.debuggable = a.data_type == TYPE_INT_BOOLEAN && a.data != 0;
            }
        }
        "service" | "receiver" => {
            if let Some(p) = find("permission", ATTR_PERMISSION).and_then(|a| a.string.as_deref()) {
                match p {
                    "android.permission.BIND_ACCESSIBILITY_SERVICE" => info.accessibility_service = true,
                    "android.permission.BIND_DEVICE_ADMIN" => info.device_admin = true,
                    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" => info.notification_listener = true,
                    _ => {}
                }
            }
        }
        _ => {}
    }
    Some(())
}

/// Parses a binary `AndroidManifest.xml`.
pub fn parse_manifest(d: &[u8]) -> Option<ManifestInfo> {
    if le_u16(d, 0)? != RES_XML_TYPE {
        return None;
    }
    let header = le_u16(d, 2)? as usize;
    let total = (le_u32(d, 4)? as usize).min(d.len());
    let mut p = header;
    let mut strings = Vec::new();
    let mut res_map = Vec::new();
    let mut info = ManifestInfo::default();
    let mut chunks = 0;
    while p + 8 <= total && chunks < 100_000 {
        chunks += 1;
        let ty = le_u16(d, p)?;
        let hsize = le_u16(d, p + 2)? as usize;
        let size = le_u32(d, p + 4)? as usize;
        if size < 8 || p + size > total {
            break;
        }
        let chunk = &d[p..p + size];
        match ty {
            RES_STRING_POOL_TYPE => strings = parse_string_pool(chunk)?,
            RES_XML_RESOURCE_MAP_TYPE => {
                res_map = (hsize..size).step_by(4).filter_map(|o| le_u32(chunk, o)).collect();
            }
            RES_XML_START_ELEMENT_TYPE => {
                let _ = parse_element(chunk, &strings, &res_map, &mut info);
            }
            _ => {}
        }
        p += size;
    }
    Some(info)
}

/// Computes the permission-based risk of a manifest.
pub fn assess(manifest: ManifestInfo) -> ApkRisk {
    let has = |p: &str| manifest.permissions.iter().any(|x| x == &format!("android.permission.{p}"));
    let mut score = 0u32;
    let mut reasons = Vec::new();
    let mut add = |cond: bool, s: u32, code: &str| {
        if cond {
            score += s;
            reasons.push(code.to_string());
        }
    };
    add(has("SEND_SMS") || has("RECEIVE_SMS") || has("READ_SMS"), 10, "sms");
    add(manifest.accessibility_service, 15, "accessibility");
    add(has("SYSTEM_ALERT_WINDOW"), 5, "overlay");
    add(manifest.device_admin, 10, "device_admin");
    add(has("REQUEST_INSTALL_PACKAGES"), 5, "install_packages");
    add(has("READ_CALL_LOG") || has("READ_CONTACTS"), 5, "contacts");
    add(manifest.notification_listener, 5, "notifications");
    add(has("RECORD_AUDIO"), 5, "microphone");
    add(has("ACCESS_BACKGROUND_LOCATION"), 5, "background_location");
    add(manifest.debuggable, 5, "debuggable");
    ApkRisk { manifest, score: score.min(45), reasons }
}

/// Reads the manifest from APK bytes.
pub fn inspect(apk: &[u8]) -> Option<ApkRisk> {
    let mut zip = zip::ZipArchive::new(Cursor::new(apk)).ok()?;
    let mut f = zip.by_name("AndroidManifest.xml").ok()?;
    let mut buf = Vec::new();
    (&mut f).take(16 << 20).read_to_end(&mut buf).ok()?;
    Some(assess(parse_manifest(&buf)?))
}

pub fn analyze(data: &[u8], out: &mut Vec<Finding>) {
    let Some(risk) = inspect(data) else { return };
    if risk.score >= 20 {
        out.push(Finding::new(
            "Heur.Android.RiskyPermissions",
            risk.score,
            format!("App requests a high-risk combination of permissions: {}", risk.reasons.join(", ")),
        ));
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Builds a minimal binary manifest (UTF-8 string pool).
    pub(crate) fn build_manifest(package: &str, permissions: &[&str], accessibility: bool) -> Vec<u8> {
        let mut strings: Vec<String> = vec![
            "manifest".into(),
            "package".into(),
            package.into(),
            "uses-permission".into(),
            "name".into(),
            "service".into(),
            "permission".into(),
        ];
        let base = strings.len();
        for p in permissions {
            strings.push(p.to_string());
        }
        strings.push("android.permission.BIND_ACCESSIBILITY_SERVICE".into());
        let acc_idx = strings.len() - 1;

        // String pool chunk.
        let mut data = Vec::new();
        let mut offsets = Vec::new();
        for s in &strings {
            offsets.push(data.len() as u32);
            data.push(s.len() as u8);
            data.push(s.len() as u8);
            data.extend_from_slice(s.as_bytes());
            data.push(0);
        }
        while data.len() % 4 != 0 {
            data.push(0);
        }
        let hsize = 28u16;
        let strings_start = hsize as u32 + 4 * strings.len() as u32;
        let mut pool = Vec::new();
        pool.extend_from_slice(&RES_STRING_POOL_TYPE.to_le_bytes());
        pool.extend_from_slice(&hsize.to_le_bytes());
        pool.extend_from_slice(&((strings_start as usize + data.len()) as u32).to_le_bytes());
        pool.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        pool.extend_from_slice(&0u32.to_le_bytes());
        pool.extend_from_slice(&(1u32 << 8).to_le_bytes());
        pool.extend_from_slice(&strings_start.to_le_bytes());
        pool.extend_from_slice(&0u32.to_le_bytes());
        for o in &offsets {
            pool.extend_from_slice(&o.to_le_bytes());
        }
        pool.extend_from_slice(&data);

        let element = |name: u32, attrs: &[(u32, u32)]| -> Vec<u8> {
            let mut c = Vec::new();
            c.extend_from_slice(&RES_XML_START_ELEMENT_TYPE.to_le_bytes());
            c.extend_from_slice(&16u16.to_le_bytes());
            let size = 16 + 20 + 20 * attrs.len();
            c.extend_from_slice(&(size as u32).to_le_bytes());
            c.extend_from_slice(&[0; 8]); // line, comment
            c.extend_from_slice(&u32::MAX.to_le_bytes()); // ns
            c.extend_from_slice(&name.to_le_bytes());
            c.extend_from_slice(&20u16.to_le_bytes()); // attributeStart
            c.extend_from_slice(&20u16.to_le_bytes()); // attributeSize
            c.extend_from_slice(&(attrs.len() as u16).to_le_bytes());
            c.extend_from_slice(&[0; 6]);
            for (n, v) in attrs {
                c.extend_from_slice(&u32::MAX.to_le_bytes());
                c.extend_from_slice(&n.to_le_bytes());
                c.extend_from_slice(&v.to_le_bytes());
                c.extend_from_slice(&8u16.to_le_bytes());
                c.push(0);
                c.push(TYPE_STRING);
                c.extend_from_slice(&v.to_le_bytes());
            }
            c
        };
        let mut body = pool;
        body.extend(element(0, &[(1, 2)]));
        for i in 0..permissions.len() {
            body.extend(element(3, &[(4, (base + i) as u32)]));
        }
        if accessibility {
            body.extend(element(5, &[(6, acc_idx as u32)]));
        }
        let mut out = Vec::new();
        out.extend_from_slice(&RES_XML_TYPE.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&((body.len() + 8) as u32).to_le_bytes());
        out.extend(body);
        out
    }

    #[test]
    fn parses_manifest_and_scores() {
        let m = build_manifest(
            "com.example.demo",
            &["android.permission.INTERNET", "android.permission.RECEIVE_SMS", "android.permission.SYSTEM_ALERT_WINDOW"],
            true,
        );
        let info = parse_manifest(&m).unwrap();
        assert_eq!(info.package, "com.example.demo");
        assert_eq!(info.permissions.len(), 3);
        assert!(info.accessibility_service);
        let risk = assess(info);
        assert_eq!(risk.score, 30);
        assert_eq!(risk.reasons, vec!["sms", "accessibility", "overlay"]);
    }

    #[test]
    fn benign_manifest() {
        let risk = assess(parse_manifest(&build_manifest("com.example.ok", &["android.permission.INTERNET"], false)).unwrap());
        assert_eq!(risk.score, 0);
    }
}
