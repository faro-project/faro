//! A Faro instance for trying the app on an emulator or a phone over USB.
//! Not a test: it is `#[ignore]`d and runs until stopped or the time is up.
//!
//! ```sh
//! FARO_EMULATOR_PORT=8787 cargo test -p faro-android --test emulator -- --ignored --nocapture
//! adb reverse tcp:8787 tcp:8787        # the phone's 127.0.0.1:8787 is this instance
//! adb shell am start -a android.intent.action.VIEW -d '<the link it prints>'
//! ```
//!
//! It runs the test harness's instance (an admin, a member with keys and an
//! approved ally), prints an enrollment link, approves the first device that
//! enrolls as the member's browser would (after its fingerprint is listed),
//! and then prints every event the device uploads, opened with the member's
//! key. The link is `http://127.0.0.1`: the client allows plain HTTP only
//! for loopback, which `adb reverse` provides.

mod support;

use std::time::{Duration, Instant};
use support::World;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "an interactive harness for the emulator, not a test"]
async fn emulator_instance() {
    support::init_logging();
    let port: u16 = std::env::var("FARO_EMULATOR_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8787);
    let minutes: u64 = std::env::var("FARO_EMULATOR_MINUTES")
        .ok()
        .and_then(|m| m.parse().ok())
        .unwrap_or(30);
    let w = World::listening_on(&format!("127.0.0.1:{port}")).await;
    let link = w.link(Some(&w.member_key_id())).await;
    println!("FARO_EMULATOR_LINK {link}");
    if let Ok(path) = std::env::var("FARO_EMULATOR_LINK_FILE") {
        std::fs::write(path, &link).expect("write the link file");
    }

    let deadline = Instant::now() + Duration::from_secs(minutes * 60);
    let mut device: Option<String> = None;
    let mut printed = 0usize;
    while Instant::now() < deadline {
        // The harness's clock is a ManualClock frozen at start; a real phone
        // signs with real time, so keep the instance's clock at real time.
        w.t.clock.set_ms(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time after 1970")
                .as_millis() as i64,
        );
        if device.is_none() {
            let r = w.t.get("/v1/me/devices", Some(&w.member_session)).await;
            let pending = r.body.as_array().and_then(|list| {
                list.iter()
                    .find(|d| d["status"] == "pending_endorsement")
                    .cloned()
            });
            if let Some(d) = pending {
                let id = d["device_id"].as_str().expect("device_id").to_owned();
                let key_id = d["key_id"].as_str().expect("key_id").to_owned();
                println!(
                    "FARO_EMULATOR_DEVICE {id} platform={} name={} fingerprint={key_id}",
                    d["platform"], d["name"]
                );
                w.endorse_named(&id, &key_id, None).await;
                println!("FARO_EMULATOR_APPROVED {id}");
                device = Some(id);
            }
        } else if let Some(id) = &device {
            let events = w.events(id).await;
            for (seq, kind, urgency, body) in events.iter().skip(printed) {
                // A flag carries its blurred thumbnail: print the start only.
                let body: String = serde_json::to_string(body)
                    .unwrap_or_default()
                    .chars()
                    .take(300)
                    .collect();
                println!("FARO_EMULATOR_EVENT seq={seq} kind={kind:?} urgency={urgency:?} {body}");
            }
            printed = printed.max(events.len());
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}
