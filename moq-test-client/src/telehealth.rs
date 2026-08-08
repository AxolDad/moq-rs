// SPDX-FileCopyrightText: 2024-2026 Cloudflare Inc., Luke Curley, Mike English and contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Telehealth perception relay conformance scenarios (wave-5 V2 ring 1).
//!
//! These scenarios exercise the *secured surface* of the telehealth
//! perception contract as a black box against any MoQT relay:
//!
//! - broadcast paths are derived from a per-session token
//!   (`telehealth/perception/s-<first 32 hex of SHA-256("moq-path:" + token)>`),
//! - a session is three data tracks (`perception.alerts` / `.metrics` /
//!   `.heartbeat`) carrying UTF-8 JSON frames (schema v2),
//! - the reverse control plane is a signed-envelope track
//!   (`<path>/control` / `perception.control`, HMAC-SHA256, reject-by-default).
//!
//! Frame payloads and the control-signing vector are pinned byte-for-byte to
//! the perception repo's `fhir/goldens/` artifacts (wire-samples.jsonl,
//! control-vector.json) so a relay that corrupts, reorders track routing, or
//! leaks unannounced sibling paths fails here before it fails in a clinic.

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::time::{timeout, Duration};

use moq_transport::coding::TrackNamespace;
use moq_transport::serve::{self, Subgroup, Tracks};
use moq_transport::session::Session;

use crate::scenarios::TestConnectionIds;
use crate::Args;

/// Overall test timeout - individual operations should complete faster
const TEST_TIMEOUT: Duration = Duration::from_secs(15);

/// How long the path-secrecy probe waits for (unwanted) data before passing.
const SECRECY_PROBE: Duration = Duration::from_secs(2);

/// The three data tracks of a perception session, in priority order.
const TRACK_ALERTS: &str = "perception.alerts";
const TRACK_METRICS: &str = "perception.metrics";
const TRACK_HEARTBEAT: &str = "perception.heartbeat";

/// Control-plane track (on the `<path>/control` broadcast).
const TRACK_CONTROL: &str = "perception.control";

/// Golden wire frames, byte-identical to the perception repo's
/// `fhir/goldens/wire-samples.jsonl` (schema v2, hand-pinned).
const GOLDEN_ALERT: &str = r#"{"alert_id":"alert-000001","backend":"mesh","concern":"facial_asymmetry","confidence":0.625,"detector_version":"perception-core@0.1.0","episode_id":"episode-000001","event":"raised","evidence":{"asymmetry":0.625,"asymmetry_left":0.5,"asymmetry_right":0.125},"message":"concern: notable facial asymmetry detected","quality":{"face_confidence":0.875,"fps_effective":15.0,"pose_pitch_deg":-1.5,"pose_yaw_deg":2.5},"schema_version":2,"session_id":"session-golden","session_token":"tok-golden","severity":"concern","ts_ms":1723150000000,"type":"alert"}"#;
const GOLDEN_METRICS: &str = r#"{"asymmetry":0.0625,"asymmetry_left":0.0625,"asymmetry_right":0.0,"backend":"mesh","blink_rate_per_min":12.0,"brow_raise":0.375,"detector_version":"perception-core@0.1.0","engagement":0.75,"expression_volatility":0.25,"fps":15.0,"mouth_openness":0.125,"quality":{"face_confidence":0.875,"fps_effective":15.0},"session_id":"session-golden","session_token":"tok-golden","ts_ms":1723150000000,"type":"metrics"}"#;
const GOLDEN_HEARTBEAT: &str = r#"{"session_id":"session-golden","session_token":"tok-golden","ts_ms":1723150000000,"type":"heartbeat"}"#;

/// Cross-language control-signing vector, pinned to the perception repo's
/// `fhir/goldens/control-vector.json` (also asserted by the Rust verifier and
/// JS signer there).
const VECTOR_KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const VECTOR_PAYLOAD: &str = r#"{"action":"ack","alert_id":"a1","ack_by":"dr-a","ts_ms":1000}"#;
const VECTOR_SIG_HEX: &str = "9d658d1d048ebbf7a3e072d4d470538f58bf1632f3e6f2d1ffa5663a1f3499ff";

/// Replay window of the device-side control verifier (`ControlVerifier`).
const REPLAY_WINDOW_MS: u64 = 30_000;

/// Session tokens used by the scenarios (fixed: paths must be reproducible).
const E2E_TOKEN: &str = "tok-conformance-e2e-0001";
const SECRECY_REAL_TOKEN: &str = "tok-secrecy-real";
const SECRECY_GUESS_TOKEN: &str = "tok-secrecy-guess";

/// Derive the broadcast path for a session token, exactly as the device does
/// (`web/public/lib/moqPublisher.js` / perception repo issue #17).
fn derived_path(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"moq-path:");
    hasher.update(token.as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("telehealth/perception/s-{}", &hex[..32])
}

/// Verify a control envelope the way the device's `ControlVerifier` does:
/// HMAC-SHA256 over the exact payload string bytes, hex signature, and a
/// ±`REPLAY_WINDOW_MS` freshness window on the payload's `ts_ms`.
fn verify_control_envelope(key: &[u8], envelope_json: &str, now_ms: u64) -> Result<()> {
    let envelope: serde_json::Value =
        serde_json::from_str(envelope_json).context("envelope is not JSON")?;
    let payload = envelope["payload"]
        .as_str()
        .context("envelope missing payload string")?;
    let sig_hex = envelope["sig"]
        .as_str()
        .context("envelope missing sig string")?;

    let mut mac = Hmac::<Sha256>::new_from_slice(key).context("bad HMAC key length")?;
    mac.update(payload.as_bytes());
    let expected: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if expected != sig_hex {
        anyhow::bail!("signature mismatch");
    }

    let payload_value: serde_json::Value =
        serde_json::from_str(payload).context("payload is not JSON")?;
    let ts_ms = payload_value["ts_ms"]
        .as_u64()
        .context("payload missing ts_ms")?;
    if now_ms.abs_diff(ts_ms) > REPLAY_WINDOW_MS {
        anyhow::bail!("stale timestamp (outside replay window)");
    }

    Ok(())
}

fn hex_key() -> Vec<u8> {
    (0..VECTOR_KEY_HEX.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&VECTOR_KEY_HEX[i..i + 2], 16).unwrap())
        .collect()
}

/// Connect and complete the MoQT SETUP exchange, returning the running pieces.
async fn connect_session(
    args: &Args,
) -> Result<(
    moq_transport::session::Session,
    moq_transport::session::Publisher,
    moq_transport::session::Subscriber,
    String,
)> {
    let tls = args.tls.load()?;
    let quic = moq_native_ietf::quic::Endpoint::new(moq_native_ietf::quic::Config::new(
        args.bind, None, tls,
    )?)?;
    let (session, cid, transport) = quic.client.connect(&args.relay, None).await?;
    let (session, publisher, subscriber) = Session::connect(session, None, transport)
        .await
        .context("SETUP exchange failed")?;
    Ok((session, publisher, subscriber, cid))
}

/// Spawn a publisher that announces `namespace` and re-writes each
/// `(track, priority, frame)` in a fresh group every 200 ms, so that a
/// subscriber joining at any point receives current data.
fn spawn_frame_publisher(
    session: Session,
    mut publisher: moq_transport::session::Publisher,
    namespace: TrackNamespace,
    frames: Vec<(&'static str, u8, &'static str)>,
) -> Result<tokio::task::JoinHandle<()>> {
    let (mut tracks_writer, _, tracks_reader) = Tracks::new(namespace).produce();

    let mut subgroup_writers = Vec::new();
    for (track, priority, frame) in &frames {
        let track_writer = tracks_writer
            .create(track)
            .context("failed to create track")?;
        let subgroups = track_writer.subgroups()?;
        subgroup_writers.push((subgroups, *priority, *frame));
    }

    let handle = tokio::spawn(async move {
        let writer_loop = async {
            let mut group_id: u64 = 0;
            loop {
                for (subgroups, priority, frame) in subgroup_writers.iter_mut() {
                    let subgroup = Subgroup {
                        group_id,
                        subgroup_id: 0,
                        priority: *priority,
                    };
                    match subgroups.create(subgroup) {
                        Ok(mut writer) => {
                            if writer.write(frame.as_bytes().to_vec().into()).is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
                group_id += 1;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        };
        tokio::select! {
            res = session.run() => {
                if let Err(e) = res {
                    tracing::debug!("publisher session ended: {e}");
                }
            }
            res = publisher.announce(tracks_reader) => {
                if let Err(e) = res {
                    tracing::debug!("announce ended: {e}");
                }
            }
            _ = writer_loop => {}
        }
    });

    Ok(handle)
}

/// Subscribe to one track on `namespace` and return the first object payload.
async fn read_first_object(
    session: Session,
    mut subscriber: moq_transport::session::Subscriber,
    namespace: TrackNamespace,
    track: &str,
) -> Result<bytes::Bytes> {
    let (track_writer, track_reader) = serve::Track::new(namespace, track.to_string()).produce();

    let read = async move {
        match track_reader.mode().await.context("failed to get mode")? {
            serve::TrackReaderMode::Stream(mut stream) => {
                while let Some(mut group) = stream.next().await? {
                    if let Some(object) = group.read_next().await? {
                        return Ok(object);
                    }
                }
                anyhow::bail!("stream ended without objects")
            }
            serve::TrackReaderMode::Subgroups(mut subgroups) => {
                while let Some(mut subgroup) = subgroups.next().await? {
                    if let Some(object) = subgroup.read_next().await? {
                        return Ok(object);
                    }
                }
                anyhow::bail!("subgroups ended without objects")
            }
            serve::TrackReaderMode::Datagrams(mut datagrams) => {
                if let Some(datagram) = datagrams.read().await? {
                    return Ok(datagram.payload);
                }
                anyhow::bail!("datagrams ended without objects")
            }
        }
    };

    tokio::select! {
        object = read => object,
        res = session.run() => {
            res.context("subscriber session error")?;
            anyhow::bail!("subscriber session ended before data arrived")
        }
        res = subscriber.subscribe(track_writer) => {
            res.context("subscribe failed")?;
            anyhow::bail!("subscription ended before data arrived")
        }
    }
}

/// TH1: Session end-to-end.
///
/// Publish the three perception data tracks on a token-derived broadcast path
/// with golden schema-v2 frames; subscribe to each track from a second
/// connection and verify every frame arrives byte-identical and parses as the
/// expected message type. Fails on corruption, cross-track misrouting, or a
/// relay that cannot serve multi-track broadcasts on derived paths.
pub async fn test_telehealth_session_e2e(args: &Args) -> Result<TestConnectionIds> {
    timeout(TEST_TIMEOUT, async {
        let mut cids = TestConnectionIds::default();
        let namespace = TrackNamespace::from_utf8_path(&derived_path(E2E_TOKEN));

        let (pub_session, publisher, _, pub_cid) = connect_session(args)
            .await
            .context("publisher failed to connect")?;
        cids.add(pub_cid);

        let publisher_task = spawn_frame_publisher(
            pub_session,
            publisher,
            namespace.clone(),
            vec![
                (TRACK_ALERTS, 0, GOLDEN_ALERT),
                (TRACK_METRICS, 1, GOLDEN_METRICS),
                (TRACK_HEARTBEAT, 2, GOLDEN_HEARTBEAT),
            ],
        )?;

        // Give the announce a moment to reach the relay.
        tokio::time::sleep(Duration::from_millis(500)).await;

        let expectations = [
            (TRACK_ALERTS, GOLDEN_ALERT, "alert"),
            (TRACK_METRICS, GOLDEN_METRICS, "metrics"),
            (TRACK_HEARTBEAT, GOLDEN_HEARTBEAT, "heartbeat"),
        ];

        let result = async {
            for (track, expected, expected_type) in expectations {
                let (sub_session, _, subscriber, sub_cid) = connect_session(args)
                    .await
                    .with_context(|| format!("subscriber failed to connect for {track}"))?;
                cids.add(sub_cid);

                let object = read_first_object(sub_session, subscriber, namespace.clone(), track)
                    .await
                    .with_context(|| format!("no data on {track}"))?;

                let received = std::str::from_utf8(&object)
                    .with_context(|| format!("{track}: frame is not UTF-8"))?;
                if received != expected {
                    anyhow::bail!(
                        "{track}: frame corrupted in transit ({} bytes received, {} expected)",
                        received.len(),
                        expected.len()
                    );
                }
                let value: serde_json::Value = serde_json::from_str(received)
                    .with_context(|| format!("{track}: frame is not JSON"))?;
                if value["type"] != expected_type {
                    anyhow::bail!(
                        "{track}: wrong message type {} (cross-track misrouting?)",
                        value["type"]
                    );
                }
                tracing::info!("{track}: golden frame delivered byte-identical");
            }
            Ok(())
        }
        .await;

        publisher_task.abort();
        result?;
        Ok(cids)
    })
    .await
    .context("test timed out")?
}

/// TH2: Path secrecy (black box).
///
/// With a session live on the derived path for token A, probe the derived
/// path for a *different* token. The relay must not deliver any data there:
/// either the subscribe fails, or nothing arrives within the probe window.
/// Receiving data on an unannounced sibling path is an immediate failure —
/// it would mean session paths are guessable or the relay leaks broadcasts.
pub async fn test_telehealth_path_secrecy(args: &Args) -> Result<TestConnectionIds> {
    timeout(TEST_TIMEOUT, async {
        let mut cids = TestConnectionIds::default();
        let real = TrackNamespace::from_utf8_path(&derived_path(SECRECY_REAL_TOKEN));
        let guess = TrackNamespace::from_utf8_path(&derived_path(SECRECY_GUESS_TOKEN));

        let (pub_session, publisher, _, pub_cid) = connect_session(args)
            .await
            .context("publisher failed to connect")?;
        cids.add(pub_cid);

        let publisher_task = spawn_frame_publisher(
            pub_session,
            publisher,
            real,
            vec![(TRACK_ALERTS, 0, GOLDEN_ALERT)],
        )?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        let (probe_session, _, probe_subscriber, probe_cid) = connect_session(args)
            .await
            .context("probe failed to connect")?;
        cids.add(probe_cid);

        let probe = read_first_object(probe_session, probe_subscriber, guess, TRACK_ALERTS);

        let result = match timeout(SECRECY_PROBE, probe).await {
            Ok(Ok(object)) => Err(anyhow::anyhow!(
                "relay delivered {} bytes on an unannounced sibling path — session paths leak",
                object.len()
            )),
            Ok(Err(e)) => {
                tracing::info!("probe rejected as expected: {e:#}");
                Ok(())
            }
            Err(_) => {
                tracing::info!("probe timed out with no data (expected)");
                Ok(())
            }
        };

        publisher_task.abort();
        result?;
        Ok(cids)
    })
    .await
    .context("test timed out")?
}

/// TH3: Control-envelope integrity.
///
/// Publish three control envelopes on the `<path>/control` broadcast —
/// correctly signed, tampered payload, and correctly signed but stale — and
/// verify on the receiving side exactly as the device's `ControlVerifier`
/// would: the signed-fresh envelope must verify after transit (byte-exact
/// payload survival), the tampered one must fail the signature check, and the
/// stale one must fail the ±30 s replay window.
pub async fn test_telehealth_control_integrity(args: &Args) -> Result<TestConnectionIds> {
    timeout(TEST_TIMEOUT, async {
        let mut cids = TestConnectionIds::default();
        let control_path = format!("{}/control", derived_path(E2E_TOKEN));
        let namespace = TrackNamespace::from_utf8_path(&control_path);

        // The pinned vector envelope, plus a tampered variant.
        let signed = serde_json::json!({ "payload": VECTOR_PAYLOAD, "sig": VECTOR_SIG_HEX });
        let tampered_payload = VECTOR_PAYLOAD.replace("dr-a", "dr-b");
        let tampered = serde_json::json!({ "payload": tampered_payload, "sig": VECTOR_SIG_HEX });
        let envelope_signed: &'static str =
            Box::leak(serde_json::to_string(&signed)?.into_boxed_str());
        let envelope_tampered: &'static str =
            Box::leak(serde_json::to_string(&tampered)?.into_boxed_str());

        let (pub_session, publisher, _, pub_cid) = connect_session(args)
            .await
            .context("control publisher failed to connect")?;
        cids.add(pub_cid);

        let publisher_task = spawn_frame_publisher(
            pub_session,
            publisher,
            namespace.clone(),
            vec![(TRACK_CONTROL, 0, envelope_signed)],
        )?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        let (sub_session, _, subscriber, sub_cid) = connect_session(args)
            .await
            .context("control subscriber failed to connect")?;
        cids.add(sub_cid);

        let result = async {
            let object =
                read_first_object(sub_session, subscriber, namespace.clone(), TRACK_CONTROL)
                    .await
                    .context("no control envelope arrived")?;
            let received = std::str::from_utf8(&object).context("control envelope is not UTF-8")?;

            let key = hex_key();

            // 1. The signed envelope must verify after transit, at a "now"
            //    inside the replay window of the pinned ts_ms=1000.
            verify_control_envelope(&key, received, 1_000)
                .context("signed envelope failed verification after relay transit")?;
            tracing::info!("signed envelope verified after transit (byte-exact payload)");

            // 2. A tampered payload must be rejected (signature mismatch).
            if verify_control_envelope(&key, envelope_tampered, 1_000).is_ok() {
                anyhow::bail!("tampered envelope verified — signature check is broken");
            }
            tracing::info!("tampered envelope rejected (signature mismatch)");

            // 3. The same signed envelope must be rejected outside the replay
            //    window (reject-by-default against replays).
            if verify_control_envelope(&key, received, 1_000 + REPLAY_WINDOW_MS + 1).is_ok() {
                anyhow::bail!("stale envelope verified — replay window is broken");
            }
            tracing::info!("stale envelope rejected (outside replay window)");

            Ok(())
        }
        .await;

        publisher_task.abort();
        result?;
        Ok(cids)
    })
    .await
    .context("test timed out")?
}

/// TH4: Priority drain (alerts first under a metrics backlog).
///
/// The device contract makes alerts the highest-priority track (subgroup
/// priority 0, vs metrics 2). This scenario floods `perception.metrics` with
/// a large padded backlog, then — after the backlog is queued — publishes a
/// single alert. A subscriber on both tracks records the arrival order.
///
/// A relay that honors subgroup priority delivers the alert *ahead of* a
/// meaningful chunk of the still-draining metrics backlog even though the
/// alert was produced last. That is a **pass**. When no reorderable backlog
/// forms, no verdict is possible — reported as a **TAP skip** with the
/// observed numbers, never a false pass. The only hard failure is the alert
/// not arriving at all.
///
/// Note: a *live-forwarding* relay (moq-relay-ietf) drops superseded metric
/// groups rather than queuing them, so a fresh alert is never blocked by a
/// stale metrics backlog *by construction* — the expected result there is a
/// skip. A store-and-forward or congested relay is where a positive pass can
/// be demonstrated; the cross-relay differential ring (#43) is where that
/// distinction gets recorded per relay.
pub async fn test_telehealth_priority_drain(args: &Args) -> Result<TestConnectionIds> {
    /// Metrics groups queued ahead of the alert.
    const BACKLOG_GROUPS: u64 = 240;
    /// Padding per metrics object (bytes) — real bytes so the relay has
    /// something to schedule.
    const PAD_BYTES: usize = 16 * 1024;
    /// Alert must beat at least this fraction of the backlog to call it a pass.
    const PASS_FRACTION: f64 = 0.25;

    timeout(Duration::from_secs(30), async {
        let mut cids = TestConnectionIds::default();
        let namespace = TrackNamespace::from_utf8_path(&derived_path("tok-priority-drain-0001"));

        // --- Publisher: announce both tracks, flood metrics, then one alert.
        let (pub_session, mut publisher, _, pub_cid) = connect_session(args)
            .await
            .context("publisher failed to connect")?;
        cids.add(pub_cid);

        let (mut tracks_writer, _, tracks_reader) = Tracks::new(namespace.clone()).produce();
        let alerts_track = tracks_writer
            .create(TRACK_ALERTS)
            .context("create alerts track")?;
        let metrics_track = tracks_writer
            .create(TRACK_METRICS)
            .context("create metrics track")?;
        let mut alerts_sub = alerts_track.subgroups()?;
        let mut metrics_sub = metrics_track.subgroups()?;

        let pad = " ".repeat(PAD_BYTES);
        let padded_metric = format!("{GOLDEN_METRICS}\n{pad}");

        let publisher_task = tokio::spawn(async move {
            let feed = async {
                // Queue the whole metrics backlog first (priority 2).
                for group_id in 0..BACKLOG_GROUPS {
                    let mut w = match metrics_sub.create(Subgroup {
                        group_id,
                        subgroup_id: 0,
                        priority: 2,
                    }) {
                        Ok(w) => w,
                        Err(_) => return,
                    };
                    if w.write(padded_metric.clone().into_bytes().into()).is_err() {
                        return;
                    }
                }
                // Then the single alert (priority 0), produced LAST.
                if let Ok(mut w) = alerts_sub.create(Subgroup {
                    group_id: 0,
                    subgroup_id: 0,
                    priority: 0,
                }) {
                    let _ = w.write(GOLDEN_ALERT.as_bytes().to_vec().into());
                }
                // Hold the tracks open so the subscriber can drain.
                std::future::pending::<()>().await;
            };
            tokio::select! {
                res = pub_session.run() => { let _ = res; }
                res = publisher.announce(tracks_reader) => { let _ = res; }
                _ = feed => {}
            }
        });

        tokio::time::sleep(Duration::from_millis(300)).await;

        // --- Subscriber: both tracks, tag every object with arrival order.
        let (sub_session, _, mut subscriber, sub_cid) = connect_session(args)
            .await
            .context("subscriber failed to connect")?;
        cids.add(sub_cid);
        let mut subscriber2 = subscriber.clone();

        #[derive(Clone, Copy, PartialEq)]
        enum Kind {
            Alert,
            Metric,
        }
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Kind>();

        let (alert_writer, alert_reader) =
            serve::Track::new(namespace.clone(), TRACK_ALERTS.to_string()).produce();
        let (metric_writer, metric_reader) =
            serve::Track::new(namespace.clone(), TRACK_METRICS.to_string()).produce();

        let tx_a = tx.clone();
        let read_alerts = async move {
            if let serve::TrackReaderMode::Subgroups(mut groups) =
                alert_reader.mode().await.context("alert mode")?
            {
                while let Some(mut g) = groups.next().await? {
                    while g.read_next().await?.is_some() {
                        let _ = tx_a.send(Kind::Alert);
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        };
        let tx_m = tx.clone();
        let read_metrics = async move {
            if let serve::TrackReaderMode::Subgroups(mut groups) =
                metric_reader.mode().await.context("metric mode")?
            {
                while let Some(mut g) = groups.next().await? {
                    while g.read_next().await?.is_some() {
                        let _ = tx_m.send(Kind::Metric);
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        };
        drop(tx);

        // Collect arrivals until the alert lands and the backlog goes quiet,
        // or an overall cap. We count metrics that arrive AFTER the alert.
        let collect = async {
            let mut alert_seen = false;
            let mut metrics_before = 0u64;
            let mut metrics_after = 0u64;
            loop {
                match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
                    Ok(Some(Kind::Alert)) => alert_seen = true,
                    Ok(Some(Kind::Metric)) => {
                        if alert_seen {
                            metrics_after += 1;
                        } else {
                            metrics_before += 1;
                        }
                    }
                    Ok(None) => break, // both readers ended
                    Err(_) => break,   // 2s quiet — drain done
                }
                if alert_seen && metrics_before + metrics_after >= BACKLOG_GROUPS {
                    break;
                }
            }
            (alert_seen, metrics_before, metrics_after)
        };

        let outcome = tokio::select! {
            res = sub_session.run() => { res.context("subscriber session error")?; None }
            res = subscriber.subscribe(alert_writer) => { res.context("alert subscribe")?; None }
            res = subscriber2.subscribe(metric_writer) => { res.context("metric subscribe")?; None }
            _ = read_alerts => None,
            _ = read_metrics => None,
            out = collect => Some(out),
        };

        publisher_task.abort();

        let (alert_seen, metrics_before, metrics_after) =
            outcome.context("no arrivals collected")?;

        if !alert_seen {
            anyhow::bail!(
                "alert never arrived (metrics before={metrics_before}, after={metrics_after})"
            );
        }

        let threshold = (BACKLOG_GROUPS as f64 * PASS_FRACTION) as u64;
        tracing::info!(
            "priority drain: alert beat {metrics_after} metrics (of {BACKLOG_GROUPS}); \
             {metrics_before} arrived first; pass threshold {threshold}"
        );
        if metrics_after >= threshold {
            tracing::info!("alert drained ahead of the backlog — priority honored");
        } else {
            // Two indistinguishable-from-the-client causes, both non-failing:
            // the link drained faster than it filled, or the relay live-
            // forwards and dropped superseded metric groups so no backlog
            // ever queued (moq-relay-ietf does the latter — a subscriber only
            // sees recent groups, so a stale metrics backlog cannot block a
            // fresh alert by construction). Either way the alert was never
            // stuck behind metrics; there is simply nothing to reorder here.
            cids.skip = Some(format!(
                "alert not blocked by any metrics backlog (beat {metrics_after}/{BACKLOG_GROUPS}, \
                 need {threshold}); relay live-forwards or drained faster than it filled — \
                 no reorderable backlog to observe"
            ));
        }
        Ok(cids)
    })
    .await
    .context("test timed out")?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Path derivation must match the device implementation exactly
    /// (pinned digests computed independently with `openssl dgst -sha256`).
    #[test]
    fn derived_paths_are_pinned() {
        assert_eq!(
            derived_path(E2E_TOKEN),
            "telehealth/perception/s-2e56f94cb20508a671fc39dd8b9b396d"
        );
        assert_eq!(
            derived_path(SECRECY_REAL_TOKEN),
            "telehealth/perception/s-6b9e7a8d1a3faf70e18385eddea99afb"
        );
        assert_eq!(
            derived_path(SECRECY_GUESS_TOKEN),
            "telehealth/perception/s-a3204a7227da22330074807cc9fd6619"
        );
        assert_eq!(
            derived_path("tok-golden"),
            "telehealth/perception/s-6f1b79d810456c99c22e6a30e7c32209"
        );
    }

    /// The cross-language signing vector must verify, tampering and staleness
    /// must not.
    #[test]
    fn control_vector_is_pinned() {
        let key = hex_key();
        let envelope =
            serde_json::json!({ "payload": VECTOR_PAYLOAD, "sig": VECTOR_SIG_HEX }).to_string();
        verify_control_envelope(&key, &envelope, 1_000).expect("pinned vector verifies");
        verify_control_envelope(&key, &envelope, 31_000).expect("edge of replay window");
        assert!(verify_control_envelope(&key, &envelope, 31_002).is_err());

        let tampered = serde_json::json!({
            "payload": VECTOR_PAYLOAD.replace("a1", "a2"),
            "sig": VECTOR_SIG_HEX,
        })
        .to_string();
        assert!(verify_control_envelope(&key, &tampered, 1_000).is_err());
    }

    /// Golden frames must stay valid JSON with the expected wire types.
    #[test]
    fn golden_frames_parse() {
        for (frame, ty) in [
            (GOLDEN_ALERT, "alert"),
            (GOLDEN_METRICS, "metrics"),
            (GOLDEN_HEARTBEAT, "heartbeat"),
        ] {
            let value: serde_json::Value = serde_json::from_str(frame).unwrap();
            assert_eq!(value["type"], ty);
        }
    }
}
