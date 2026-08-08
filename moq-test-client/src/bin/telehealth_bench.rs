// SPDX-FileCopyrightText: 2024-2026 Cloudflare Inc., Luke Curley, Mike English and contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Telehealth load / soak harness (wave-5 V2 ring, edge_emotion_engine #42).
//!
//! Drives N concurrent synthetic perception sessions against a MoQT relay,
//! each publishing the three data tracks (`perception.alerts` / `.metrics` /
//! `.heartbeat`) on its own token-derived broadcast path at contract cadence,
//! and measures end-to-end alert delivery latency and delivery ratio.
//!
//! Latency is measured in-process: each alert payload carries a monotonic
//! nanosecond stamp from a shared epoch; the session's own subscriber reads it
//! back and records `now - sent`. Publisher and subscriber share the process
//! clock, so the number is real one-way latency through the relay.
//!
//! ```text
//! moq-telehealth-bench --relay https://localhost:4443 --tls-disable-verify \
//!     --sessions 25 --duration-secs 120 [--churn] [--json]
//! ```
//!
//! Short profile (default) is a smoke-scale load; a long `--duration-secs`
//! makes it a soak. Parameters map to draft-evens-moq-bench where applicable.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use sha2::{Digest, Sha256};

use moq_transport::coding::TrackNamespace;
use moq_transport::serve::{self, Subgroup, Tracks};
use moq_transport::session::Session;

const TRACK_ALERTS: &str = "perception.alerts";
const TRACK_METRICS: &str = "perception.metrics";
const TRACK_HEARTBEAT: &str = "perception.heartbeat";

/// Contract-ish cadence (ms).
const METRICS_EVERY_MS: u64 = 1_000;
const HEARTBEAT_EVERY_MS: u64 = 10_000;
const ALERT_EVERY_MS: u64 = 2_000;

#[derive(Parser, Clone)]
#[command(name = "moq-telehealth-bench")]
#[command(about = "Telehealth load/soak harness for MoQT relays", long_about = None)]
struct Args {
    #[arg(
        short,
        long,
        default_value = "https://localhost:4443",
        env = "RELAY_URL"
    )]
    relay: url::Url,
    /// Concurrent synthetic sessions.
    #[arg(short, long, default_value_t = 25)]
    sessions: usize,
    /// How long to run (seconds).
    #[arg(short, long, default_value_t = 30)]
    duration_secs: u64,
    /// Restart each session's publisher once at the halfway mark (reconnect
    /// churn — models the token-grace reconnect path).
    #[arg(long)]
    churn: bool,
    /// Emit the summary as JSON instead of a table.
    #[arg(long)]
    json: bool,
    #[arg(long, default_value = "[::]:0")]
    bind: std::net::SocketAddr,
    #[command(flatten)]
    tls: moq_native_ietf::tls::Args,
}

fn derived_path(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"moq-path:");
    hasher.update(token.as_bytes());
    let hex: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("telehealth/perception/s-{}", &hex[..32])
}

/// Shared measurement state.
#[derive(Default)]
struct Stats {
    latencies_us: Mutex<Vec<u64>>,
    alerts_sent: AtomicU64,
    alerts_recv: AtomicU64,
}

async fn connect(
    args: &Args,
) -> Result<(
    Session,
    moq_transport::session::Publisher,
    moq_transport::session::Subscriber,
)> {
    let tls = args.tls.load()?;
    let quic = moq_native_ietf::quic::Endpoint::new(moq_native_ietf::quic::Config::new(
        args.bind, None, tls,
    )?)?;
    let (session, _cid, transport) = quic.client.connect(&args.relay, None).await?;
    let (session, publisher, subscriber) = Session::connect(session, None, transport)
        .await
        .context("SETUP failed")?;
    Ok((session, publisher, subscriber))
}

/// Run one session's publisher: metrics + heartbeat + stamped alerts until the
/// deadline. Each alert payload carries `{"seq":N,"sent_us":T,...}`.
async fn run_publisher(
    args: Args,
    token: String,
    epoch: Instant,
    deadline: Instant,
    stats: Arc<Stats>,
) {
    let feed = async {
        let (session, mut publisher, _) = connect(&args).await.context("pub connect")?;
        let namespace = TrackNamespace::from_utf8_path(&derived_path(&token));
        let (mut tracks, _, reader) = Tracks::new(namespace).produce();
        let mut alerts = tracks.create(TRACK_ALERTS).context("alerts")?.subgroups()?;
        let mut metrics = tracks
            .create(TRACK_METRICS)
            .context("metrics")?
            .subgroups()?;
        let mut heartbeat = tracks.create(TRACK_HEARTBEAT).context("hb")?.subgroups()?;

        let write = async {
            let mut group: u64 = 0;
            let mut next_metric = Instant::now();
            let mut next_alert = Instant::now() + Duration::from_millis(ALERT_EVERY_MS);
            let mut next_hb = Instant::now() + Duration::from_millis(HEARTBEAT_EVERY_MS);
            let mut seq: u64 = 0;
            while Instant::now() < deadline {
                let now = Instant::now();
                if now >= next_metric {
                    let f = format!(r#"{{"type":"metrics","seq":{seq}}}"#);
                    write_one(&mut metrics, group, 1, &f);
                    group += 1;
                    next_metric += Duration::from_millis(METRICS_EVERY_MS);
                }
                if now >= next_alert {
                    let sent_us = epoch.elapsed().as_micros() as u64;
                    let f = format!(
                        r#"{{"type":"alert","seq":{seq},"sent_us":{sent_us},"severity":"concern"}}"#
                    );
                    write_one(&mut alerts, group, 0, &f);
                    group += 1;
                    seq += 1;
                    stats.alerts_sent.fetch_add(1, Ordering::Relaxed);
                    next_alert += Duration::from_millis(ALERT_EVERY_MS);
                }
                if now >= next_hb {
                    let f = r#"{"type":"heartbeat"}"#.to_string();
                    write_one(&mut heartbeat, group, 2, &f);
                    group += 1;
                    next_hb += Duration::from_millis(HEARTBEAT_EVERY_MS);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Ok::<(), anyhow::Error>(())
        };
        tokio::select! {
            res = session.run() => { res.context("pub session")?; }
            res = publisher.announce(reader) => { res.context("announce")?; }
            res = write => { res?; }
        }
        Ok::<(), anyhow::Error>(())
    };
    if let Err(e) = feed.await {
        tracing::debug!("publisher {token} ended: {e:#}");
    }
}

fn write_one(subgroups: &mut serve::SubgroupsWriter, group_id: u64, priority: u8, payload: &str) {
    if let Ok(mut w) = subgroups.create(Subgroup {
        group_id,
        subgroup_id: 0,
        priority,
    }) {
        let _ = w.write(payload.as_bytes().to_vec().into());
    }
}

/// Run one session's subscriber: read alerts, record latency vs the stamped
/// `sent_us`.
async fn run_subscriber(
    args: Args,
    token: String,
    epoch: Instant,
    deadline: Instant,
    stats: Arc<Stats>,
) {
    let sub = async {
        let (session, _, mut subscriber) = connect(&args).await.context("sub connect")?;
        let namespace = TrackNamespace::from_utf8_path(&derived_path(&token));
        let (writer, reader) = serve::Track::new(namespace, TRACK_ALERTS.to_string()).produce();

        let read = async {
            if let serve::TrackReaderMode::Subgroups(mut groups) =
                reader.mode().await.context("mode")?
            {
                while Instant::now() < deadline {
                    let Some(mut g) = groups.next().await? else {
                        break;
                    };
                    while let Some(obj) = g.read_next().await? {
                        let recv_us = epoch.elapsed().as_micros() as u64;
                        if let Some(sent_us) = parse_sent_us(&obj) {
                            stats.alerts_recv.fetch_add(1, Ordering::Relaxed);
                            stats
                                .latencies_us
                                .lock()
                                .unwrap()
                                .push(recv_us.saturating_sub(sent_us));
                        }
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        };
        tokio::select! {
            res = session.run() => { res.context("sub session")?; }
            res = subscriber.subscribe(writer) => { res.context("subscribe")?; }
            res = read => { res?; }
        }
        Ok::<(), anyhow::Error>(())
    };
    if let Err(e) = sub.await {
        tracing::debug!("subscriber {token} ended: {e:#}");
    }
}

fn parse_sent_us(obj: &[u8]) -> Option<u64> {
    let v: serde_json::Value = serde_json::from_slice(obj).ok()?;
    v.get("sent_us")?.as_u64()
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx]
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let args = Args::parse();
    let epoch = Instant::now();
    let deadline = epoch + Duration::from_secs(args.duration_secs);
    let stats = Arc::new(Stats::default());

    let tokens: Vec<String> = (0..args.sessions)
        .map(|i| format!("tok-bench-{i:04}"))
        .collect();
    let mut tasks = Vec::new();

    // Publishers first (staggered) — the relay closes a subscribe to a path
    // that has not been announced yet, so announces must land first.
    for token in &tokens {
        let pub_args = args.clone();
        let pub_token = token.clone();
        let pub_stats = stats.clone();
        tasks.push(tokio::spawn(async move {
            run_publisher(
                pub_args.clone(),
                pub_token.clone(),
                epoch,
                deadline,
                pub_stats.clone(),
            )
            .await;
            // Churn: reconnect the publisher for the second half.
            if pub_args.churn && Instant::now() < deadline {
                run_publisher(pub_args, pub_token, epoch, deadline, pub_stats).await;
            }
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Let announces propagate, then bring up subscribers.
    tokio::time::sleep(Duration::from_millis(500)).await;
    for token in &tokens {
        tasks.push(tokio::spawn(run_subscriber(
            args.clone(),
            token.clone(),
            epoch,
            deadline,
            stats.clone(),
        )));
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Wait for the run to finish.
    tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
    tokio::time::sleep(Duration::from_millis(500)).await; // drain tail
    for t in tasks {
        t.abort();
    }

    let mut lat = stats.latencies_us.lock().unwrap().clone();
    lat.sort_unstable();
    let sent = stats.alerts_sent.load(Ordering::Relaxed);
    let recv = stats.alerts_recv.load(Ordering::Relaxed);
    let ratio = if sent > 0 {
        recv as f64 / sent as f64
    } else {
        0.0
    };
    let ms = |us: u64| us as f64 / 1000.0;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "format": "telehealth-bench/v1",
                "sessions": args.sessions,
                "duration_secs": args.duration_secs,
                "churn": args.churn,
                "alerts_sent": sent,
                "alerts_received": recv,
                "delivery_ratio": ratio,
                "latency_ms": {
                    "p50": ms(percentile(&lat, 0.50)),
                    "p95": ms(percentile(&lat, 0.95)),
                    "p99": ms(percentile(&lat, 0.99)),
                    "max": ms(*lat.last().unwrap_or(&0)),
                },
            }))?
        );
    } else {
        println!("telehealth-bench/v1");
        println!("  sessions:        {}", args.sessions);
        println!(
            "  duration:        {}s (churn={})",
            args.duration_secs, args.churn
        );
        println!("  alerts sent:     {sent}");
        println!(
            "  alerts received: {recv}  (delivery {:.1}%)",
            ratio * 100.0
        );
        println!(
            "  alert latency:   p50={:.1}ms  p95={:.1}ms  p99={:.1}ms  max={:.1}ms",
            ms(percentile(&lat, 0.50)),
            ms(percentile(&lat, 0.95)),
            ms(percentile(&lat, 0.99)),
            ms(*lat.last().unwrap_or(&0)),
        );
    }
    Ok(())
}
