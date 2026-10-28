//! CryProt (rev 1e5cb7a) in the row format of ../rust. Both parties run as
//! tokio tasks over `cryprot_net::testing::local_conn` (QUIC on localhost).
//! Bytes are the application bytes that CryProt's metrics layer records for
//! its instrumented phases (both parties); rounds cannot be counted over QUIC
//! and are left as "-". Time is wall time of both parties together.
//!
//! Rows: SimplestOT base OT (128 random OTs), OT extension (semi-honest IKNP,
//! malicious KOS) as random OT and as COT with a chosen Δ (one extra block
//! per OT), Silent OT (dual LPN, expand-convolute code; not Ferret) as COT
//! with Δ, semi-honest and malicious.
//!
//! ```text
//! cargo run --release -- [n_ext = 2^23] [n_silent = 20,000,000]
//! ```

use cryprot_core::Block;
use cryprot_net::metrics::{new_comm_layer, CommLayerData};
use cryprot_net::testing::local_conn;
use cryprot_ot::extension::{
    MaliciousOtExtensionReceiver, MaliciousOtExtensionSender, SemiHonestOtExtensionReceiver,
    SemiHonestOtExtensionSender,
};
use cryprot_ot::silent_ot::{
    MaliciousSilentOtReceiver, MaliciousSilentOtSender, SemiHonestSilentOtReceiver, SemiHonestSilentOtSender,
};
use cryprot_ot::simplest_ot::SimplestOt;
use cryprot_ot::{random_choices, CotReceiver, CotSender, RotReceiver, RotSender};
use std::time::Instant;
use subtle::Choice;
use tracing_subscriber::layer::SubscriberExt;

fn bytes(data: &CommLayerData) -> u64 {
    data.reset().iter().map(|d| d.write.bytes_with_sub_comm).sum()
}

fn row(comp: &str, sec: &str, n: usize, phase: &str, b: u64, t: f64, ok: bool) {
    println!("CryProt,{comp},{sec},{n},{phase},{b},-,-,{t:.6},{}", if ok { "ok" } else { "FAIL" });
}

fn bit(c: &Choice) -> bool {
    c.unwrap_u8() == 1
}

fn delta() -> Block {
    Block::from(0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128)
}

async fn base(data: &CommLayerData) {
    let n = 128;
    let (c1, c2) = local_conn().await.unwrap();
    let choices = random_choices(n, &mut rand::make_rng::<rand::rngs::StdRng>());
    let (mut s, mut r) = (SimplestOt::new(c1), SimplestOt::new(c2));
    bytes(data);
    let t = Instant::now();
    let (m, got) = tokio::try_join!(s.send(n), r.receive(&choices)).unwrap();
    let t = t.elapsed().as_secs_f64();
    let ok = (0..n).all(|i| got[i] == m[i][bit(&choices[i]) as usize] && m[i][0] != m[i][1]);
    row("base-co", "-", n, "all", bytes(data), t, ok);
}

macro_rules! ext {
    ($data:expr, $sec:expr, $S:ty, $R:ty, $n:expr) => {{
        let n = $n;
        // Random OT.
        let (c1, c2) = local_conn().await.unwrap();
        let (mut s, mut r) = (<$S>::new(c1), <$R>::new(c2));
        bytes($data);
        let t = Instant::now();
        tokio::try_join!(s.do_base_ots(), r.do_base_ots()).unwrap();
        row("rot", $sec, n, "setup", bytes($data), t.elapsed().as_secs_f64(), true);
        let choices = random_choices(n, &mut rand::make_rng::<rand::rngs::StdRng>());
        let t = Instant::now();
        let (m, got) = tokio::try_join!(s.send(n), r.receive(&choices)).unwrap();
        let t = t.elapsed().as_secs_f64();
        let ok = (0..n).all(|i| got[i] == m[i][bit(&choices[i]) as usize]);
        row("rot", $sec, n, "extend", bytes($data), t, ok);
        // COT with chosen Δ, same instances (base OTs already done).
        let d = delta();
        let t = Instant::now();
        let (k, got) = tokio::try_join!(s.correlated_send(n, |_| d), r.correlated_receive(&choices)).unwrap();
        let t = t.elapsed().as_secs_f64();
        let ok = (0..n).all(|i| got[i] == if bit(&choices[i]) { k[i] ^ d } else { k[i] });
        row("cot-chosen-delta", $sec, n, "extend", bytes($data), t, ok);
    }};
}

macro_rules! silent {
    ($data:expr, $sec:expr, $S:ty, $R:ty, $n:expr) => {{
        let n = $n;
        let (c1, c2) = local_conn().await.unwrap();
        let (mut s, mut r) = (<$S>::new(c1), <$R>::new(c2));
        let d = delta();
        bytes($data);
        let t = Instant::now();
        let (k, (got, choices)) = tokio::try_join!(s.correlated_send(n, d), r.correlated_receive(n)).unwrap();
        let t = t.elapsed().as_secs_f64();
        let ones = choices.iter().filter(|c| bit(c)).count();
        let ok = ones > n / 3
            && ones < 2 * n / 3
            && (0..n).all(|i| got[i] == if bit(&choices[i]) { k[i] ^ d } else { k[i] });
        row("silent", $sec, n, "all", bytes($data), t, ok);
    }};
}

#[tokio::main]
async fn main() {
    let a: Vec<usize> = std::env::args().skip(1).map(|s| s.parse().unwrap()).collect();
    let n_ext = a.first().copied().unwrap_or(1 << 23);
    let n_sil = a.get(1).copied().unwrap_or(20_000_000);
    let (layer, data) = new_comm_layer();
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(layer)).unwrap();

    base(&data).await;
    ext!(&data, "sh", SemiHonestOtExtensionSender, SemiHonestOtExtensionReceiver, n_ext);
    ext!(&data, "mal", MaliciousOtExtensionSender, MaliciousOtExtensionReceiver, n_ext);
    silent!(&data, "sh", SemiHonestSilentOtSender, SemiHonestSilentOtReceiver, n_sil);
    silent!(&data, "mal", MaliciousSilentOtSender, MaliciousSilentOtReceiver, n_sil);
}
