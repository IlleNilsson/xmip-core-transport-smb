//! The module's timing program (`doc/governance/rust-style.md` section
//! 5c): this transport held to how long Xmip takes — the millisecond rule
//! (`CONTRIBUTING.md`, *Rust is here for one reason*). A plain `cargo test`
//! leaves it out; the landing runs it after every other test of the module,
//! alone, one test at a time
//! (`cargo test --test measured --all-features -- --test-threads=1`), so
//! what is measured is Xmip's work and not its neighbors':
//!
//! - a thousand files on one session take a millisecond each at most;
//! - a thousand receives on one session take a millisecond each at most.
//!
//! Each the millisecond beyond the round's wakes, round by round beside a
//! plain wake, the fastest of five (`xcore::latency::Rounds`).

use std::time::Duration;

use transport::Configured;
use transport::Transport;
use xcore::latency::Rounds;
use xmip_core_transport_smb::{SmbTransport, session};

/// What a file or a receive wakes where a plain wake wakes one: the far end
/// and this end at each of its three requests — `CREATE`, `WRITE` and
/// `CLOSE`, or `CREATE`, `QUERY_DIRECTORY` and `CLOSE`.
const WAKES: u32 = 6;

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// The far end and the near end that sets up a session on it.
fn ends() -> (SmbTransport, std::net::TcpListener, SmbTransport) {
    let far_end = SmbTransport::new("127.0.0.1:0", session::SHARE).timing_out_after(secs(5));
    let (listener, address) = far_end.bind().expect("binding");
    let near = SmbTransport::new(address, session::SHARE).timing_out_after(secs(5));
    (far_end, listener, near)
}

#[test]
fn a_thousand_files_take_a_millisecond_each_at_most() {
    const SENDS: usize = 1000;
    let (far_end, listener, near) = ends();
    let sender = std::thread::spawn(move || {
        let mut rounds = Rounds::crossing(WAKES);
        for n in 0..SENDS {
            let name = format!("{n}.edi");
            rounds.round(|| near.send(&name, n.to_string().as_bytes()))?;
        }
        Ok::<_, transport::TransportError>(rounds)
    });
    let mut session = far_end.accept_one(&listener).expect("accepting");
    for n in 0..SENDS {
        let stored = session.next_store().expect("store").expect("one");
        assert_eq!(stored.bytes, n.to_string().as_bytes());
    }
    let rounds = sender.join().expect("thread").expect("sending");
    rounds.hold("a file");
}

#[test]
fn a_thousand_receives_take_a_millisecond_each_at_most() {
    const RECEIVES: usize = 1000;
    let (far_end, listener, near) = ends();
    let receiver = std::thread::spawn(move || {
        let mut rounds = Rounds::crossing(WAKES);
        for _ in 0..RECEIVES {
            assert!(rounds.round(|| near.receive())?.is_empty());
        }
        Ok::<_, transport::TransportError>(rounds)
    });
    // Served until the near end lets its session go.
    let mut session = far_end.accept_one(&listener).expect("accepting");
    while session.next_event().expect("served").is_some() {}
    let rounds = receiver.join().expect("thread").expect("received");
    rounds.hold("a receive");
}
