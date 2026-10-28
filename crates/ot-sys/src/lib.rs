//! Bindings to the OT libraries used by `dpf_common::ot`:
//!
//! * emp-ot 0.3.0 (header-only, `cpp/emp_shim.cpp`): Naor–Pinkas base OT,
//!   IKNP COT / chosen OT / random OT (semi-honest, or malicious with emp's
//!   KOS-style consistency check), and Ferret COT whose base COTs are passed in.
//! * libOTe (`cpp/ote_shim.cpp`): the Masny–Rindal base OT.
//! * SCI from EzPC (`cpp/sci_shim.cpp`, with `cpp/sci_override/` replacing
//!   its sockets): OTPack with KK13, CrypTFlow2's bit triples and SiRNN's
//!   multiplexer, over a [`SharedTransport`] (SCI uses two threads).
//! * emp-tool's half-gates garbling of AND gates ([`HalfGates`]).
//!
//! The libraries speak through a [`Transport`] (in `dpf_common`, the
//! `Channel`): emp's byte stream is buffered and leaves as one message
//! whenever emp flushes or starts to read, libOTe's coproto messages are sent
//! one by one. A failed check inside a library, or a peer that closed its end,
//! surfaces as [`OtError`].
//!
//! Blocks are `u128` (little-endian, the memory layout of `__m128i`); choice
//! bits are `bool`.

use std::ffi::{c_char, c_int, c_void, CStr};

/// A message transport between the two parties.
pub trait Transport {
    /// Sends one message. `false` if the peer is gone.
    fn send_msg(&mut self, msg: Vec<u8>) -> bool;
    /// Receives the next message. `None` if the peer is gone.
    fn recv_msg(&mut self) -> Option<Vec<u8>>;
}

/// An error reported by a library (a failed consistency check, or the peer
/// closing the channel).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtError(pub String);

impl std::fmt::Display for OtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for OtError {}

#[repr(C)]
struct OtsIo {
    write: extern "C" fn(*mut c_void, *const u8, usize) -> c_int,
    read: extern "C" fn(*mut c_void, *mut u8, usize) -> c_int,
    flush: extern "C" fn(*mut c_void) -> c_int,
}

#[repr(C)]
struct OtsMsg {
    send: extern "C" fn(*mut c_void, *const u8, usize) -> c_int,
    recv: extern "C" fn(*mut c_void, *mut *const u8, *mut usize) -> c_int,
}

// `u128` buffers are passed by pointer only: 16 bytes, 16-aligned on x86-64,
// the layout of emp's and libOTe's `block` (__m128i).
#[allow(improper_ctypes)]
unsafe extern "C" {
    fn ots_last_error() -> *const c_char;
    fn ots_np_send(io: *const OtsIo, ctx: *mut c_void, m: *const u128, n: i64) -> c_int;
    fn ots_np_recv(io: *const OtsIo, ctx: *mut c_void, b: *const u8, n: i64, out: *mut u128) -> c_int;

    fn ots_iknp_new(malicious: c_int) -> *mut c_void;
    fn ots_iknp_free(h: *mut c_void);
    fn ots_iknp_setup_send(h: *mut c_void, io: *const OtsIo, ctx: *mut c_void, s: *const u8, k0: *const u128) -> c_int;
    fn ots_iknp_setup_recv(h: *mut c_void, io: *const OtsIo, ctx: *mut c_void, k0: *const u128, k1: *const u128) -> c_int;
    fn ots_iknp_delta(h: *mut c_void, out: *mut u128);
    fn ots_iknp_send_cot(h: *mut c_void, io: *const OtsIo, ctx: *mut c_void, k: *mut u128, n: i64) -> c_int;
    fn ots_iknp_recv_cot(h: *mut c_void, io: *const OtsIo, ctx: *mut c_void, m: *mut u128, b: *const u8, n: i64) -> c_int;
    fn ots_iknp_send(h: *mut c_void, io: *const OtsIo, ctx: *mut c_void, m0: *const u128, m1: *const u128, n: i64) -> c_int;
    fn ots_iknp_recv(h: *mut c_void, io: *const OtsIo, ctx: *mut c_void, out: *mut u128, b: *const u8, n: i64) -> c_int;
    fn ots_iknp_send_rot(h: *mut c_void, io: *const OtsIo, ctx: *mut c_void, m0: *mut u128, m1: *mut u128, n: i64) -> c_int;
    fn ots_iknp_recv_rot(h: *mut c_void, io: *const OtsIo, ctx: *mut c_void, out: *mut u128, b: *const u8, n: i64) -> c_int;

    fn ots_ferret_new(sender: c_int, malicious: c_int, p: *const i64) -> *mut c_void;
    fn ots_ferret_free(h: *mut c_void);
    fn ots_ferret_base_cots(p: *const i64) -> i64;
    fn ots_ferret_setup(
        h: *mut c_void,
        io: *const OtsIo,
        ctx: *mut c_void,
        delta: *const u128,
        base: *const u128,
        bits: *const u8,
        n: i64,
    ) -> c_int;
    fn ots_ferret_rcot(h: *mut c_void, io: *const OtsIo, ctx: *mut c_void, out: *mut u128, n: i64) -> c_int;
    fn ots_ferret_state(h: *mut c_void, left: *mut i64, limit: *mut i64);

    fn ots_mr_last_error() -> *const c_char;
    fn ots_mr_send(io: *const OtsMsg, ctx: *mut c_void, seed: *const u8, out: *mut u128, n: i64) -> c_int;
    fn ots_mr_recv(io: *const OtsMsg, ctx: *mut c_void, seed: *const u8, b: *const u8, out: *mut u128, n: i64) -> c_int;
}

/// One library call's view of the transport: emp's writes are buffered until
/// a flush or a read, reads are served from the current inbound message.
struct Bridge<'a, T: Transport> {
    t: &'a mut T,
    wbuf: Vec<u8>,
    rbuf: Vec<u8>,
    rpos: usize,
    /// Byte offset (counted over everything written in this call) whose low
    /// bit is flipped on the way out, for tests of the malicious checks.
    fault: Option<usize>,
    written: usize,
}

impl<'a, T: Transport> Bridge<'a, T> {
    fn new(t: &'a mut T, fault: Option<usize>) -> Self {
        Bridge { t, wbuf: Vec::new(), rbuf: Vec::new(), rpos: 0, fault, written: 0 }
    }

    fn flush(&mut self) -> bool {
        if self.wbuf.is_empty() {
            return true;
        }
        self.t.send_msg(std::mem::take(&mut self.wbuf))
    }

    fn ctx(&mut self) -> *mut c_void {
        self as *mut Self as *mut c_void
    }

    /// Ends the call: everything written is sent, everything received used.
    fn finish(mut self) -> Result<(), OtError> {
        if !self.flush() {
            return Err(OtError("peer closed the channel".into()));
        }
        assert_eq!(self.rpos, self.rbuf.len(), "a library call left part of a message unread");
        Ok(())
    }
}

extern "C" fn io_write<T: Transport>(ctx: *mut c_void, p: *const u8, n: usize) -> c_int {
    let b = unsafe { &mut *(ctx as *mut Bridge<T>) };
    let start = b.wbuf.len();
    b.wbuf.extend_from_slice(unsafe { std::slice::from_raw_parts(p, n) });
    if let Some(at) = b.fault {
        if at >= b.written && at < b.written + n {
            b.wbuf[start + at - b.written] ^= 1;
            b.fault = None;
        }
    }
    b.written += n;
    0
}

extern "C" fn io_read<T: Transport>(ctx: *mut c_void, p: *mut u8, n: usize) -> c_int {
    let b = unsafe { &mut *(ctx as *mut Bridge<T>) };
    if !b.flush() {
        return 1;
    }
    let out = unsafe { std::slice::from_raw_parts_mut(p, n) };
    let mut off = 0;
    while off < n {
        if b.rpos == b.rbuf.len() {
            match b.t.recv_msg() {
                Some(m) => {
                    b.rbuf = m;
                    b.rpos = 0;
                }
                None => return 1,
            }
        }
        let k = (n - off).min(b.rbuf.len() - b.rpos);
        out[off..off + k].copy_from_slice(&b.rbuf[b.rpos..b.rpos + k]);
        b.rpos += k;
        off += k;
    }
    0
}

extern "C" fn io_flush<T: Transport>(ctx: *mut c_void) -> c_int {
    let b = unsafe { &mut *(ctx as *mut Bridge<T>) };
    if b.flush() { 0 } else { 1 }
}

extern "C" fn msg_send<T: Transport>(ctx: *mut c_void, p: *const u8, n: usize) -> c_int {
    let b = unsafe { &mut *(ctx as *mut Bridge<T>) };
    let mut m = unsafe { std::slice::from_raw_parts(p, n) }.to_vec();
    if let Some(at) = b.fault {
        if at >= b.written && at < b.written + n {
            m[at - b.written] ^= 1;
            b.fault = None;
        }
    }
    b.written += n;
    if b.t.send_msg(m) { 0 } else { 1 }
}

extern "C" fn msg_recv<T: Transport>(ctx: *mut c_void, p: *mut *const u8, n: *mut usize) -> c_int {
    let b = unsafe { &mut *(ctx as *mut Bridge<T>) };
    match b.t.recv_msg() {
        Some(m) => {
            b.rbuf = m;
            b.rpos = b.rbuf.len();
            unsafe {
                *p = b.rbuf.as_ptr();
                *n = b.rbuf.len();
            }
            0
        }
        None => 1,
    }
}

fn io<T: Transport>() -> OtsIo {
    OtsIo { write: io_write::<T>, read: io_read::<T>, flush: io_flush::<T> }
}

fn msg<T: Transport>() -> OtsMsg {
    OtsMsg { send: msg_send::<T>, recv: msg_recv::<T> }
}

fn last(f: unsafe extern "C" fn() -> *const c_char) -> OtError {
    OtError(unsafe { CStr::from_ptr(f()) }.to_string_lossy().into_owned())
}

/// Runs one emp call over `t`.
fn emp_call<T: Transport>(t: &mut T, fault: Option<usize>, f: impl FnOnce(*const OtsIo, *mut c_void) -> c_int) -> Result<(), OtError> {
    let io = io::<T>();
    let mut b = Bridge::new(t, fault);
    let rc = f(&io, b.ctx());
    if rc != 0 {
        return Err(last(ots_last_error));
    }
    b.finish()
}

fn bytes(bits: &[bool]) -> Vec<u8> {
    bits.iter().map(|&b| b as u8).collect()
}

/// Naor–Pinkas base OT (emp `OTNP`, secp256r1), chosen messages, as sender.
pub fn np_send<T: Transport>(t: &mut T, m0: &[u128], m1: &[u128]) -> Result<(), OtError> {
    assert_eq!(m0.len(), m1.len());
    let n = m0.len();
    let m: Vec<u128> = m0.iter().chain(m1).copied().collect();
    emp_call(t, None, |io, ctx| unsafe { ots_np_send(io, ctx, m.as_ptr(), n as i64) })
}

/// Naor–Pinkas base OT, as receiver: `m_{b_i}` for each choice.
pub fn np_recv<T: Transport>(t: &mut T, b: &[bool]) -> Result<Vec<u128>, OtError> {
    let bb = bytes(b);
    let mut out = vec![0u128; b.len()];
    emp_call(t, None, |io, ctx| unsafe { ots_np_recv(io, ctx, bb.as_ptr(), b.len() as i64, out.as_mut_ptr()) })?;
    Ok(out)
}

fn mr_call<T: Transport>(t: &mut T, fault: Option<usize>, f: impl FnOnce(*const OtsMsg, *mut c_void) -> c_int) -> Result<(), OtError> {
    let io = msg::<T>();
    let mut b = Bridge::new(t, fault);
    if f(&io, b.ctx()) != 0 {
        return Err(last(ots_mr_last_error));
    }
    b.finish()
}

/// Masny–Rindal base OT (libOTe), `n` random OTs as sender. `seed` seeds
/// libOTe's PRNG. `fault` flips a bit of the outgoing bytes (tests).
pub fn mr_send<T: Transport>(t: &mut T, seed: [u8; 16], n: usize, fault: Option<usize>) -> Result<Vec<(u128, u128)>, OtError> {
    let mut out = vec![0u128; 2 * n];
    mr_call(t, fault, |io, ctx| unsafe { ots_mr_send(io, ctx, seed.as_ptr(), out.as_mut_ptr(), n as i64) })?;
    Ok(out.chunks_exact(2).map(|c| (c[0], c[1])).collect())
}

/// Masny–Rindal base OT, as receiver with choices `b`.
pub fn mr_recv<T: Transport>(t: &mut T, seed: [u8; 16], b: &[bool], fault: Option<usize>) -> Result<Vec<u128>, OtError> {
    let bb = bytes(b);
    let mut out = vec![0u128; b.len()];
    mr_call(t, fault, |io, ctx| unsafe { ots_mr_recv(io, ctx, seed.as_ptr(), bb.as_ptr(), out.as_mut_ptr(), b.len() as i64) })?;
    Ok(out)
}

/// One emp `IKNP` instance (one direction).
pub struct Iknp {
    h: *mut c_void,
    /// Flips a bit at this byte offset of the next call's outgoing bytes
    /// (tests of the malicious check).
    pub fault_next: Option<usize>,
}

// The handle is only used through `&mut self`.
unsafe impl Send for Iknp {}

impl Drop for Iknp {
    fn drop(&mut self) {
        unsafe { ots_iknp_free(self.h) }
    }
}

impl Iknp {
    pub fn new(malicious: bool) -> Self {
        Iknp { h: unsafe { ots_iknp_new(malicious as c_int) }, fault_next: None }
    }

    fn call<T: Transport>(&mut self, t: &mut T, f: impl FnOnce(*mut c_void, *const OtsIo, *mut c_void) -> c_int) -> Result<(), OtError> {
        let h = self.h;
        emp_call(t, self.fault_next.take(), |io, ctx| f(h, io, ctx))
    }

    /// Extension sender (holds Δ = s): base-OT receiver outputs `k0` for choices `s`.
    pub fn setup_send<T: Transport>(&mut self, t: &mut T, s: &[bool; 128], k0: &[u128; 128]) -> Result<(), OtError> {
        let sb = bytes(s);
        self.call(t, |h, io, ctx| unsafe { ots_iknp_setup_send(h, io, ctx, sb.as_ptr(), k0.as_ptr()) })
    }

    /// Extension receiver: base-OT sender keys `(k0, k1)`.
    pub fn setup_recv<T: Transport>(&mut self, t: &mut T, k0: &[u128; 128], k1: &[u128; 128]) -> Result<(), OtError> {
        self.call(t, |h, io, ctx| unsafe { ots_iknp_setup_recv(h, io, ctx, k0.as_ptr(), k1.as_ptr()) })
    }

    /// emp's Δ (the sender's base-OT choices as a block).
    pub fn delta(&self) -> u128 {
        let mut d = 0;
        unsafe { ots_iknp_delta(self.h, &mut d) };
        d
    }

    /// `n` COTs as sender: `K`, with the receiver holding `K ⊕ b·Δ`.
    pub fn send_cot<T: Transport>(&mut self, t: &mut T, n: usize) -> Result<Vec<u128>, OtError> {
        let mut k = vec![0u128; n];
        self.call(t, |h, io, ctx| unsafe { ots_iknp_send_cot(h, io, ctx, k.as_mut_ptr(), n as i64) })?;
        Ok(k)
    }

    /// COTs as receiver on choices `b`.
    pub fn recv_cot<T: Transport>(&mut self, t: &mut T, b: &[bool]) -> Result<Vec<u128>, OtError> {
        let bb = bytes(b);
        let mut m = vec![0u128; b.len()];
        self.call(t, |h, io, ctx| unsafe { ots_iknp_recv_cot(h, io, ctx, m.as_mut_ptr(), bb.as_ptr(), b.len() as i64) })?;
        Ok(m)
    }

    /// Chosen-message OT as sender.
    pub fn send<T: Transport>(&mut self, t: &mut T, m0: &[u128], m1: &[u128]) -> Result<(), OtError> {
        assert_eq!(m0.len(), m1.len());
        self.call(t, |h, io, ctx| unsafe { ots_iknp_send(h, io, ctx, m0.as_ptr(), m1.as_ptr(), m0.len() as i64) })
    }

    /// Chosen-message OT as receiver.
    pub fn recv<T: Transport>(&mut self, t: &mut T, b: &[bool]) -> Result<Vec<u128>, OtError> {
        let bb = bytes(b);
        let mut out = vec![0u128; b.len()];
        self.call(t, |h, io, ctx| unsafe { ots_iknp_recv(h, io, ctx, out.as_mut_ptr(), bb.as_ptr(), b.len() as i64) })?;
        Ok(out)
    }

    /// Random OT as sender: `(m0, m1)` pairs.
    pub fn send_rot<T: Transport>(&mut self, t: &mut T, n: usize) -> Result<(Vec<u128>, Vec<u128>), OtError> {
        let (mut m0, mut m1) = (vec![0u128; n], vec![0u128; n]);
        self.call(t, |h, io, ctx| unsafe { ots_iknp_send_rot(h, io, ctx, m0.as_mut_ptr(), m1.as_mut_ptr(), n as i64) })?;
        Ok((m0, m1))
    }

    /// Random OT as receiver on choices `b`.
    pub fn recv_rot<T: Transport>(&mut self, t: &mut T, b: &[bool]) -> Result<Vec<u128>, OtError> {
        let bb = bytes(b);
        let mut out = vec![0u128; b.len()];
        self.call(t, |h, io, ctx| unsafe { ots_iknp_recv_rot(h, io, ctx, out.as_mut_ptr(), bb.as_ptr(), b.len() as i64) })?;
        Ok(out)
    }
}

/// emp's `PrimalLPNParameter`: `[n, t, k, log_bin, n_pre, t_pre, k_pre, log_bin_pre]`.
pub type FerretParams = [i64; 8];

/// Base COTs a Ferret setup with `p` consumes.
pub fn ferret_base_cots(p: &FerretParams) -> usize {
    unsafe { ots_ferret_base_cots(p.as_ptr()) as usize }
}

/// One emp `FerretCOT` instance (one direction).
pub struct Ferret {
    h: *mut c_void,
    /// Flips a bit at this byte offset of the next call's outgoing bytes.
    pub fault_next: Option<usize>,
}

unsafe impl Send for Ferret {}

impl Drop for Ferret {
    fn drop(&mut self) {
        unsafe { ots_ferret_free(self.h) }
    }
}

impl Ferret {
    pub fn new(sender: bool, malicious: bool, p: &FerretParams) -> Result<Self, OtError> {
        let h = unsafe { ots_ferret_new(sender as c_int, malicious as c_int, p.as_ptr()) };
        if h.is_null() {
            return Err(last(ots_last_error));
        }
        Ok(Ferret { h, fault_next: None })
    }

    fn call<T: Transport>(&mut self, t: &mut T, f: impl FnOnce(*mut c_void, *const OtsIo, *mut c_void) -> c_int) -> Result<(), OtError> {
        let h = self.h;
        emp_call(t, self.fault_next.take(), |io, ctx| f(h, io, ctx))
    }

    /// Setup (emp's pre iteration) on base COTs. Sender: `delta` (lsb 1) and
    /// its keys `K` in `base`. Receiver: `M` in `base` and its choices `bits`.
    pub fn setup<T: Transport>(&mut self, t: &mut T, delta: Option<u128>, base: &[u128], bits: &[bool]) -> Result<(), OtError> {
        let bb = bytes(bits);
        let d = delta.unwrap_or(0);
        self.call(t, |h, io, ctx| unsafe {
            ots_ferret_setup(h, io, ctx, if delta.is_some() { &d } else { std::ptr::null() }, base.as_ptr(), bb.as_ptr(), base.len() as i64)
        })
    }

    /// `n` random COTs: sender `K` (lsb 0), receiver `M` with `lsb(M)` its choice.
    pub fn rcot<T: Transport>(&mut self, t: &mut T, n: usize) -> Result<Vec<u128>, OtError> {
        let mut out = vec![0u128; n];
        if n > 0 {
            self.call(t, |h, io, ctx| unsafe { ots_ferret_rcot(h, io, ctx, out.as_mut_ptr(), n as i64) })?;
        }
        Ok(out)
    }

    /// COTs buffered inside emp and the yield of one main iteration.
    pub fn state(&self) -> (usize, usize) {
        let (mut left, mut limit) = (0, 0);
        unsafe { ots_ferret_state(self.h, &mut left, &mut limit) };
        (left as usize, limit as usize)
    }
}

// ---------------------------------------------------------------------------
// SCI (EzPC): KK13, CrypTFlow2's bit triples, SiRNN's multiplexer.
// ---------------------------------------------------------------------------

/// A transport that two threads can use at once (SCI runs its two COT
/// directions in parallel OpenMP threads), with explicit round stamps: a
/// message is stamped one after what its sending thread has received, so
/// independent parallel messages share a round whatever the thread timing.
pub trait SharedTransport: Sync {
    /// This party's clock (the largest stamp it has received).
    fn clock(&self) -> usize;
    /// Raises the party's clock to `stamp` (after a multi-threaded call).
    fn advance_clock(&self, stamp: usize);
    /// Sends one message with this stamp. `false` if the peer is gone.
    fn send_at(&self, msg: Vec<u8>, stamp: usize) -> bool;
    /// Receives the next message and its stamp, without moving the party's
    /// clock. `None` if the peer is gone. Called by one thread at a time.
    fn recv_at(&self) -> Option<(usize, Vec<u8>)>;
}

#[repr(C)]
struct OtsSciIo {
    write: extern "C" fn(*mut c_void, c_int, *const u8, usize) -> c_int,
    read: extern "C" fn(*mut c_void, c_int, *mut u8, usize) -> c_int,
    flush: extern "C" fn(*mut c_void, c_int) -> c_int,
}

#[allow(improper_ctypes)]
unsafe extern "C" {
    fn ots_sci_last_error() -> *const c_char;
    fn ots_sci_new(party: c_int, io: *const OtsSciIo, ctx: *mut c_void) -> *mut c_void;
    fn ots_sci_free(h: *mut c_void);
    fn ots_sci_triples(h: *mut c_void, io: *const OtsSciIo, ctx: *mut c_void, a: *mut u8, b: *mut u8, c: *mut u8, n: i32) -> c_int;
    fn ots_sci_mux(h: *mut c_void, io: *const OtsSciIo, ctx: *mut c_void, sel: *const u8, x: *const u64, y: *mut u64, n: i32, bw: i32) -> c_int;

    fn ots_gc_new(s: *const u128) -> *mut c_void;
    fn ots_gc_free(g: *mut c_void);
    fn ots_gc_garble(g: *mut c_void, delta: *const u128, a0: *const u128, b0: *const u128, out0: *mut u128, tables: *mut u128, n: i64);
    fn ots_gc_eval(g: *mut c_void, a: *const u128, b: *const u128, tables: *const u128, out: *mut u128, n: i64);
}

/// SCI's three streams (io, io_rev, io_GC).
const SCI_STREAMS: usize = 3;

#[derive(Default)]
struct SciStream {
    wbuf: Vec<u8>,
    rbuf: Vec<u8>,
    rpos: usize,
}

#[derive(Default)]
struct Demux {
    queues: [std::collections::VecDeque<(usize, Vec<u8>)>; SCI_STREAMS],
    /// A thread is blocked in `recv_shared`; the others wait for it.
    reading: bool,
    closed: bool,
}

/// One SCI call's view of the transport: every write leaves at once as one
/// message tagged with its stream's index (one byte), and each stream has a
/// read buffer fed by a demultiplexer, so the two COT threads of SiRNN's
/// multiplexer can wait on their own streams at the same time.
struct SciBridge<'a, T: SharedTransport> {
    t: &'a T,
    streams: [std::sync::Mutex<SciStream>; SCI_STREAMS],
    demux: std::sync::Mutex<Demux>,
    cv: std::sync::Condvar,
    /// The party's clock when the call started: where every thread begins.
    base: usize,
    /// Per thread, the largest stamp it has received in this call.
    clocks: std::sync::Mutex<std::collections::HashMap<std::thread::ThreadId, usize>>,
}

impl<'a, T: SharedTransport> SciBridge<'a, T> {
    fn new(t: &'a T) -> Self {
        let base = t.clock();
        SciBridge { t, streams: Default::default(), demux: Default::default(), cv: Default::default(), base, clocks: Default::default() }
    }

    fn thread_clock(&self) -> usize {
        *self.clocks.lock().unwrap().get(&std::thread::current().id()).unwrap_or(&self.base)
    }

    fn saw(&self, stamp: usize) {
        let mut c = self.clocks.lock().unwrap();
        let e = c.entry(std::thread::current().id()).or_insert(self.base);
        *e = (*e).max(stamp);
    }

    fn ctx(&self) -> *mut c_void {
        self as *const Self as *mut c_void
    }

    fn flush(&self, s: usize, st: &mut SciStream) -> bool {
        if st.wbuf.is_empty() {
            return true;
        }
        let mut m = Vec::with_capacity(st.wbuf.len() + 1);
        m.push(s as u8);
        m.append(&mut st.wbuf);
        self.t.send_at(m, self.thread_clock() + 1)
    }

    /// The next message of stream `s`, with its stamp.
    fn next(&self, s: usize) -> Option<(usize, Vec<u8>)> {
        let mut d = self.demux.lock().unwrap();
        loop {
            if let Some(m) = d.queues[s].pop_front() {
                return Some(m);
            }
            if d.closed {
                return None;
            }
            if d.reading {
                d = self.cv.wait(d).unwrap();
                continue;
            }
            d.reading = true;
            drop(d);
            let got = self.t.recv_at();
            d = self.demux.lock().unwrap();
            d.reading = false;
            match got {
                Some((stamp, mut m)) if !m.is_empty() && (m[0] as usize) < SCI_STREAMS => {
                    let to = m.remove(0) as usize;
                    d.queues[to].push_back((stamp, m));
                }
                _ => d.closed = true,
            }
            self.cv.notify_all();
        }
    }

    fn finish(self) -> Result<(), OtError> {
        for s in 0..SCI_STREAMS {
            let mut st = self.streams[s].lock().unwrap();
            if !self.flush(s, &mut st) {
                return Err(OtError("peer closed the channel".into()));
            }
            assert_eq!(st.rpos, st.rbuf.len(), "an SCI call left part of a message unread");
        }
        let d = self.demux.lock().unwrap();
        assert!(d.queues.iter().all(|q| q.is_empty()), "an SCI call left a message unread");
        // The party knows what any of its threads received.
        let end = self.clocks.lock().unwrap().values().copied().fold(self.base, usize::max);
        self.t.advance_clock(end);
        Ok(())
    }
}

extern "C" fn sci_write<T: SharedTransport>(ctx: *mut c_void, s: c_int, p: *const u8, n: usize) -> c_int {
    // SCI's sockets are unbuffered and its code relies on it (a thread may
    // write and then wait at an OpenMP barrier without flushing), so every
    // write leaves at once. Rounds are unaffected: they come from the
    // stamps, and writes before the next read share one.
    let b = unsafe { &*(ctx as *const SciBridge<T>) };
    let mut st = b.streams[s as usize].lock().unwrap();
    st.wbuf.extend_from_slice(unsafe { std::slice::from_raw_parts(p, n) });
    if b.flush(s as usize, &mut st) { 0 } else { 1 }
}

extern "C" fn sci_flush<T: SharedTransport>(ctx: *mut c_void, s: c_int) -> c_int {
    let b = unsafe { &*(ctx as *const SciBridge<T>) };
    let mut st = b.streams[s as usize].lock().unwrap();
    if b.flush(s as usize, &mut st) { 0 } else { 1 }
}

extern "C" fn sci_read<T: SharedTransport>(ctx: *mut c_void, s: c_int, p: *mut u8, n: usize) -> c_int {
    let b = unsafe { &*(ctx as *const SciBridge<T>) };
    let s = s as usize;
    let mut st = b.streams[s].lock().unwrap();
    if !b.flush(s, &mut st) {
        return 1;
    }
    let out = unsafe { std::slice::from_raw_parts_mut(p, n) };
    let mut off = 0;
    while off < n {
        if st.rpos == st.rbuf.len() {
            // Only this stream's thread uses `st`, so waiting with it held
            // blocks no one else.
            match b.next(s) {
                Some((stamp, m)) => {
                    b.saw(stamp);
                    st.rbuf = m;
                    st.rpos = 0;
                }
                None => return 1,
            }
        }
        let k = (n - off).min(st.rbuf.len() - st.rpos);
        out[off..off + k].copy_from_slice(&st.rbuf[st.rpos..st.rpos + k]);
        st.rpos += k;
        off += k;
    }
    0
}

fn sci_io<T: SharedTransport>() -> OtsSciIo {
    OtsSciIo { write: sci_write::<T>, read: sci_read::<T>, flush: sci_flush::<T> }
}

/// One party's SCI state: its OTPack (base OTs, IKNP both ways, KK13 for
/// N = 2..256), CrypTFlow2's triple generator and the auxiliary protocols.
pub struct Sci {
    h: *mut c_void,
}

// SCI's objects are only used through `&mut self`.
unsafe impl Send for Sci {}

impl Drop for Sci {
    fn drop(&mut self) {
        unsafe { ots_sci_free(self.h) }
    }
}

fn sci_call<T: SharedTransport>(t: &T, f: impl FnOnce(*const OtsSciIo, *mut c_void) -> c_int) -> Result<(), OtError> {
    let io = sci_io::<T>();
    let b = SciBridge::new(t);
    if f(&io, b.ctx()) != 0 {
        return Err(last(ots_sci_last_error));
    }
    b.finish()
}

impl Sci {
    /// Setup. `alice` is SCI's ALICE (the KKOT sender, our party 0).
    pub fn new<T: SharedTransport>(t: &T, alice: bool) -> Result<Self, OtError> {
        let io = sci_io::<T>();
        let b = SciBridge::new(t);
        let h = unsafe { ots_sci_new(if alice { 1 } else { 2 }, &io, b.ctx()) };
        if h.is_null() {
            return Err(last(ots_sci_last_error));
        }
        b.finish()?;
        Ok(Sci { h })
    }

    /// `n` (even) bit triples `(a, b, c)` from CrypTFlow2's `_8KKOT`: pairs
    /// `(2i, 2i+1)` come from one 1-out-of-8 KKOT and share `a`.
    pub fn triples<T: SharedTransport>(&mut self, t: &T, n: usize) -> Result<Vec<(bool, bool, bool)>, OtError> {
        assert!(n % 2 == 0, "_8KKOT makes triples in pairs");
        let (mut a, mut b, mut c) = (vec![0u8; n], vec![0u8; n], vec![0u8; n]);
        let h = self.h;
        sci_call(t, |io, ctx| unsafe { ots_sci_triples(h, io, ctx, a.as_mut_ptr(), b.as_mut_ptr(), c.as_mut_ptr(), n as i32) })?;
        Ok((0..n).map(|i| (a[i] != 0, b[i] != 0, c[i] != 0)).collect())
    }

    /// SiRNN's multiplexer: shares of `sel · x` over Z_2^bw (bw ≤ 64), with
    /// `sel` XOR-shared and `x` additively shared.
    pub fn mux<T: SharedTransport>(&mut self, t: &T, sel: &[bool], x: &[u64], bw: usize) -> Result<Vec<u64>, OtError> {
        assert!(sel.len() == x.len() && (1..=64).contains(&bw));
        let s = bytes(sel);
        let mut y = vec![0u64; x.len()];
        let h = self.h;
        sci_call(t, |io, ctx| unsafe { ots_sci_mux(h, io, ctx, s.as_ptr(), x.as_ptr(), y.as_mut_ptr(), x.len() as i32, bw as i32) })?;
        Ok(y)
    }
}

// ---------------------------------------------------------------------------
// Half-gates garbling (emp-tool, as in emp-sh2pc).
// ---------------------------------------------------------------------------

/// emp-tool's half-gates AND garbling with its MITCCRH hash keyed by a
/// public `s`. Both parties must garble/evaluate the same gates in order.
pub struct HalfGates {
    g: *mut c_void,
}

unsafe impl Send for HalfGates {}

impl Drop for HalfGates {
    fn drop(&mut self) {
        unsafe { ots_gc_free(self.g) }
    }
}

impl HalfGates {
    pub fn new(s: u128) -> Self {
        HalfGates { g: unsafe { ots_gc_new(&s) } }
    }

    /// Garbler: output 0-labels and two table rows per gate. `delta` has lsb 1.
    pub fn garble(&mut self, delta: u128, a0: &[u128], b0: &[u128]) -> (Vec<u128>, Vec<u128>) {
        assert_eq!(a0.len(), b0.len());
        let n = a0.len();
        let (mut out, mut tables) = (vec![0u128; n], vec![0u128; 2 * n]);
        unsafe { ots_gc_garble(self.g, &delta, a0.as_ptr(), b0.as_ptr(), out.as_mut_ptr(), tables.as_mut_ptr(), n as i64) };
        (out, tables)
    }

    /// Evaluator: active output labels.
    pub fn eval(&mut self, a: &[u128], b: &[u128], tables: &[u128]) -> Vec<u128> {
        assert!(a.len() == b.len() && tables.len() == 2 * a.len());
        let mut out = vec![0u128; a.len()];
        unsafe { ots_gc_eval(self.g, a.as_ptr(), b.as_ptr(), tables.as_ptr(), out.as_mut_ptr(), a.len() as i64) };
        out
    }
}
