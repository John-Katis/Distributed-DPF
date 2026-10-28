//! Bindings to the OT libraries used by `dpf_common::ot`:
//!
//! * emp-ot 0.3.0 (header-only, `cpp/emp_shim.cpp`): Naor–Pinkas base OT,
//!   IKNP COT / chosen OT / random OT (semi-honest, or malicious with emp's
//!   KOS-style consistency check), and Ferret COT whose base COTs are passed in.
//! * libOTe (`cpp/ote_shim.cpp`): the Masny–Rindal base OT.
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
