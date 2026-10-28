// C ABI over emp-ot 0.3.0 (header-only): Naor–Pinkas base OT, IKNP COT/OT
// (semi-honest, or malicious with emp's KOS-style check), Ferret COT, and
// emp-tool's half-gates garbling of an AND gate.
//
// Every call takes the I/O callbacks and their context; emp's channel is a
// RustIO whose bytes go through them. Exceptions (emp's error(), patched by
// build.sh to throw, and a closed channel) are caught here and returned as -1,
// with the message available from ots_last_error().
//
// Ferret's base COTs: emp's FerretCOT draws them from BaseCot<IO>, which runs
// its own IKNP over Chou–Orlandi. BaseCot<RustIO> below is a specialisation
// that serves COTs handed in by the caller instead (ours: KOS/IKNP on
// Masny–Rindal or Naor–Pinkas), with emp's normalisation: the sender's K gets
// lsb 0 and the receiver's M gets lsb = choice, valid for any lsb(Δ) = 1.
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"

extern "C" {
struct OtsIo {
	// Buffers n bytes for sending. 0 on success.
	int (*write)(void *ctx, const uint8_t *p, size_t n);
	// Fills n bytes, flushing pending writes first. 0 on success, else the
	// peer is gone.
	int (*read)(void *ctx, uint8_t *p, size_t n);
	// Sends the buffered bytes as one message. 0 on success.
	int (*flush)(void *ctx);
};
}

namespace {
thread_local std::string g_err;
}

struct BaseFeed {
	const emp::block *data = nullptr; // K (sender) or M (receiver)
	const uint8_t *bits = nullptr;    // receiver's choices
	int64_t n = 0, pos = 0;
};

class RustIO : public emp::IOChannel<RustIO> {
public:
	const OtsIo *io = nullptr;
	void *ctx = nullptr;
	BaseFeed feed;
	void send_data_internal(const void *d, size_t n) {
		if (io->write(ctx, (const uint8_t *)d, n)) throw std::runtime_error("channel closed");
	}
	void recv_data_internal(void *d, size_t n) {
		if (io->read(ctx, (uint8_t *)d, n)) throw std::runtime_error("peer closed the channel");
	}
	void flush() {
		if (io->flush(ctx)) throw std::runtime_error("channel closed");
	}
};

// Must precede ferret_cot.h's first use of BaseCot<RustIO>.
#include "emp-ot/ferret/base_cot.h"

template <>
class BaseCot<RustIO> {
public:
	int party;
	block minusone, ot_delta;
	RustIO *io;
	bool malicious;

	BaseCot(int party, RustIO *io, bool malicious = false) : party(party), io(io), malicious(malicious) {
		minusone = makeBlock(0xFFFFFFFFFFFFFFFFLL, 0xFFFFFFFFFFFFFFFELL);
		ot_delta = zero_block;
	}

	void cot_gen_pre(block deltain) { ot_delta = deltain; }
	void cot_gen_pre() {}

	// The next `size` fed COTs, normalised. `bits` gets the receiver's choices.
	void take(block *out, int64_t size, bool *bits) {
		BaseFeed &f = io->feed;
		if (f.pos + size > f.n) throw std::runtime_error("Ferret needs more base COTs than were given");
		block ch[2] = {zero_block, makeBlock(0, 1)};
		for (int64_t i = 0; i < size; ++i) {
			block x = f.data[f.pos + i] & minusone;
			if (party == ALICE) {
				out[i] = x;
			} else {
				bool b = f.bits[f.pos + i] != 0;
				out[i] = x ^ ch[b];
				if (bits) bits[i] = b;
			}
		}
		f.pos += size;
	}

	void cot_gen(block *ot_data, int64_t size, bool * = nullptr) { take(ot_data, size, nullptr); }

	void cot_gen(OTPre<RustIO> *pre_ot, int64_t size, bool * = nullptr) {
		std::vector<block> d(size);
		std::vector<uint8_t> bits(size);
		take(d.data(), size, (bool *)bits.data());
		if (party == ALICE)
			pre_ot->send_pre(d.data(), ot_delta);
		else
			pre_ot->recv_pre(d.data(), (bool *)bits.data());
	}
};

#include "emp-ot/ferret/ferret_cot.h"

using namespace emp;

template <class F>
static int guard(RustIO &r, const OtsIo *io, void *ctx, F f) {
	r.io = io;
	r.ctx = ctx;
	try {
		f();
		r.flush();
		return 0;
	} catch (const std::exception &e) {
		g_err = e.what();
	} catch (...) {
		g_err = "unknown C++ exception";
	}
	return -1;
}

extern "C" {

const char *ots_last_error() { return g_err.c_str(); }

// ---- Naor–Pinkas (chosen-message; m holds m0[0..n] then m1[0..n]) ----

int ots_np_send(const OtsIo *io, void *ctx, const block *m, int64_t n) {
	RustIO r;
	return guard(r, io, ctx, [&] {
		OTNP<RustIO> ot(&r);
		ot.send(m, m + n, n);
	});
}

int ots_np_recv(const OtsIo *io, void *ctx, const uint8_t *b, int64_t n, block *out) {
	RustIO r;
	return guard(r, io, ctx, [&] {
		OTNP<RustIO> ot(&r);
		ot.recv(out, (const bool *)b, n);
	});
}

// ---- IKNP ----

struct Iknp {
	RustIO r;
	IKNP<RustIO> ot;
	explicit Iknp(bool mal) : ot(&r, mal) {}
};

void *ots_iknp_new(int malicious) { return new Iknp(malicious != 0); }
void ots_iknp_free(void *h) { delete (Iknp *)h; }

// Extension sender: base-OT receiver with choices s (Δ = s), keys k0.
int ots_iknp_setup_send(void *h, const OtsIo *io, void *ctx, const uint8_t *s, const block *k0) {
	Iknp *p = (Iknp *)h;
	return guard(p->r, io, ctx, [&] {
		block k[128];
		memcpy(k, k0, sizeof k);
		p->ot.setup_send((const bool *)s, k);
	});
}

int ots_iknp_setup_recv(void *h, const OtsIo *io, void *ctx, const block *k0, const block *k1) {
	Iknp *p = (Iknp *)h;
	return guard(p->r, io, ctx, [&] {
		block a[128], b[128];
		memcpy(a, k0, sizeof a);
		memcpy(b, k1, sizeof b);
		p->ot.setup_recv(a, b);
	});
}

void ots_iknp_delta(void *h, block *out) { *out = ((Iknp *)h)->ot.Delta; }

// COT: sender gets K, receiver M = K ⊕ b·Δ.
int ots_iknp_send_cot(void *h, const OtsIo *io, void *ctx, block *k, int64_t n) {
	Iknp *p = (Iknp *)h;
	return guard(p->r, io, ctx, [&] { p->ot.send_cot(k, n); });
}

int ots_iknp_recv_cot(void *h, const OtsIo *io, void *ctx, block *m, const uint8_t *b, int64_t n) {
	Iknp *p = (Iknp *)h;
	return guard(p->r, io, ctx, [&] { p->ot.recv_cot(m, (const bool *)b, n); });
}

// Chosen-message OT.
int ots_iknp_send(void *h, const OtsIo *io, void *ctx, const block *m0, const block *m1, int64_t n) {
	Iknp *p = (Iknp *)h;
	return guard(p->r, io, ctx, [&] { p->ot.send(m0, m1, n); });
}

int ots_iknp_recv(void *h, const OtsIo *io, void *ctx, block *out, const uint8_t *b, int64_t n) {
	Iknp *p = (Iknp *)h;
	return guard(p->r, io, ctx, [&] { p->ot.recv(out, (const bool *)b, n); });
}


// ---- Ferret ----

struct Ferret {
	RustIO r;
	RustIO *ios[1];
	FerretCOT<RustIO> *f = nullptr;
	int party;
	bool mal;
	PrimalLPNParameter param;
};

// p = {n, t, k, log_bin, n_pre, t_pre, k_pre, log_bin_pre}; sender = ALICE.
void *ots_ferret_new(int sender, int malicious, const int64_t *p) {
	Ferret *h = new Ferret;
	h->party = sender ? ALICE : BOB;
	h->mal = malicious != 0;
	try {
		h->param = PrimalLPNParameter(p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
	} catch (const std::exception &e) {
		g_err = e.what();
		delete h;
		return nullptr;
	}
	h->ios[0] = &h->r;
	return h;
}

void ots_ferret_free(void *hp) {
	Ferret *h = (Ferret *)hp;
	if (h->f) {
		h->f->skip_file();
		delete h->f;
	}
	delete h;
}

// Base COTs the setup consumes: the pre iteration's t_pre·log_bin_pre for
// the GGM trees, k_pre for LPN, and emp's 128 check COTs (taken in both modes).
int64_t ots_ferret_base_cots(const int64_t *p) { return p[5] * p[7] + p[6] + 128; }

// Setup on `n` base COTs: the sender passes K and its Δ (lsb 1), the
// receiver M and its choice bits. Runs the pre iteration.
int ots_ferret_setup(void *hp, const OtsIo *io, void *ctx, const block *delta, const block *base,
		const uint8_t *bits, int64_t n) {
	Ferret *h = (Ferret *)hp;
	return guard(h->r, io, ctx, [&] {
		h->r.feed = BaseFeed{base, bits, n, 0};
		h->f = new FerretCOT<RustIO>(h->party, 1, h->ios, h->mal, false, h->param);
		// A path that never exists, so emp never loads or stores a pre file.
		const std::string none = "/nonexistent-dpf-ot-sys/ferret-pre";
		if (h->party == ALICE)
			h->f->setup(*delta, none);
		else
			h->f->setup(none);
		h->r.feed = BaseFeed{};
	});
}

// n random COTs: sender K (lsb 0), receiver M with lsb(M) = choice.
int ots_ferret_rcot(void *hp, const OtsIo *io, void *ctx, block *out, int64_t n) {
	Ferret *h = (Ferret *)hp;
	return guard(h->r, io, ctx, [&] { h->f->rcot(out, n); });
}

// COTs still buffered inside emp, and the yield of one iteration.
void ots_ferret_state(void *hp, int64_t *left, int64_t *limit) {
	Ferret *h = (Ferret *)hp;
	*left = h->f->ot_limit - h->f->ot_used;
	*limit = h->f->ot_limit;
}

// ---- Half-gates garbling (ZRE15) with emp's MITCCRH, as emp-sh2pc's
// HalfGateGen / HalfGateEva compute an AND gate. Only the gate arithmetic:
// the tables travel through the caller's channel. ----

struct Gc {
	MITCCRH<8> h;
};

// Both parties start from the same public key s (the garbler's).
void *ots_gc_new(const block *s) {
	Gc *g = new Gc;
	g->h.setS(*s);
	return g;
}

void ots_gc_free(void *g) { delete (Gc *)g; }

// Garbler: for 0-labels (a0, b0) of n gates, the output 0-labels and two
// table rows per gate. delta must have lsb 1 (point-and-permute).
void ots_gc_garble(void *g, const block *delta, const block *a0, const block *b0, block *out0, block *tables, int64_t n) {
	Gc *h = (Gc *)g;
	for (int64_t i = 0; i < n; ++i)
		out0[i] = halfgates_garble(a0[i], a0[i] ^ *delta, b0[i], b0[i] ^ *delta, *delta, tables + 2 * i, &h->h);
}

// Evaluator: the active output labels from the active input labels.
void ots_gc_eval(void *g, const block *a, const block *b, const block *tables, block *out, int64_t n) {
	Gc *h = (Gc *)g;
	for (int64_t i = 0; i < n; ++i) out[i] = halfgates_eval(a[i], b[i], tables + 2 * i, &h->h);
}

} // extern "C"
