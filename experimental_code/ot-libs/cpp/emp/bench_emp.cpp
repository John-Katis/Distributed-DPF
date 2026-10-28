// emp-ot 0.3.0 over cio::Link (one thread per party, both in this process).
// Party 0 is ALICE (OT sender / holds Δ), party 1 is BOB.
//
// Rows (see ../count_io.h): base OT (NP, CO; 128 chosen-message OTs), IKNP
// COT with Δ (semi-honest and malicious, setup and extend phases), IKNP
// chosen-message OT, Ferret RCOT (semi-honest and malicious; setup, first N,
// next N). Every output is checked.
#include "../count_io.h"
#include <emp-tool/emp-tool.h>
#include <emp-ot/emp-ot.h>
#include <thread>
#include <cstdlib>

using namespace emp;

class CIO : public IOChannel<CIO> {
public:
	cio::End *e;
	explicit CIO(cio::End *e) : e(e) {}
	void send_data_internal(const void *d, size_t n) { e->write(d, n); }
	void recv_data_internal(void *d, size_t n) { e->read(d, n); }
	void flush() { e->flush(); }
};

// Per-party measurement of consecutive phases.
struct Meas {
	std::vector<cio::Stats> st;
	std::vector<double> t;
	cio::Stats s0;
	cio::Clock c;
	cio::End *e;
	int party;
	Meas(cio::End *e, int party) : e(e), party(party) {}
	void start() {
		e->flush();
		cio::sync(*e, party);
		s0 = e->stats();
		c = cio::Clock();
	}
	void stop() {
		e->flush();
		st.push_back(e->stats() - s0);
		t.push_back(c.secs());
	}
};

template <class F0, class F1>
void two(F0 f0, F1 f1) {
	cio::Link L;
	std::thread th([&] { f1(&L.b); });
	f0(&L.a);
	th.join();
}

static bool eq(block a, block b) { return cmpBlock(&a, &b, 1); }

static void emit(const char *comp, const char *sec, uint64_t n, const std::vector<std::string> &phases,
		const Meas &m0, const Meas &m1, bool ok) {
	for (size_t i = 0; i < phases.size(); ++i)
		cio::row("emp-ot", comp, sec, n, phases[i], m0.st[i], m1.st[i], m0.t[i], m1.t[i], ok);
}

template <class OTT>
void base_ot(const char *name) {
	const int n = 128;
	std::vector<block> b0(n), b1(n), r(n);
	bool b[n];
	PRG prg;
	prg.random_block(b0.data(), n);
	prg.random_block(b1.data(), n);
	prg.random_bool(b, n);
	Meas *M0, *M1;
	two([&](cio::End *e) {
		CIO io(e);
		M0 = new Meas(e, 0);
		M0->start();
		OTT ot(&io);
		ot.send(b0.data(), b1.data(), n);
		M0->stop();
	}, [&](cio::End *e) {
		CIO io(e);
		M1 = new Meas(e, 1);
		M1->start();
		OTT ot(&io);
		ot.recv(r.data(), b, n);
		M1->stop();
	});
	bool ok = true;
	for (int i = 0; i < n; ++i) ok &= eq(r[i], b[i] ? b1[i] : b0[i]);
	emit(name, "-", n, {"all"}, *M0, *M1, ok);
	delete M0;
	delete M1;
}

void iknp_cot(bool mal, int64_t n) {
	std::vector<block> k(n), m(n);
	bool *b = new bool[n];
	PRG prg;
	prg.random_bool(b, n);
	block delta;
	Meas *M0, *M1;
	two([&](cio::End *e) {
		CIO io(e);
		M0 = new Meas(e, 0);
		IKNP<CIO> ot(&io, mal);
		M0->start();
		ot.setup_send();
		M0->stop();
		M0->start();
		ot.send_cot(k.data(), n);
		M0->stop();
		delta = ot.Delta;
	}, [&](cio::End *e) {
		CIO io(e);
		M1 = new Meas(e, 1);
		IKNP<CIO> ot(&io, mal);
		M1->start();
		ot.setup_recv();
		M1->stop();
		M1->start();
		ot.recv_cot(m.data(), b, n);
		M1->stop();
	});
	bool ok = true;
	for (int64_t i = 0; i < n; ++i) ok &= eq(m[i], b[i] ? (k[i] ^ delta) : k[i]);
	emit("cot", mal ? "mal" : "sh", n, {"setup", "extend"}, *M0, *M1, ok);
	delete M0;
	delete M1;
	delete[] b;
}

void iknp_ot(bool mal, int64_t n) {
	std::vector<block> b0(n), b1(n), r(n);
	bool *b = new bool[n];
	PRG prg;
	prg.random_block(b0.data(), n);
	prg.random_block(b1.data(), n);
	prg.random_bool(b, n);
	Meas *M0, *M1;
	two([&](cio::End *e) {
		CIO io(e);
		M0 = new Meas(e, 0);
		IKNP<CIO> ot(&io, mal);
		M0->start();
		ot.setup_send();
		M0->stop();
		M0->start();
		ot.send(b0.data(), b1.data(), n);
		M0->stop();
	}, [&](cio::End *e) {
		CIO io(e);
		M1 = new Meas(e, 1);
		IKNP<CIO> ot(&io, mal);
		M1->start();
		ot.setup_recv();
		M1->stop();
		M1->start();
		ot.recv(r.data(), b, n);
		M1->stop();
	});
	bool ok = true;
	for (int64_t i = 0; i < n; ++i) ok &= eq(r[i], b[i] ? b1[i] : b0[i]);
	emit("ot", mal ? "mal" : "sh", n, {"setup", "extend"}, *M0, *M1, ok);
	delete M0;
	delete M1;
	delete[] b;
}

// Two phases of n RCOTs after the setup (constructor: CO base OT, IKNP/KOS
// base COTs, the pre iteration with ferret_b13's pre parameters).
void ferret(bool mal, int64_t n) {
	std::vector<block> k0(n), k1(n), m0(n), m1(n);
	block delta;
	Meas *M0, *M1;
	two([&](cio::End *e) {
		CIO io(e);
		CIO *ios[1] = {&io};
		M0 = new Meas(e, 0);
		M0->start();
		auto *f = new FerretCOT<CIO>(ALICE, 1, ios, mal);
		M0->stop();
		delta = f->Delta;
		M0->start();
		f->rcot(k0.data(), n);
		M0->stop();
		M0->start();
		f->rcot(k1.data(), n);
		M0->stop();
		f->skip_file();
		delete f;
	}, [&](cio::End *e) {
		CIO io(e);
		CIO *ios[1] = {&io};
		M1 = new Meas(e, 1);
		M1->start();
		auto *f = new FerretCOT<CIO>(BOB, 1, ios, mal);
		M1->stop();
		M1->start();
		f->rcot(m0.data(), n);
		M1->stop();
		M1->start();
		f->rcot(m1.data(), n);
		M1->stop();
		f->skip_file();
		delete f;
	});
	// Receiver's choice bit is lsb(M), since lsb(Δ) = 1 and lsb(K) = 0.
	bool ok = true;
	int64_t ones = 0;
	for (int64_t i = 0; i < n; ++i) {
		bool c0 = getLSB(m0[i]), c1 = getLSB(m1[i]);
		ones += c0;
		ok &= eq(m0[i], c0 ? (k0[i] ^ delta) : k0[i]);
		ok &= eq(m1[i], c1 ? (k1[i] ^ delta) : k1[i]);
	}
	ok &= ones > n / 3 && ones < 2 * n / 3;
	emit("ferret", mal ? "mal" : "sh", n, {"setup", "first N", "next N"}, *M0, *M1, ok);
	delete M0;
	delete M1;
}

int main(int argc, char **argv) {
	int64_t n_ext = argc > 1 ? atoll(argv[1]) : (1 << 23);
	int64_t n_fer = argc > 2 ? atoll(argv[2]) : 20000000;
	base_ot<OTNP<CIO>>("base-np");
	base_ot<OTCO<CIO>>("base-co");
	for (bool mal : {false, true}) iknp_cot(mal, n_ext);
	for (bool mal : {false, true}) iknp_ot(mal, n_ext);
	for (bool mal : {false, true}) ferret(mal, n_fer);
}
