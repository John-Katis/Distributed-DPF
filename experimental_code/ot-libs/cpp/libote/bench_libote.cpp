// libOTe (osu-crypto, rev 5d419c34) over cio::Link through coproto's
// BufferingSocket: each party runs its protocol task until it blocks, sends
// everything outbound as one message and feeds the next inbound message.
// BufferingSocket frames every coproto message with a small header, which is
// counted in the bytes.
//
// Rows (see ../count_io.h): base OT (SimplestOT = CO15, Masny–Rindal;
// 128 random OTs), IKNP and KOS random OT, KOS Δ-OT (fixed Δ), Silent OT
// (BCG+19/RRT23 dual LPN, not Ferret) as COT with Δ, semi-honest and
// malicious, with the SPIN, BlkAcc3x32 (default) and ExConv7x24 codes, and KKRT / OOS 1-out-of-N random OT. Every output is checked.
#include "../count_io.h"
#include <coproto/Socket/BufferingSocket.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <libOTe/Base/MasnyRindal.h>
#include <libOTe/Base/SimplestOT.h>
#include <libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h>
#include <libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h>
#include <libOTe/NChooseOne/Oos/OosNcoOtReceiver.h>
#include <libOTe/NChooseOne/Oos/OosNcoOtSender.h>
#include <libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h>
#include <libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h>
#include <libOTe/TwoChooseOne/Kos/KosOtExtReceiver.h>
#include <libOTe/TwoChooseOne/Kos/KosOtExtSender.h>
#include <libOTe/TwoChooseOne/KosDot/KosDotExtReceiver.h>
#include <libOTe/TwoChooseOne/KosDot/KosDotExtSender.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtSender.h>
#include <functional>
#include <sstream>
#include <thread>

using namespace osuCrypto;
using coproto::BufferingSocket;

// One party's measured phases over one BufferingSocket.
struct Party {
	cio::End *e;
	int party;
	BufferingSocket sock;
	std::vector<cio::Stats> st;
	std::vector<double> t;
	Party(cio::End *e, int party) : e(e), party(party) {}

	void phase(std::function<task<>(Socket &)> f) {
		e->flush();
		cio::sync(*e, party);
		auto s0 = e->stats();
		cio::Clock c;
		auto proto = f(sock) | macoro::make_eager();
		while (true) {
			auto b = sock.getOutbound();
			if (b && b->size()) {
				e->write(b->data(), b->size());
				e->flush();
			}
			if (proto.is_ready()) break;
			auto msg = e->read_msg();
			sock.processInbound(msg);
		}
		macoro::sync_wait(std::move(proto));
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

static void emit(const char *comp, const char *sec, uint64_t n, const std::vector<std::string> &phases,
		const Party &p0, const Party &p1, bool ok) {
	for (size_t i = 0; i < phases.size(); ++i)
		cio::row("libOTe", comp, sec, n, phases[i], p0.st[i], p1.st[i], p0.t[i], p1.t[i], ok);
}

template <class OT>
void base_ot(const char *name) {
	const u64 n = 128;
	std::vector<std::array<block, 2>> m(n);
	std::vector<block> r(n);
	BitVector c(n);
	std::unique_ptr<Party> P0, P1;
	two([&](cio::End *e) {
		P0 = std::make_unique<Party>(e, 0);
		PRNG prng(sysRandomSeed());
		OT ot;
		P0->phase([&](Socket &s) { return ot.send(m, prng, s); });
	}, [&](cio::End *e) {
		P1 = std::make_unique<Party>(e, 1);
		PRNG prng(sysRandomSeed());
		c.randomize(prng);
		OT ot;
		P1->phase([&](Socket &s) { return ot.receive(c, r, prng, s); });
	});
	bool ok = true;
	for (u64 i = 0; i < n; ++i) ok &= r[i] == m[i][c[i]] && m[i][0] != m[i][1];
	emit(name, "-", n, {"all"}, *P0, *P1, ok);
}

// Random OT extension (IKNP / KOS): base OTs, then n random OTs.
template <class S, class R>
void rot(const char *comp, const char *sec, u64 n) {
	std::vector<std::array<block, 2>> m(n);
	std::vector<block> r(n);
	BitVector c(n);
	std::unique_ptr<Party> P0, P1;
	two([&](cio::End *e) {
		P0 = std::make_unique<Party>(e, 0);
		PRNG prng(sysRandomSeed());
		S ot;
		P0->phase([&](Socket &s) { return ot.genBaseOts(prng, s); });
		P0->phase([&](Socket &s) { return ot.send(m, prng, s); });
	}, [&](cio::End *e) {
		P1 = std::make_unique<Party>(e, 1);
		PRNG prng(sysRandomSeed());
		c.randomize(prng);
		R ot;
		P1->phase([&](Socket &s) { return ot.genBaseOts(prng, s); });
		P1->phase([&](Socket &s) { return ot.receive(c, r, prng, s); });
	});
	bool ok = true;
	for (u64 i = 0; i < n; ++i) ok &= r[i] == m[i][c[i]];
	emit(comp, sec, n, {"setup", "extend"}, *P0, *P1, ok);
}

// KOS Δ-OT: as rot, with the sender's messages correlated by a fixed Δ.
void kos_dot(u64 n) {
	std::vector<std::array<block, 2>> m(n);
	std::vector<block> r(n);
	BitVector c(n);
	block delta;
	std::unique_ptr<Party> P0, P1;
	two([&](cio::End *e) {
		P0 = std::make_unique<Party>(e, 0);
		PRNG prng(sysRandomSeed());
		delta = prng.get<block>();
		KosDotExtSender ot;
		ot.setDelta(delta);
		P0->phase([&](Socket &s) { return ot.genBaseOts(prng, s); });
		P0->phase([&](Socket &s) { return ot.send(m, prng, s); });
	}, [&](cio::End *e) {
		P1 = std::make_unique<Party>(e, 1);
		PRNG prng(sysRandomSeed());
		c.randomize(prng);
		KosDotExtReceiver ot;
		P1->phase([&](Socket &s) { return ot.genBaseOts(prng, s); });
		P1->phase([&](Socket &s) { return ot.receive(c, r, prng, s); });
	});
	bool ok = true, delta_ok = true;
	for (u64 i = 0; i < n; ++i) {
		ok &= r[i] == m[i][c[i]];
		delta_ok &= (m[i][0] ^ m[i][1]) == delta;
	}
	emit(delta_ok ? "dot-cot" : "dot-rot", "mal", n, {"setup", "extend"}, *P0, *P1, ok);
}

// Silent OT as COT a = b ⊕ c·Δ: base correlations, then n COTs.
void silent(bool mal, u64 n, MultType code) {
	std::vector<block> b(n), a(n);
	BitVector c(n);
	block delta;
	auto sec = mal ? SilentSecType::Malicious : SilentSecType::SemiHonest;
	std::unique_ptr<Party> P0, P1;
	two([&](cio::End *e) {
		P0 = std::make_unique<Party>(e, 0);
		PRNG prng(sysRandomSeed());
		delta = prng.get<block>();
		SilentOtExtSender ot;
		ot.configure(n, 2, 1, sec, SdNoiseDistribution::Regular, code);
		P0->phase([&](Socket &s) { return ot.genBaseCors(delta, prng, s); });
		P0->phase([&](Socket &s) { return ot.silentSend(delta, b, prng, s); });
	}, [&](cio::End *e) {
		P1 = std::make_unique<Party>(e, 1);
		PRNG prng(sysRandomSeed());
		SilentOtExtReceiver ot;
		ot.configure(n, 2, 1, sec, SdNoiseDistribution::Regular, code);
		P1->phase([&](Socket &s) { return ot.genBaseCors(prng, s); });
		P1->phase([&](Socket &s) { return ot.silentReceive(c, a, prng, s, OTType::Correlated); });
	});
	bool ok = true;
	u64 ones = 0;
	for (u64 i = 0; i < n; ++i) {
		ones += c[i];
		ok &= a[i] == (c[i] ? (b[i] ^ delta) : b[i]);
	}
	ok &= ones > n / 3 && ones < 2 * n / 3;
	std::ostringstream name;
	name << "silent-" << code;
	emit(name.str().c_str(), mal ? "mal" : "sh", n, {"setup", "extend"}, *P0, *P1, ok);
}

// 1-out-of-N random OT (KKRT semi-honest, OOS malicious): the receiver's
// encoding of its choice equals the sender's encoding of that value.
template <class S, class R>
void nco(const char *comp, bool mal, u64 n, u64 N) {
	u64 bits = log2ceil(N);
	std::vector<u64> choice(n);
	std::vector<block> enc_r(n);
	Matrix<block> enc_s(n, N);
	std::unique_ptr<Party> P0, P1;
	block seed = toBlock(42); // the check's coin, fixed here
	two([&](cio::End *e) {
		P0 = std::make_unique<Party>(e, 0);
		PRNG prng(sysRandomSeed());
		S ot;
		ot.configure(mal, 40, bits);
		P0->phase([&](Socket &s) -> task<> {
			co_await ot.genBaseOts(prng, s);
			co_await ot.init(n, prng, s);
		});
		P0->phase([&](Socket &s) -> task<> {
			co_await ot.recvCorrection(s, n);
			if (mal) co_await ot.check(s, seed);
			for (u64 i = 0; i < n; ++i)
				for (u64 x = 0; x < N; ++x) ot.encode(i, &x, &enc_s(i, x), sizeof(block));
		});
	}, [&](cio::End *e) {
		P1 = std::make_unique<Party>(e, 1);
		PRNG prng(sysRandomSeed());
		for (auto &x : choice) x = prng.get<u64>() % N;
		R ot;
		ot.configure(mal, 40, bits);
		P1->phase([&](Socket &s) -> task<> {
			co_await ot.genBaseOts(prng, s);
			co_await ot.init(n, prng, s);
		});
		P1->phase([&](Socket &s) -> task<> {
			for (u64 i = 0; i < n; ++i) ot.encode(i, &choice[i], &enc_r[i], sizeof(block));
			co_await ot.sendCorrection(s, n);
			if (mal) co_await ot.check(s, seed);
		});
	});
	bool ok = true;
	for (u64 i = 0; i < n; ++i) {
		ok &= enc_r[i] == enc_s(i, choice[i]);
		ok &= enc_r[i] != enc_s(i, (choice[i] + 1) % N);
	}
	emit(comp, mal ? "mal" : "sh", n, {"setup", "extend"}, *P0, *P1, ok);
}

int main(int argc, char **argv) {
	u64 n_ext = argc > 1 ? atoll(argv[1]) : (1 << 23);
	u64 n_sil = argc > 2 ? atoll(argv[2]) : 20000000;
	u64 n_nco = argc > 3 ? atoll(argv[3]) : (1 << 20);
	base_ot<SimplestOT>("base-co");
	base_ot<MasnyRindal>("base-mr");
	rot<IknpOtExtSender, IknpOtExtReceiver>("rot", "sh", n_ext);
	rot<KosOtExtSender, KosOtExtReceiver>("rot", "mal", n_ext);
	kos_dot(n_ext);
	for (auto code : {MultType::Spin, MultType::BlkAcc3x32, MultType::ExConv7x24})
		for (bool mal : {false, true}) silent(mal, n_sil, code);
	nco<KkrtNcoOtSender, KkrtNcoOtReceiver>("1ofN-kkrt", false, n_nco, 8);
	nco<OosNcoOtSender, OosNcoOtReceiver>("1ofN-oos", true, n_nco, 8);
}
