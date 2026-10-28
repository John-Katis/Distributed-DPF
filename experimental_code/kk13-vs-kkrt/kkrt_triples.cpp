// CrypTFlow2's bit-triple generator (_8KKOT: one 1-out-of-8 OT of 2-bit
// messages per correlated pair of triples), as dpf_common::bool2pc does it on
// our KK13, but on libOTe's KKRT 1-out-of-N OT extension (semi-honest).
//
// KKRT gives random encodings: the receiver gets enc(i, r) for its choice r,
// the sender enc(i, x) for every x. The sender then sends its 8 messages of
// 2 bits masked with the low 2 bits of enc(i, x) (16 bits per OT); the
// receiver unmasks entry r. Party 0 is the OT sender (CrypTFlow2's ALICE).
//
// Phases over ../ot-libs/cpp/count_io.h: setup (base OTs + init for all OTs),
// then `--seq` single-triple calls one after another (floram-arith's F_AND
// calls triples(1) per AND), then one batch of `--batch` triples. Every
// triple is checked: (a0 ⊕ a1) ∧ (b0 ⊕ b1) = c0 ⊕ c1.
#include "../ot-libs/cpp/count_io.h"
#include <coproto/Socket/BufferingSocket.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h>
#include <libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h>
#include <functional>
#include <thread>

using namespace osuCrypto;
using coproto::BufferingSocket;

struct Party {
	cio::End *e;
	int party;
	BufferingSocket sock;
	std::vector<cio::Stats> st;
	std::vector<double> t;
	cio::Stats s0;
	cio::Clock c;
	Party(cio::End *e, int party) : e(e), party(party) {}

	void run(std::function<task<>(Socket &)> f) {
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
	}
	void start() {
		e->flush();
		cio::sync(*e, party);
		s0 = e->stats();
		c = cio::Clock();
	}
	void stop() {
		st.push_back(e->stats() - s0);
		t.push_back(c.secs());
	}
};

struct Triple {
	bool a, b, c;
};

// One batch of m triples (the first of each _8KKOT pair, as bool2pc uses).
static std::vector<Triple> sender_batch(Party &P, KkrtNcoOtSender &ot, u64 &next, u64 m, PRNG &prng) {
	std::vector<Triple> out(m);
	std::vector<u8> masked(2 * m);
	P.run([&](Socket &s) -> task<> {
		co_await ot.recvCorrection(s, m);
		for (u64 i = 0; i < m; ++i) {
			bool a = prng.getBit(), b0 = prng.getBit(), b1 = prng.getBit(), c0 = prng.getBit(), c1 = prng.getBit();
			u16 word = 0;
			for (u64 j = 0; j < 8; ++j) {
				bool ja = j & 1, jb0 = j & 2, jb1 = j & 4;
				u8 msg = (u8)((((a ^ ja) & (b0 ^ jb0)) ^ c0) | (((a ^ ja) & (b1 ^ jb1)) ^ c1) << 1);
				block enc;
				ot.encode(next + i, &j, &enc, sizeof(block));
				word |= (u16)((msg ^ (enc.get<u8>(0) & 3)) & 3) << (2 * j);
			}
			memcpy(&masked[2 * i], &word, 2);
			out[i] = {a, b0, c0};
		}
		co_await s.send(std::move(masked));
	});
	next += m;
	return out;
}

static std::vector<Triple> recver_batch(Party &P, KkrtNcoOtReceiver &ot, u64 &next, u64 m, PRNG &prng) {
	std::vector<Triple> out(m);
	std::vector<block> enc(m);
	std::vector<u64> sel(m);
	std::vector<u8> masked(2 * m);
	P.run([&](Socket &s) -> task<> {
		for (u64 i = 0; i < m; ++i) {
			bool a = prng.getBit(), b0 = prng.getBit(), b1 = prng.getBit();
			sel[i] = (u64)a | (u64)b0 << 1 | (u64)b1 << 2;
			ot.encode(next + i, &sel[i], &enc[i], sizeof(block));
			out[i] = {a, b0, false};
		}
		co_await ot.sendCorrection(s, m);
		co_await s.recv(masked);
	});
	for (u64 i = 0; i < m; ++i) {
		u16 word;
		memcpy(&word, &masked[2 * i], 2);
		u8 res = ((word >> (2 * sel[i])) & 3) ^ (enc[i].get<u8>(0) & 3);
		out[i].c = res & 1;
	}
	next += m;
	return out;
}

int main(int argc, char **argv) {
	u64 seq = argc > 1 ? atoll(argv[1]) : 200;
	u64 batch = argc > 2 ? atoll(argv[2]) : (1 << 20);
	u64 total = seq + batch;
	std::vector<Triple> t0, t1;
	std::unique_ptr<Party> P0, P1;
	cio::Link L;
	std::thread th([&] {
		P1 = std::make_unique<Party>(&L.b, 1);
		PRNG prng(toBlock(2));
		KkrtNcoOtReceiver ot;
		ot.configure(false, 40, 3);
		u64 next = 0;
		P1->start();
		P1->run([&](Socket &s) -> task<> {
			co_await ot.genBaseOts(prng, s);
			co_await ot.init(total, prng, s);
		});
		P1->stop();
		P1->start();
		for (u64 i = 0; i < seq; ++i) {
			auto x = recver_batch(*P1, ot, next, 1, prng);
			t1.insert(t1.end(), x.begin(), x.end());
		}
		P1->stop();
		P1->start();
		auto x = recver_batch(*P1, ot, next, batch, prng);
		t1.insert(t1.end(), x.begin(), x.end());
		P1->stop();
	});
	{
		P0 = std::make_unique<Party>(&L.a, 0);
		PRNG prng(toBlock(1));
		KkrtNcoOtSender ot;
		ot.configure(false, 40, 3);
		u64 next = 0;
		P0->start();
		P0->run([&](Socket &s) -> task<> {
			co_await ot.genBaseOts(prng, s);
			co_await ot.init(total, prng, s);
		});
		P0->stop();
		P0->start();
		for (u64 i = 0; i < seq; ++i) {
			auto x = sender_batch(*P0, ot, next, 1, prng);
			t0.insert(t0.end(), x.begin(), x.end());
		}
		P0->stop();
		P0->start();
		auto x = sender_batch(*P0, ot, next, batch, prng);
		t0.insert(t0.end(), x.begin(), x.end());
		P0->stop();
	}
	th.join();
	bool ok = t0.size() == total && t1.size() == total;
	for (u64 i = 0; ok && i < total; ++i) ok = ((t0[i].a ^ t1[i].a) & (t0[i].b ^ t1[i].b)) == (t0[i].c ^ t1[i].c);
	const char *ph[3] = {"setup", "seq", "batch"};
	u64 n[3] = {total, seq, batch};
	for (int i = 0; i < 3; ++i)
		cio::row("KKRT", "and-triples", "sh", n[i], ph[i], P0->st[i], P1->st[i], P0->t[i], P1->t[i], ok);
}
