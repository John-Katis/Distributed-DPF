// C ABI over libOTe's Masny–Rindal base OT (MR19, random OT). The protocol
// task runs on coproto's BufferingSocket: each step sends everything outbound
// as one message and feeds the next inbound one, both through the caller's
// callbacks. Errors are returned as -1, the message in ots_mr_last_error().
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>

#include <coproto/Socket/BufferingSocket.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <libOTe/Base/MasnyRindal.h>

using namespace osuCrypto;

extern "C" {
struct OtsMsg {
	// Sends one whole message. 0 on success.
	int (*send)(void *ctx, const uint8_t *p, size_t n);
	// Receives the next whole message into a buffer owned by the caller,
	// valid until the next call. 0 on success, else the peer is gone.
	int (*recv)(void *ctx, const uint8_t **p, size_t *n);
};
}

namespace {
thread_local std::string g_err;

template <class Task>
void drive(Task proto, coproto::BufferingSocket &sock, const OtsMsg *io, void *ctx) {
	auto t = std::move(proto) | macoro::make_eager();
	while (true) {
		auto b = sock.getOutbound();
		if (b && b->size() && io->send(ctx, b->data(), b->size())) throw std::runtime_error("channel closed");
		if (t.is_ready()) break;
		const uint8_t *p;
		size_t n;
		if (io->recv(ctx, &p, &n)) throw std::runtime_error("peer closed the channel");
		sock.processInbound(span<u8>((u8 *)p, n));
	}
	macoro::sync_wait(std::move(t));
}

template <class F>
int guard(F f) {
	try {
		f();
		return 0;
	} catch (const std::exception &e) {
		g_err = e.what();
	} catch (...) {
		g_err = "unknown C++ exception";
	}
	return -1;
}
} // namespace

extern "C" {

const char *ots_mr_last_error() { return g_err.c_str(); }

// n random OTs as sender: out holds the pairs (m0, m1), 2n blocks.
int ots_mr_send(const OtsMsg *io, void *ctx, const uint8_t *seed, block *out, int64_t n) {
	return guard([&] {
		PRNG prng(*(const block *)seed);
		std::vector<std::array<block, 2>> m(n);
		coproto::BufferingSocket sock;
		MasnyRindal ot;
		drive(ot.send(m, prng, sock), sock, io, ctx);
		memcpy(out, m.data(), n * sizeof(m[0]));
	});
}

// n random OTs as receiver with choices b (one byte each): out holds m_b.
int ots_mr_recv(const OtsMsg *io, void *ctx, const uint8_t *seed, const uint8_t *b, block *out, int64_t n) {
	return guard([&] {
		PRNG prng(*(const block *)seed);
		BitVector c(n);
		for (int64_t i = 0; i < n; ++i) c[i] = b[i] != 0;
		coproto::BufferingSocket sock;
		MasnyRindal ot;
		drive(ot.receive(c, span<block>(out, n), prng, sock), sock, io, ctx);
	});
}

} // extern "C"
