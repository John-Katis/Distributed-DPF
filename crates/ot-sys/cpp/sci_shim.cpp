// C ABI over SCI (EzPC f24bf3e), the library of CrypTFlow2 and SiRNN: its
// OTPack (Naor–Pinkas base OTs, IKNP in both directions, and the KK13 1-out-
// of-N extension for N = 2..256), CrypTFlow2's bit-triple generator
// (_8KKOT) and SiRNN's multiplexer (AuxProtocols::multiplexer).
//
// SCI's sockets are replaced by sci_override/utils/net_io_channel.h, which
// sends through the OtsSciIo callbacks; a handle rebinds them for every call.
// Errors (a closed channel) are returned as -1, the message in
// ots_sci_last_error().
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include "BuildingBlocks/aux-protocols.h"
#include "Millionaire/bit-triple-generator.h"
#include "OT/ot_pack.h"
#include "utils/io_pack.h"

namespace {
thread_local std::string g_err;

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

struct Sci {
	int party; // sci::ALICE = 1 (KKOT sender) or sci::BOB = 2
	sci::IOPack *iopack = nullptr;
	sci::OTPack *otpack = nullptr;
	TripleGenerator *triples = nullptr;
	AuxProtocols *aux = nullptr;

	void flush() {
		iopack->io->flush();
		iopack->io_rev->flush();
		iopack->io_GC->flush();
	}
};
} // namespace

extern "C" {

const char *ots_sci_last_error() { return g_err.c_str(); }

// Sets up one party: OTPack's base OTs and extensions (as SCI's own
// programs do), the triple generator and the auxiliary protocols.
void *ots_sci_new(int party, const OtsSciIo *io, void *ctx) {
	Sci *h = new Sci;
	h->party = party;
	int rc = guard([&] {
		h->iopack = new sci::IOPack(party);
		h->iopack->bind(io, ctx);
		h->otpack = new sci::OTPack(h->iopack, party);
		h->triples = new TripleGenerator(party, h->iopack, h->otpack);
		h->aux = new AuxProtocols(party, h->iopack, h->otpack);
		h->flush();
	});
	if (rc != 0) return nullptr;
	return h;
}

void ots_sci_free(void *hp) {
	Sci *h = (Sci *)hp;
	delete h->aux;
	delete h->triples;
	delete h->otpack;
	delete h->iopack;
	delete h;
}

// n bit triples (n even) with CrypTFlow2's _8KKOT: one 1-out-of-8 KKOT of
// 2-bit messages per pair (2i, 2i+1), which share a. One byte per bit.
int ots_sci_triples(void *hp, const OtsSciIo *io, void *ctx, uint8_t *a, uint8_t *b, uint8_t *c, int32_t n) {
	Sci *h = (Sci *)hp;
	return guard([&] {
		h->iopack->bind(io, ctx);
		h->triples->generate(h->party, a, b, c, n, _8KKOT, false, 1);
		h->flush();
	});
}

// SiRNN's multiplexer: y = sel · x over Z_2^bw, sel XOR-shared, x and y
// additively shared (bw ≤ 64).
int ots_sci_mux(void *hp, const OtsSciIo *io, void *ctx, const uint8_t *sel, const uint64_t *x, uint64_t *y,
		int32_t n, int32_t bw) {
	Sci *h = (Sci *)hp;
	return guard([&] {
		h->iopack->bind(io, ctx);
		std::vector<uint8_t> s(sel, sel + n);
		std::vector<uint64_t> xx(x, x + n);
		h->aux->multiplexer(s.data(), xx.data(), y, n, bw, bw);
		h->flush();
	});
}

} // extern "C"
