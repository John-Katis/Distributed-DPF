// Replaces SCI's utils/io_pack.h: the same IOPack, built on the three
// stream-backed NetIOs of net_io_channel.h instead of opening sockets.
#ifndef IO_PACK_H__
#define IO_PACK_H__
#include "utils/net_io_channel.h"

namespace sci {
class IOPack {
public:
	NetIO *io;
	NetIO *io_rev;
	NetIO *io_GC;
	std::string address;
	int party, port = 0;

	explicit IOPack(int party) : party(party) {
		io = new NetIO(0, party == 1);
		io_rev = new NetIO(1, party == 1);
		io_GC = new NetIO(2, party == 1);
	}

	// Points all three streams at the callbacks of the current call.
	void bind(const OtsSciIo *cb, void *ctx) {
		for (NetIO *n : {io, io_rev, io_GC}) {
			n->cb = cb;
			n->ctx = ctx;
		}
	}

	uint64_t get_rounds() { return io->num_rounds + io_GC->num_rounds; }
	uint64_t get_comm() { return io->counter + io_rev->counter + io_GC->counter; }

	~IOPack() {
		delete io;
		delete io_rev;
		delete io_GC;
	}
};
} // namespace sci
#endif // IO_PACK_H__
