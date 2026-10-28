// Replaces SCI's socket-based utils/net_io_channel.h (found first on the
// include path): the same class sci::NetIO with the same members, whose bytes
// go to one stream of the caller's transport through OtsSciIo callbacks
// (see ../../sci_shim.cpp). SCI's IOPack has three NetIOs (io, io_rev, io_GC);
// io and io_rev are used concurrently from two OpenMP threads, so the
// callbacks are thread-safe and every message carries its stream index.
#ifndef NETWORK_IO_CHANNEL
#define NETWORK_IO_CHANNEL
#include "utils/io_channel.h"
#include <cstdint>
#include <stdexcept>
#include <string>
using std::string;

enum class LastCall { None, Send, Recv };

extern "C" {
struct OtsSciIo {
	// Buffers n bytes for stream s. 0 on success.
	int (*write)(void *ctx, int s, const uint8_t *p, size_t n);
	// Fills n bytes of stream s, flushing its pending writes first.
	int (*read)(void *ctx, int s, uint8_t *p, size_t n);
	// Sends stream s's buffered bytes as one message.
	int (*flush)(void *ctx, int s);
};
}

namespace sci {
class NetIO : public IOChannel<NetIO> {
public:
	bool is_server = false;
	string addr;
	int port = 0;
	uint64_t counter = 0;
	uint64_t num_rounds = 0;
	bool has_sent = false;
	bool FBF_mode = false;
	LastCall last_call = LastCall::None;

	const OtsSciIo *cb = nullptr;
	void *ctx = nullptr;
	int stream = 0;

	NetIO(int stream, bool is_server) : is_server(is_server), stream(stream) {}

	void send_data(const void *data, int len) {
		if (last_call != LastCall::Send) {
			num_rounds++;
			last_call = LastCall::Send;
		}
		counter += len;
		if (cb->write(ctx, stream, (const uint8_t *)data, len)) throw std::runtime_error("channel closed");
		has_sent = true;
	}

	void recv_data(void *data, int len) {
		if (last_call != LastCall::Recv) {
			num_rounds++;
			last_call = LastCall::Recv;
		}
		has_sent = false;
		if (cb->read(ctx, stream, (uint8_t *)data, len)) throw std::runtime_error("peer closed the channel");
	}

	void flush() {
		if (cb->flush(ctx, stream)) throw std::runtime_error("channel closed");
	}

	void sync() {
		int tmp = 0;
		if (is_server) {
			send_data(&tmp, 1);
			recv_data(&tmp, 1);
		} else {
			recv_data(&tmp, 1);
			send_data(&tmp, 1);
			flush();
		}
	}

	void set_FBF() { flush(); }
	void set_NBF() { flush(); }
	void set_nodelay() {}
	void set_delay() {}
};
} // namespace sci
#endif // NETWORK_IO_CHANNEL
