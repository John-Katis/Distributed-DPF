// In-memory duplex link between two threads that counts bytes, messages and
// rounds with the rule of dpf_common::net::Channel:
//
//   a message is stamped clock + 1, a party's clock is the largest stamp it
//   has received, and its round count is the largest stamp it has sent or
//   received.
//
// Writes are buffered and leave as one message when the party flushes or
// starts to read, so everything a party sends between two reads counts as one
// message, as one `Channel::send` would.
#pragma once
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace cio {

struct Stats {
	uint64_t bytes_sent = 0, bytes_recv = 0, msgs = 0, rounds = 0;
	Stats operator-(const Stats &o) const {
		return {bytes_sent - o.bytes_sent, bytes_recv - o.bytes_recv, msgs - o.msgs, rounds - o.rounds};
	}
};

struct Queue {
	std::mutex m;
	std::condition_variable cv;
	std::deque<std::pair<uint64_t, std::vector<uint8_t>>> q;
};

// One party's end.
class End {
public:
	End(Queue *out, Queue *in) : out_(out), in_(in) {}

	void write(const void *data, size_t n) {
		const uint8_t *p = (const uint8_t *)data;
		buf_.insert(buf_.end(), p, p + n);
	}

	void flush() {
		if (buf_.empty()) return;
		uint64_t stamp = clock_ + 1;
		st_.rounds = std::max(st_.rounds, stamp);
		st_.bytes_sent += buf_.size();
		st_.msgs += 1;
		{
			std::lock_guard<std::mutex> g(out_->m);
			out_->q.emplace_back(stamp, std::move(buf_));
		}
		out_->cv.notify_one();
		buf_.clear();
	}

	void read(void *data, size_t n) {
		flush();
		uint8_t *p = (uint8_t *)data;
		while (n > 0) {
			if (pos_ == cur_.size()) {
				std::unique_lock<std::mutex> g(in_->m);
				in_->cv.wait(g, [&] { return !in_->q.empty(); });
				auto msg = std::move(in_->q.front());
				in_->q.pop_front();
				g.unlock();
				clock_ = std::max(clock_, msg.first);
				st_.rounds = std::max(st_.rounds, msg.first);
				st_.bytes_recv += msg.second.size();
				cur_ = std::move(msg.second);
				pos_ = 0;
			}
			size_t k = std::min(n, cur_.size() - pos_);
			memcpy(p, cur_.data() + pos_, k);
			pos_ += k;
			p += k;
			n -= k;
		}
	}

	// The next whole message (for message-based transports such as coproto's
	// BufferingSocket). Must not be mixed with a partly consumed read().
	std::vector<uint8_t> read_msg() {
		flush();
		std::unique_lock<std::mutex> g(in_->m);
		in_->cv.wait(g, [&] { return !in_->q.empty(); });
		auto msg = std::move(in_->q.front());
		in_->q.pop_front();
		g.unlock();
		clock_ = std::max(clock_, msg.first);
		st_.rounds = std::max(st_.rounds, msg.first);
		st_.bytes_recv += msg.second.size();
		return std::move(msg.second);
	}

	// Starts a new round: the next message is stamped after everything this
	// party has sent or received, so a phase that begins with this party
	// speaking is not counted inside the previous phase's last round.
	void barrier() { clock_ = st_.rounds; }

	// Snapshot of the counters. Call flush() first if the snapshot should
	// include buffered writes.
	Stats stats() const { return st_; }

private:
	Queue *out_, *in_;
	std::vector<uint8_t> buf_, cur_;
	size_t pos_ = 0;
	uint64_t clock_ = 0;
	Stats st_;
};

struct Link {
	Queue a2b, b2a;
	End a{&a2b, &b2a}, b{&b2a, &a2b};
};

// A round trip, party 1 first, as Channel::sync. Not counted by callers
// that take stats after it.
inline void sync(End &e, int party) {
	uint8_t x = 0;
	if (party == 1) {
		e.write(&x, 1);
		e.read(&x, 1);
	} else {
		e.read(&x, 1);
		e.write(&x, 1);
		e.flush();
	}
	e.barrier();
}

struct Clock {
	std::chrono::steady_clock::time_point t0 = std::chrono::steady_clock::now();
	double secs() const {
		return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
	}
};

// One CSV row: lib,component,security,n,phase,bytes,rounds,msgs,secs,check.
// `bytes` is both directions; rounds is the max over the parties; secs is
// the max over the parties.
inline void row(const std::string &lib, const std::string &comp, const std::string &sec, uint64_t n,
		const std::string &phase, const Stats &s0, const Stats &s1, double t0, double t1, bool ok) {
	printf("%s,%s,%s,%llu,%s,%llu,%llu,%llu,%.6f,%s\n", lib.c_str(), comp.c_str(), sec.c_str(),
			(unsigned long long)n, phase.c_str(), (unsigned long long)(s0.bytes_sent + s1.bytes_sent),
			(unsigned long long)std::max(s0.rounds, s1.rounds), (unsigned long long)(s0.msgs + s1.msgs),
			std::max(t0, t1), ok ? "ok" : "FAIL");
	fflush(stdout);
}

} // namespace cio
