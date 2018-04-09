/*
 *	MPTCP implementation - Concurrent Multipath Transfer / Resource Pooling version 2 (CMT/RPv2)
 *
 *	Current Maintainer & Author:
 *	Denis Lugowski <denis.lugowski@haw-hamburg.de>
 * Thomas Dreibholz <dreibh@simula.no>
 *
 * For the algorithm design, see:
 * Dreibholz, Thomas: "Evaluation and Optimisation of Multi-Path Transport using
 * the Stream Control Transmission Protocol", Habilitation Treatise, University
 * of Duisburg-Essen, Faculty of Economics, Institute for Computer Science and
 * Business Information Systems, URN urn:nbn:de:hbz:464-20120315-103208-1,
 * March 13, 2012
 * URL: https://duepublico.uni-duisburg-essen.de/servlets/DerivateServlet/Derivate-29737/Dre2012_final.pdf
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#include <net/tcp.h>
#include <net/mptcp.h>
#include <linux/module.h>

static int rpv2_scale = 32;
static int dup_acks_rtx = 3;
static int snd_buffer = 0;

struct mptcp_cmtrpv2 {
	u64	increase;
};


static inline int mptcp_cmtrpv2_sk_can_send(const struct sock *sk)
{
	return mptcp_sk_can_send(sk) && tcp_sk(sk)->srtt_us;
}

static inline u64 mptcp_cmtrpv2_scale(u32 val, int scale)
{
	return (u64) val << scale;
}

static inline void mptcp_set_increase_ratio(const struct sock *meta_sk, u64 increase)
{
	((struct mptcp_cmtrpv2 *)inet_csk_ca(meta_sk))->increase = increase;
}

static inline u64 mptcp_get_increase_ratio(const struct sock *meta_sk)
{
	return ((struct mptcp_cmtrpv2 *)inet_csk_ca(meta_sk))->increase;
}

static void mptcp_cmtrpv2_calc_increase_ratio(const struct sock *sk, u32 factor)
{
	const struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;
	const struct sock *sub_sk;
	struct tcp_sock *tp = tcp_sk(sk);
	u64 total_bandwidth = 0, increase = 0, denominator = 0;

	if (!mpcb)
		return;

	if (unlikely(factor)) {
		// Summarize all subflow bandwidths into total_bandwidth.
		mptcp_for_each_sk(mpcb, sub_sk) {
			struct tcp_sock *sub_tp = tcp_sk(sub_sk);

			if (!mptcp_cmtrpv2_sk_can_send(sub_sk))
				continue;

			total_bandwidth += div64_u64(mptcp_cmtrpv2_scale(sub_tp->snd_cwnd, rpv2_scale), sub_tp->srtt_us);
		}

		denominator = (tp->srtt_us * total_bandwidth) >> rpv2_scale;

		if (!unlikely(denominator))
			denominator = 1;

		increase = DIV_ROUND_UP((tp->snd_cwnd * factor), denominator);
		mptcp_set_increase_ratio(mptcp_meta_sk(sk), increase);
	}
}

static u32 mptcp_cmtrpv2_calc_ssthresh(struct sock *sk)
{
	const struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;
	const struct sock *sub_sk;
	struct tcp_sock *tp = tcp_sk(sk);
	u64 total_bandwidth = 0, decrease = 0;
	u32 new_ssthresh = 0;

	// For singlepath, find a convenient value for return!
	if (!mpcb)
		return tcp_reno_ssthresh(sk);

	// Summarize all subflow bandwidths into total_bandwidth.
	mptcp_for_each_sk(mpcb, sub_sk) {
		struct tcp_sock *sub_tp = tcp_sk(sub_sk);

		if (!mptcp_cmtrpv2_sk_can_send(sub_sk))
			continue;

		total_bandwidth += div64_u64(mptcp_cmtrpv2_scale(sub_tp->snd_cwnd, rpv2_scale), sub_tp->srtt_us);
	}

	decrease =  DIV_ROUND_UP(((total_bandwidth * tp->srtt_us) >> rpv2_scale), 2);

	if (DIV_ROUND_UP(tp->snd_cwnd, 2) > decrease)
		decrease = DIV_ROUND_UP(tp->snd_cwnd, 2);

	// If decrease is smaller than cwnd the difference between them will be >=1
	if (decrease < tp->snd_cwnd)
		new_ssthresh = tp->snd_cwnd - decrease;
	else
		new_ssthresh  = 1;


	return new_ssthresh;
}

static void mptcp_cmtrpv2_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	struct tcp_sock *tp = tcp_sk(sk);

	// Retransmission timeout occured
	if (event == CA_EVENT_LOSS)
		tp->snd_cwnd = 1;
}

static void mptcp_cmtrpv2_set_state(struct sock *sk, u8 ca_state)
{
	if (!mptcp(tcp_sk(sk)))
		return;
}

static u32 mptcp_cmtrpv2_slow_start(struct tcp_sock *tp, u32 acked)
{
	u64 increase = 0;
	u32 cwnd = tp->snd_cwnd + acked;

	if (cwnd > tp->snd_ssthresh)
		cwnd = tp->snd_ssthresh + 1;

	mptcp_cmtrpv2_calc_increase_ratio(tp->meta_sk, min((acked * tp->mss_cache), tp->mss_cache));
	increase = mptcp_get_increase_ratio(tp->meta_sk);

	acked -= cwnd - tp->snd_cwnd;

	snd_buffer += increase;

	if (snd_buffer >= tp->mss_cache) {
		tp->snd_cwnd++;
		snd_buffer -= tp->mss_cache;
	}

	return acked;
}

static void mptcp_cmtrpv2_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u64 increase = 0;

	if (!mptcp(tp)) {
		tcp_reno_cong_avoid(sk, ack, acked);
		return;
	}

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tp->snd_cwnd <= tp->snd_ssthresh) {
		/* In "safe" area, increase. */
		mptcp_cmtrpv2_slow_start(tp, acked);
		return;
	}

	mptcp_cmtrpv2_calc_increase_ratio(sk, tp->mss_cache);
	increase = mptcp_get_increase_ratio(mptcp_meta_sk(sk));

	snd_buffer += increase;

	if (tp->snd_cwnd_cnt >= tp->snd_cwnd) {
		if (snd_buffer >= tp->mss_cache) {
			if (tp->snd_cwnd < tp->snd_cwnd_clamp)
				tp->snd_cwnd++;

			snd_buffer -= tp->mss_cache;
			tp->snd_cwnd_cnt = 0;
		}
	} else {
		tp->snd_cwnd_cnt++;
	}
}

static void mptcp_cmtrpv2_fast_rtx(struct sock *sk, u32 ssthresh)
{
	struct tcp_sock *tp = tcp_sk(sk);

	// Check if we are in Fast RTX
	if (tp->sacked_out >= dup_acks_rtx)
		tp->snd_cwnd = ssthresh;
}

u32 mptcp_cmtrpv2_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	u32 ssthresh;

	if (!mptcp(tp)) {
		return tcp_reno_ssthresh(sk);
	}

	ssthresh = mptcp_cmtrpv2_calc_ssthresh(sk);

	mptcp_cmtrpv2_fast_rtx(sk, ssthresh);

	return ssthresh;
}

static struct tcp_congestion_ops mptcp_cmtrpv2 = {
	.ssthresh	  = mptcp_cmtrpv2_ssthresh,
	.cong_avoid	  = mptcp_cmtrpv2_cong_avoid,
	.cwnd_event   = mptcp_cmtrpv2_cwnd_event,
	.set_state	  = mptcp_cmtrpv2_set_state,
	.owner		  = THIS_MODULE,
	.name		  = "cmtrpv2",
};

static int __init mptcp_cmtrpv2_register(void)
{
	BUILD_BUG_ON(sizeof(struct mptcp_cmtrpv2) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&mptcp_cmtrpv2);
}

static void __exit mptcp_cmtrpv2_unregister(void)
{
	tcp_unregister_congestion_control(&mptcp_cmtrpv2);
}

module_init(mptcp_cmtrpv2_register);
module_exit(mptcp_cmtrpv2_unregister);

MODULE_AUTHOR("Denis Lugowski <denis.lugowski@haw-hamburg.de>, Thomas Dreibholz <dreibh@simula.no>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MPTCP CMT/RPv2");
MODULE_VERSION("0.9");
