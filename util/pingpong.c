/*
 * Copyright (c) 2013-2015 Intel Corporation.  All rights reserved.
 * Copyright (c) 2014-2016, Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2016 Cray Inc.  All rights reserved.
 *
 * This software is available to you under the BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AWV
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <assert.h>
#include <getopt.h>
#include <inttypes.h>
#include <netdb.h>
#include <poll.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_tagged.h>


#ifndef FT_FIVERSION
#define FT_FIVERSION FI_VERSION(1,3)
#endif

#ifdef __APPLE__
#include "osx/osd.h"
#elif defined __FreeBSD__
#include "freebsd/osd.h"
#endif


enum precision {
	NANO = 1,
	MICRO = 1000,
	MILLI = 1000000,
};

enum {
	FT_OPT_ACTIVE		= 1 << 0,
	FT_OPT_ITER		= 1 << 1,
	FT_OPT_SIZE		= 1 << 2,
	FT_OPT_RX_CQ		= 1 << 3,
	FT_OPT_TX_CQ		= 1 << 4,
	FT_OPT_RX_CNTR		= 1 << 5,
	FT_OPT_TX_CNTR		= 1 << 6,
	FT_OPT_VERIFY_DATA	= 1 << 7,
	FT_OPT_ALIGN		= 1 << 8,
	FT_OPT_BW		= 1 << 9,
};


struct ft_opts {
	int iterations;
	int transfer_size;
	int window_size; //SNIP ???
	char *src_port;
	char *dst_port;
	char *src_addr;
	char *dst_addr;
	int sizes_enabled;
	int options;
	int argc;
	char **argv;
};

#define ADDR_OPTS "b:p:s:"
#define INFO_OPTS "n:f:e:"
#define CS_OPTS ADDR_OPTS "I:S:"
#define BENCHMARK_OPTS "v:"

#define INIT_OPTS (struct ft_opts) \
	{	.options = FT_OPT_RX_CQ | FT_OPT_TX_CQ, \
		.iterations = 1000, \
		.transfer_size = 1024, \
		.window_size = 64, \
		.sizes_enabled = FT_DEFAULT_SIZE, \
		.argc = argc, .argv = argv \
	}

#define FT_STR_LEN 32
#define FT_MAX_CTRL_MSG 64
#define FT_MR_KEY 0xC0DE
#define FT_MSG_MR_ACCESS (FI_SEND | FI_RECV)
#define FT_RMA_MR_ACCESS (FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE)

#define FT_PRINTERR(call, retv) \
	do { fprintf(stderr, call "(): %s:%d, ret=%d (%s)\n", __FILE__, __LINE__, \
			(int) retv, fi_strerror((int) -retv)); } while (0)

#define FT_LOG(level, fmt, ...) \
	do { fprintf(stderr, "[%s] fabtests:%s:%d: " fmt "\n", level, __FILE__, \
			__LINE__, ##__VA_ARGS__); } while (0)

#define FT_ERR(fmt, ...) FT_LOG("error", fmt, ##__VA_ARGS__)
#define FT_WARN(fmt, ...) FT_LOG("warn", fmt, ##__VA_ARGS__)

#define FT_EQ_ERR(eq, entry, buf, len) \
	FT_ERR("eq_readerr: %s", fi_eq_strerror(eq, entry.prov_errno, \
				entry.err_data, buf, len))

#define FT_CQ_ERR(cq, entry, buf, len) \
	FT_ERR("cq_readerr: %s", fi_cq_strerror(cq, entry.prov_errno, \
				entry.err_data, buf, len))

#define FT_CLOSE_FID(fd)					\
	do {							\
		int ret;					\
		if ((fd)) {					\
			ret = fi_close(&(fd)->fid);		\
			if (ret)				\
				FT_ERR("fi_close (%d) fid %d",	\
					ret, (int) (fd)->fid.fclass);	\
			fd = NULL;				\
		}						\
	} while (0)

#define FT_CLOSEV_FID(fd, cnt)			\
	do {					\
		int i;				\
		if (!(fd))			\
			break;			\
		for (i = 0; i < (cnt); i++) {	\
			FT_CLOSE_FID((fd)[i]);	\
		}				\
	} while (0)


#define FT_PROCESS_QUEUE_ERR(readerr, rd, queue, fn, str)	\
	do {							\
		if (rd == -FI_EAVAIL) {				\
			readerr(queue, fn " " str);		\
		} else {					\
			FT_PRINTERR(fn, rd);			\
		}						\
	} while (0)

#define FT_PROCESS_EQ_ERR(rd, eq, fn, str) \
	FT_PROCESS_QUEUE_ERR(eq_readerr, rd, eq, fn, str)

#define FT_PRINT_OPTS_USAGE(opt, desc) fprintf(stderr, " %-20s %s\n", opt, desc)

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))
#define ARRAY_SIZE(A) (sizeof(A)/sizeof(*A))

#define TEST_ENUM_SET_N_RETURN(str, enum_val, type, data)	\
	TEST_SET_N_RETURN(str, #enum_val, enum_val, type, data)

#define TEST_SET_N_RETURN(str, val_str, val, type, data)	\
	do {							\
		if (!strncmp(str, val_str, strlen(val_str))) {	\
			*(type *)(data) = val;			\
			return 0;				\
		}						\
	} while (0)


char *ep_name(int ep_type) {
	char *en;
	switch(ep_type) {
		case FI_EP_DGRAM:	en = "UDM"; break;
		case FI_EP_RDM:		en = "RDM"; break;
		case FI_EP_MSG:		en = "MSG"; break;
		default:		en = "NOP"; break;
	}
	return en;
}

struct ct_pingpong {
	struct fi_info *fi_pep, *fi, *hints;
	struct fid_fabric *fabric;
	struct fid_wait *waitset;
	struct fid_domain *domain;
	struct fid_poll *pollset;
	struct fid_pep *pep;
	struct fid_ep *ep, *alias_ep;
	struct fid_cq *txcq, *rxcq;
	struct fid_cntr *txcntr, *rxcntr;
	struct fid_mr *mr;
	struct fid_av *av;
	struct fid_eq *eq;

	struct fid_mr no_mr;
	struct fi_context tx_ctx, rx_ctx;
	struct fi_context *ctx_arr;
	uint64_t remote_cq_data;

	uint64_t tx_seq, rx_seq, tx_cq_cntr, rx_cq_cntr;
	int ft_skip_mr;
	int ft_parent_proc;
	pid_t ft_child_pid;
	int ft_socket_pair[2];

	fi_addr_t remote_fi_addr;
	void *buf, *tx_buf, *rx_buf;
	size_t buf_size, tx_size, rx_size;
	int rx_fd, tx_fd;
	char default_port[8];

	char test_name[50];
	int timeout;
	struct timespec start, end;

	struct fi_av_attr av_attr;
	struct fi_eq_attr eq_attr;
	struct fi_cq_attr cq_attr;
	struct fi_cntr_attr cntr_attr;
	struct ft_opts opts;

	const unsigned int test_cnt;
};

#define FT_ENABLE_ALL		(~0)
#define FT_DEFAULT_SIZE		(1 << 0)

struct test_size_param {
	int size;
	int enable_flags;
};

struct test_size_param test_size[] = {
	{ 1 <<  1, 0 }, { (1 <<  1) + (1 <<  0), 0 },
	{ 1 <<  2, 0 }, { (1 <<  2) + (1 <<  1), 0 },
	{ 1 <<  3, 0 }, { (1 <<  3) + (1 <<  2), 0 },
	{ 1 <<  4, 0 }, { (1 <<  4) + (1 <<  3), 0 },
	{ 1 <<  5, 0 }, { (1 <<  5) + (1 <<  4), 0 },
	{ 1 <<  6, FT_DEFAULT_SIZE }, { (1 <<  6) + (1 <<  5), 0 },
	{ 1 <<  7, 0 }, { (1 <<  7) + (1 <<  6), 0 },
	{ 1 <<  8, FT_DEFAULT_SIZE }, { (1 <<  8) + (1 <<  7), 0 },
	{ 1 <<  9, 0 }, { (1 <<  9) + (1 <<  8), 0 },
	{ 1 << 10, FT_DEFAULT_SIZE }, { (1 << 10) + (1 <<  9), 0 },
	{ 1 << 11, 0 }, { (1 << 11) + (1 << 10), 0 },
	{ 1 << 12, FT_DEFAULT_SIZE }, { (1 << 12) + (1 << 11), 0 },
	{ 1 << 13, FT_DEFAULT_SIZE }, { (1 << 13) + (1 << 12), FT_DEFAULT_SIZE },
	{ 1 << 14, FT_DEFAULT_SIZE }, { (1 << 14) + (1 << 13), 0 },
	{ 1 << 15, 0 }, { (1 << 15) + (1 << 14), 0 },
	{ 1 << 16, 0}, { (1 << 16) + (1 << 15), 0 },
	{ 1 << 17, 0 }, { (1 << 17) + (1 << 16), 0 },
	{ 1 << 18, 0 }, { (1 << 18) + (1 << 17), 0 },
	{ 1 << 19, 0 }, { (1 << 19) + (1 << 18), 0 },
	{ 1 << 20, 0}, { (1 << 20) + (1 << 19), 0 },
	{ 1 << 21, 0}, { (1 << 21) + (1 << 20), 0 },
	{ 1 << 22, 0}, { (1 << 22) + (1 << 21), 0 },
	{ 1 << 23, 0 },
};

const unsigned int test_cnt = (sizeof test_size / sizeof test_size[0]);

static const char integ_alphabet[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const int integ_alphabet_length = (sizeof(integ_alphabet)/sizeof(*integ_alphabet)) - 1;

#define TEST_CNT test_cnt
#define INTEG_SEED 7
#define FT_BENCHMARK_MAX_MSG_SIZE (test_size[TEST_CNT - 1].size)


/*******************************************************************************************/
/*                                       FT proto                                          */
/*******************************************************************************************/

void ft_parseinfo(int op, char *optarg, struct fi_info *hints);
void ft_parse_addr_opts(int op, char *optarg, struct ft_opts *opts);
void ft_parsecsopts(int op, char *optarg, struct ft_opts *opts);
void ft_usage(char *name, char *desc);
void ft_csusage(char *name, char *desc);

void ft_fill_buf(void *buf, int size);
int ft_check_buf(void *buf, int size);

uint64_t ft_init_cq_data(struct fi_info *info);
//int ft_alloc_bufs();
int ft_open_fabric_res(struct ct_pingpong *ct);
int ft_getinfo(struct ct_pingpong *ct, struct fi_info *hints, struct fi_info **info);
int ft_init_fabric();
int ft_start_server(struct ct_pingpong *ct);
int ft_server_connect(struct ct_pingpong *ct);
int ft_client_connect(struct ct_pingpong *ct);
int ft_alloc_active_res(struct ct_pingpong *ct, struct fi_info *fi);
int ft_init_ep(struct ct_pingpong *ct);
int ft_init_alias_ep(struct ct_pingpong *ct, uint64_t flags);
int ft_av_insert(struct fid_av *av, void *addr, size_t count, fi_addr_t *fi_addr,
		uint64_t flags, void *context);
int ft_init_av(struct ct_pingpong *ct);
void ft_free_res(struct ct_pingpong *ct);
void init_test(struct ct_pingpong *ct, struct ft_opts *opts, char *test_name, size_t test_name_len);

int ft_sync(struct ct_pingpong *ct);
int ft_finalize(struct ct_pingpong *ct);

ssize_t ft_post_rx(struct ct_pingpong *ct, struct fid_ep *ep, size_t size, struct fi_context* ctx);
ssize_t ft_post_tx(struct ct_pingpong *ct, struct fid_ep *ep, size_t size, struct fi_context* ctx);
ssize_t ft_rx(struct ct_pingpong *ct, struct fid_ep *ep, size_t size);
ssize_t ft_tx(struct ct_pingpong *ct, struct fid_ep *ep, size_t size);
ssize_t ft_inject(struct ct_pingpong *ct, struct fid_ep *ep, size_t size);

int ft_cq_readerr(struct fid_cq *cq);
int ft_get_rx_comp(struct ct_pingpong *ct, uint64_t total);
int ft_get_tx_comp(struct ct_pingpong *ct, uint64_t total);

void eq_readerr(struct fid_eq *eq, const char *eq_str);

int64_t get_elapsed(const struct timespec *b, const struct timespec *a,
		enum precision p);
void show_perf(char *name, int tsize, int iters, struct timespec *start,
		struct timespec *end, int xfers_per_iter);

int ft_getsrcaddr(char *node, char *service, struct fi_info *hints);
int ft_read_addr_opts(struct ct_pingpong *ct, char **node, char **service, struct fi_info *hints,
		uint64_t *flags, struct ft_opts *opts);
char *size_str(char str[FT_STR_LEN], long long size);
char *cnt_str(char str[FT_STR_LEN], long long cnt);
int size_to_count(struct ct_pingpong *ct, int size);

void ft_parse_benchmark_opts(struct ct_pingpong *ct, int op, char *optarg);
void ft_benchmark_usage(void);
int pingpong(struct ct_pingpong *ct);

void ft_init_ct_pingpong(struct ct_pingpong *ct);

/*******************************************************************************************/
/*                                       FT func                                           */
/*******************************************************************************************/

static inline int ft_use_size(int index, int enable_flags)
{
	return (enable_flags == FT_ENABLE_ALL) ||
		(enable_flags & test_size[index].enable_flags);
}

static inline void ft_start(struct ct_pingpong *ct)
{
	ct->opts.options |= FT_OPT_ACTIVE;
	clock_gettime(CLOCK_MONOTONIC, &(ct->start));
}

static inline void ft_stop(struct ct_pingpong *ct)
{
	clock_gettime(CLOCK_MONOTONIC, &(ct->end));
	ct->opts.options &= ~FT_OPT_ACTIVE;
}

static int ft_check_opts(struct ct_pingpong *ct, uint64_t flags)
{
	return (ct->opts.options & flags) == flags;
}

void ft_fill_buf(void *buf, int size)
{
	char *msg_buf;
	int msg_index;
	static unsigned int iter = 0;
	int i;

	msg_index = ((iter++)*INTEG_SEED) % integ_alphabet_length;
	msg_buf = (char *)buf;
	for (i = 0; i < size; i++) {
		msg_buf[i] = integ_alphabet[msg_index++];
		if (msg_index >= integ_alphabet_length)
			msg_index = 0;
	}
}

int ft_check_buf(void *buf, int size)
{
	char *recv_data;
	char c;
	static unsigned int iter = 0;
	int msg_index;
	int i;

	msg_index = ((iter++)*INTEG_SEED) % integ_alphabet_length;
	recv_data = (char *)buf;

	for (i = 0; i < size; i++) {
		c = integ_alphabet[msg_index++];
		if (msg_index >= integ_alphabet_length)
			msg_index = 0;
		if (c != recv_data[i])
			break;
	}
	if (i != size) {
		printf("Error at iteration=%d size=%d byte=%d\n",
			iter, size, i);
		return 1;
	}

	return 0;
}

uint64_t ft_init_cq_data(struct fi_info *info)
{
	if (info->domain_attr->cq_data_size >= sizeof(uint64_t)) {
		return 0x0123456789abcdefULL;
	} else {
		return 0x0123456789abcdef &
			((0x1ULL << (info->domain_attr->cq_data_size * 8)) - 1);
	}
}

static void ft_cq_set_wait_attr(struct ct_pingpong *ct)
{
	ct->cq_attr.wait_obj = FI_WAIT_NONE; // NEEDED ? SNIP ??
}

static void ft_cntr_set_wait_attr(struct ct_pingpong *ct)
{
	ct->cntr_attr.wait_obj = FI_WAIT_NONE; // NEEDED ? SNIPP ??
}

static uint64_t ft_caps_to_mr_access(uint64_t caps)
{
	uint64_t mr_access = 0;

	if (caps & (FI_MSG | FI_TAGGED)) {
		if (caps & FT_MSG_MR_ACCESS)
			mr_access |= caps & FT_MSG_MR_ACCESS;
		else
			mr_access |= FT_MSG_MR_ACCESS;
	}

	if (caps & (FI_RMA | FI_ATOMIC)) {
		if (caps & FT_RMA_MR_ACCESS)
			mr_access |= caps & FT_RMA_MR_ACCESS;
		else
			mr_access |= FT_RMA_MR_ACCESS;
	}

	return mr_access;
}

/*
 * Include FI_MSG_PREFIX space in the allocated buffer, and ensure that the
 * buffer is large enough for a control message used to exchange addressing
 * data.
 */
int ft_alloc_msgs(struct ct_pingpong *ct)
{
	int ret;
	long alignment = 1;

	/* TODO: support multi-recv tests */
	if (ct->fi->rx_attr->op_flags == FI_MULTI_RECV)
		return 0;

	ct->tx_size = ct->opts.options & FT_OPT_SIZE ?
		  ct->opts.transfer_size : test_size[TEST_CNT - 1].size;
	if (ct->tx_size > ct->fi->ep_attr->max_msg_size)
		ct->tx_size = ct->fi->ep_attr->max_msg_size;
	ct->rx_size = ct->tx_size;
	ct->buf_size = MAX(ct->tx_size, FT_MAX_CTRL_MSG) + MAX(ct->rx_size, FT_MAX_CTRL_MSG);

	if (ct->opts.options & FT_OPT_ALIGN) {
		alignment = sysconf(_SC_PAGESIZE);
		if (alignment < 0)
			return -errno;
		ct->buf_size += alignment;

		ret = posix_memalign(&(ct->buf), (size_t) alignment, ct->buf_size);
		if (ret) {
			FT_PRINTERR("posix_memalign", ret);
			return ret;
		}
	} else {
		ct->buf = malloc(ct->buf_size);
		if (!ct->buf) {
			perror("malloc");
			return -FI_ENOMEM;
		}
	}
	memset(ct->buf, 0, ct->buf_size);
	ct->rx_buf = ct->buf;
	ct->tx_buf = (char *) ct->buf + MAX(ct->rx_size, FT_MAX_CTRL_MSG);
	ct->tx_buf = (void *) (((uintptr_t) ct->tx_buf + alignment - 1) &
			   ~(alignment - 1));

	ct->remote_cq_data = ft_init_cq_data(ct->fi);

	if (ct->opts.window_size > 0) {
		ct->ctx_arr = calloc(ct->opts.window_size, sizeof(struct fi_context));
		if (!ct->ctx_arr)
			return -FI_ENOMEM;
	}

	if (!ct->ft_skip_mr && ((ct->fi->mode & FI_LOCAL_MR) ||
				(ct->fi->caps & (FI_RMA | FI_ATOMIC)))) {
		ret = fi_mr_reg(ct->domain, ct->buf, ct->buf_size, ft_caps_to_mr_access(ct->fi->caps),
				0, FT_MR_KEY, 0, &(ct->mr), NULL);
		if (ret) {
			FT_PRINTERR("fi_mr_reg", ret);
			return ret;
		}
	} else {
		ct->mr = &(ct->no_mr);
	}

	return 0;
}

int ft_open_fabric_res(struct ct_pingpong *ct)
{
	int ret;

	ret = fi_fabric(ct->fi->fabric_attr, &(ct->fabric), NULL);
	if (ret) {
		FT_PRINTERR("fi_fabric", ret);
		return ret;
	}

	ret = fi_eq_open(ct->fabric, &(ct->eq_attr), &(ct->eq), NULL);
	if (ret) {
		FT_PRINTERR("fi_eq_open", ret);
		return ret;
	}

	ret = fi_domain(ct->fabric, ct->fi, &(ct->domain), NULL);
	if (ret) {
		FT_PRINTERR("fi_domain", ret);
		return ret;
	}

	return 0;
}

int ft_alloc_active_res(struct ct_pingpong *ct, struct fi_info *fi) // ... SNIP ??
{
	int ret;

	ret = ft_alloc_msgs(ct);
	if (ret)
		return ret;

	if (ct->cq_attr.format == FI_CQ_FORMAT_UNSPEC) { // ...
		if (fi->caps & FI_TAGGED)
			ct->cq_attr.format = FI_CQ_FORMAT_TAGGED;
		else
			ct->cq_attr.format = FI_CQ_FORMAT_CONTEXT;
	}

	if (ct->opts.options & FT_OPT_TX_CQ) {
		ft_cq_set_wait_attr(ct); // ??
		ct->cq_attr.size = fi->tx_attr->size;
		ret = fi_cq_open(ct->domain, &(ct->cq_attr), &(ct->txcq), &(ct->txcq));
		if (ret) {
			FT_PRINTERR("fi_cq_open", ret);
			return ret;
		}
	}

	if (ct->opts.options & FT_OPT_TX_CNTR) {
		ft_cntr_set_wait_attr(ct); // ??
		ret = fi_cntr_open(ct->domain, &(ct->cntr_attr), &(ct->txcntr), &(ct->txcntr));
		if (ret) {
			FT_PRINTERR("fi_cntr_open", ret);
			return ret;
		}
	}

	if (ct->opts.options & FT_OPT_RX_CQ) {
		ft_cq_set_wait_attr(ct); // ??
		ct->cq_attr.size = fi->rx_attr->size;
		ret = fi_cq_open(ct->domain, &(ct->cq_attr), &(ct->rxcq), &(ct->rxcq));
		if (ret) {
			FT_PRINTERR("fi_cq_open", ret);
			return ret;
		}
	}

	if (ct->opts.options & FT_OPT_RX_CNTR) {
		ft_cntr_set_wait_attr(ct); // ??
		ret = fi_cntr_open(ct->domain, &(ct->cntr_attr), &(ct->rxcntr), &(ct->rxcntr));
		if (ret) {
			FT_PRINTERR("fi_cntr_open", ret);
			return ret;
		}
	}

	if (fi->ep_attr->type == FI_EP_RDM || fi->ep_attr->type == FI_EP_DGRAM) {
		if (fi->domain_attr->av_type != FI_AV_UNSPEC)
			ct->av_attr.type = fi->domain_attr->av_type;

		ret = fi_av_open(ct->domain, &(ct->av_attr), &(ct->av), NULL);
		if (ret) {
			FT_PRINTERR("fi_av_open", ret);
			return ret;
		}
	}

	ret = fi_endpoint(ct->domain, fi, &(ct->ep), NULL);
	if (ret) {
		FT_PRINTERR("fi_endpoint", ret);
		return ret;
	}

	return 0;
}

static int dupaddr(void **dst_addr, size_t *dst_addrlen,
		void *src_addr, size_t src_addrlen)
{
	*dst_addr = malloc(src_addrlen);
	if (!*dst_addr) {
		FT_ERR("address allocation failed");
		return EAI_MEMORY;
	}
	*dst_addrlen = src_addrlen;
	memcpy(*dst_addr, src_addr, src_addrlen);
	return 0;
}

static int getaddr(char *node, char *service,
			struct fi_info *hints, uint64_t flags)
{
	int ret;
	struct fi_info *fi;

	if (!node && !service) {
		if (flags & FI_SOURCE) {
			hints->src_addr = NULL;
			hints->src_addrlen = 0;
		} else {
			hints->dest_addr = NULL;
			hints->dest_addrlen = 0;
		}
		return 0;
	}

	ret = fi_getinfo(FT_FIVERSION, node, service, flags, hints, &fi);
	if (ret) {
		FT_PRINTERR("fi_getinfo", ret);
		return ret;
	}
	hints->addr_format = fi->addr_format;

	if (flags & FI_SOURCE) {
		ret = dupaddr(&hints->src_addr, &hints->src_addrlen,
				fi->src_addr, fi->src_addrlen);
	} else {
		ret = dupaddr(&hints->dest_addr, &hints->dest_addrlen,
				fi->dest_addr, fi->dest_addrlen);
	}

	fi_freeinfo(fi);
	return ret;
}

void eq_readerr(struct fid_eq *eq, const char *eq_str)
{
	struct fi_eq_err_entry eq_err;
	int rd;

	rd = fi_eq_readerr(eq, &eq_err, 0);
	if (rd != sizeof(eq_err)) {
		FT_PRINTERR("fi_eq_readerr", rd);
	} else {
		FT_EQ_ERR(eq, eq_err, NULL, 0);
	}
}


int ft_getsrcaddr(char *node, char *service, struct fi_info *hints)
{
	return getaddr(node, service, hints, FI_SOURCE);
}

int ft_read_addr_opts(struct ct_pingpong *ct, char **node, char **service, struct fi_info *hints,
		uint64_t *flags, struct ft_opts *opts)
{
	int ret;

	if (opts->dst_addr) {
		if (!opts->dst_port)
			opts->dst_port = ct->default_port;

		ret = ft_getsrcaddr(opts->src_addr, opts->src_port, hints);
		if (ret)
			return ret;
		*node = opts->dst_addr;
		*service = opts->dst_port;
	} else {
		if (!opts->src_port)
			opts->src_port = ct->default_port;

		*node = opts->src_addr;
		*service = opts->src_port;
		*flags = FI_SOURCE;
	}

	return 0;
}

int ft_getinfo(struct ct_pingpong *ct, struct fi_info *hints, struct fi_info **info)
{
	char *node, *service;
	uint64_t flags = 0;
	int ret;

	ret = ft_read_addr_opts(ct, &node, &service, hints, &flags, &(ct->opts));
	if (ret)
		return ret;

	if (!hints->ep_attr->type)
		hints->ep_attr->type = FI_EP_RDM;

	ret = fi_getinfo(FT_FIVERSION, node, service, flags, hints, info);
	if (ret) {
		FT_PRINTERR("fi_getinfo", ret);
		return ret;
	}
	return 0;
}

static void ft_close_fids(struct ct_pingpong *ct)
{
	if (ct->mr != &(ct->no_mr))
		FT_CLOSE_FID(ct->mr);
	FT_CLOSE_FID(ct->alias_ep);
	FT_CLOSE_FID(ct->ep);
	FT_CLOSE_FID(ct->pep);
	FT_CLOSE_FID(ct->pollset);
	FT_CLOSE_FID(ct->rxcq);
	FT_CLOSE_FID(ct->txcq);
	FT_CLOSE_FID(ct->rxcntr);
	FT_CLOSE_FID(ct->txcntr);
	FT_CLOSE_FID(ct->av);
	FT_CLOSE_FID(ct->eq);
	FT_CLOSE_FID(ct->domain);
	FT_CLOSE_FID(ct->waitset);
	FT_CLOSE_FID(ct->fabric);
}

void ft_free_res(struct ct_pingpong *ct)
{
	ft_close_fids(ct);
	if (ct->ctx_arr) {
		free(ct->ctx_arr);
		ct->ctx_arr = NULL;
	}

	if (ct->buf) {
		free(ct->buf);
		ct->buf = ct->rx_buf = ct->tx_buf = NULL;
		ct->buf_size = ct->rx_size = ct->tx_size = 0;
	}
	if (ct->fi_pep) {
		fi_freeinfo(ct->fi_pep);
		ct->fi_pep = NULL;
	}
	if (ct->fi) {
		fi_freeinfo(ct->fi);
		ct->fi = NULL;
	}
	if (ct->hints) {
		fi_freeinfo(ct->hints);
		ct->hints = NULL;
	}
}


char *size_str(char str[FT_STR_LEN], long long size)
{
	long long base, fraction = 0;
	char mag;

	memset(str, '\0', FT_STR_LEN);

	if (size >= (1 << 30)) {
		base = 1 << 30;
		mag = 'g';
	} else if (size >= (1 << 20)) {
		base = 1 << 20;
		mag = 'm';
	} else if (size >= (1 << 10)) {
		base = 1 << 10;
		mag = 'k';
	} else {
		base = 1;
		mag = '\0';
	}

	if (size / base < 10)
		fraction = (size % base) * 10 / base;

	if (fraction)
		snprintf(str, FT_STR_LEN, "%lld.%lld%c", size / base, fraction, mag);
	else
		snprintf(str, FT_STR_LEN, "%lld%c", size / base, mag);

	return str;
}

char *cnt_str(char str[FT_STR_LEN], long long cnt)
{
	if (cnt >= 1000000000)
		snprintf(str, FT_STR_LEN, "%lldb", cnt / 1000000000);
	else if (cnt >= 1000000)
		snprintf(str, FT_STR_LEN, "%lldm", cnt / 1000000);
	else if (cnt >= 1000)
		snprintf(str, FT_STR_LEN, "%lldk", cnt / 1000);
	else
		snprintf(str, FT_STR_LEN, "%lld", cnt);

	return str;
}

int size_to_count(struct ct_pingpong *ct, int size)
{
	if (size >= (1 << 20))
		return (ct->opts.options & FT_OPT_BW) ? 200 : 100;
	else if (size >= (1 << 16))
		return (ct->opts.options & FT_OPT_BW) ? 2000 : 1000;
	else
		return (ct->opts.options & FT_OPT_BW) ? 20000: 10000;
}

void init_test(struct ct_pingpong *ct, struct ft_opts *opts, char *test_name, size_t test_name_len)
{
	char sstr[FT_STR_LEN];

	size_str(sstr, opts->transfer_size);
	if (!strcmp(test_name, "custom"))
		snprintf(test_name, test_name_len, "%s_lat", sstr);
	if (!(opts->options & FT_OPT_ITER))
		opts->iterations = size_to_count(ct, opts->transfer_size);
}

#define FT_POST(post_fn, comp_fn, seq, op_str, ...)				\
	do {									\
		int timeout_save;						\
		int ret, rc;							\
										\
		while (1) {							\
			ret = post_fn(__VA_ARGS__);				\
			if (!ret)						\
				break;						\
										\
			if (ret != -FI_EAGAIN) {				\
				FT_PRINTERR(op_str, ret);			\
				return ret;					\
			}							\
										\
			timeout_save = ct->timeout;					\
			ct->timeout = 0;						\
			rc = comp_fn(ct, seq);					\
			if (rc && rc != -FI_EAGAIN) {				\
				FT_ERR("Failed to get " op_str " completion");	\
				return rc;					\
			}							\
			ct->timeout = timeout_save;					\
		}								\
		seq++;								\
	} while (0)

ssize_t ft_post_tx(struct ct_pingpong *ct, struct fid_ep *ep, size_t size, struct fi_context* ctx)
{
	FT_POST(fi_send, ft_get_tx_comp, ct->tx_seq, "transmit", ep,
			ct->tx_buf,	size, fi_mr_desc(ct->mr),
			ct->remote_fi_addr, ctx);
	return 0;
}

ssize_t ft_tx(struct ct_pingpong *ct, struct fid_ep *ep, size_t size)
{
	ssize_t ret;

	if (ft_check_opts(ct, FT_OPT_VERIFY_DATA | FT_OPT_ACTIVE))
		ft_fill_buf((char *) ct->tx_buf, size);

	ret = ft_post_tx(ct, ep, size, &(ct->tx_ctx));
	if (ret)
		return ret;

	ret = ft_get_tx_comp(ct, ct->tx_seq);
	return ret;
}

ssize_t ft_post_inject(struct ct_pingpong *ct, struct fid_ep *ep, size_t size)
{
	FT_POST(fi_inject, ft_get_tx_comp, ct->tx_seq, "inject",
			ep, ct->tx_buf, size,
			ct->remote_fi_addr);
	ct->tx_cq_cntr++;
	return 0;
}

ssize_t ft_inject(struct ct_pingpong *ct, struct fid_ep *ep, size_t size)
{
	ssize_t ret;

	if (ft_check_opts(ct, FT_OPT_VERIFY_DATA | FT_OPT_ACTIVE))
		ft_fill_buf((char *) ct->tx_buf, size);

	ret = ft_post_inject(ct, ep, size);
	if (ret)
		return ret;

	return ret;
}


ssize_t ft_post_rx(struct ct_pingpong *ct, struct fid_ep *ep, size_t size, struct fi_context* ctx)
{
	FT_POST(fi_recv, ft_get_rx_comp, ct->rx_seq, "receive", ep, ct->rx_buf,
			MAX(size, FT_MAX_CTRL_MSG),
			fi_mr_desc(ct->mr),	0, ctx);
	return 0;
}

ssize_t ft_rx(struct ct_pingpong *ct, struct fid_ep *ep, size_t size)
{
	ssize_t ret;

	ret = ft_get_rx_comp(ct, ct->rx_seq);
	if (ret)
		return ret;

	if (ft_check_opts(ct, FT_OPT_VERIFY_DATA | FT_OPT_ACTIVE)) {
		ret = ft_check_buf((char *) ct->rx_buf, size);
		if (ret)
			return ret;
	}
	/* TODO: verify CQ data, if available */

	/* Ignore the size arg. Post a buffer large enough to handle all message
	 * sizes. ft_sync() makes use of ft_rx() and gets called in tests just before
	 * message size is updated. The recvs posted are always for the next incoming
	 * message */
	ret = ft_post_rx(ct, ct->ep, ct->rx_size, &(ct->rx_ctx));
	return ret;
}

/*
 * fi_cq_err_entry can be cast to any CQ entry format.
 */
static int ft_spin_for_comp(struct fid_cq *cq, uint64_t *cur,
			    uint64_t total, int timeout)
{
	struct fi_cq_err_entry comp;
	struct timespec a, b;
	int ret;

	if (timeout >= 0)
		clock_gettime(CLOCK_MONOTONIC, &a);

	while (total - *cur > 0) {
		ret = fi_cq_read(cq, &comp, 1);
		if (ret > 0) {
			if (timeout >= 0)
				clock_gettime(CLOCK_MONOTONIC, &a);

			(*cur)++;
		} else if (ret < 0 && ret != -FI_EAGAIN) {
			return ret;
		} else if (timeout >= 0) {
			clock_gettime(CLOCK_MONOTONIC, &b);
			if ((b.tv_sec - a.tv_sec) > timeout) {
				fprintf(stderr, "%ds timeout expired\n", timeout);
				return -FI_ENODATA;
			}
		}
	}

	return 0;
}

static int ft_get_cq_comp(struct fid_cq *cq, uint64_t *cur,
			  uint64_t total, int timeout)
{
	int ret = ft_spin_for_comp(cq, cur, total, timeout);

	if (ret) {
		if (ret == -FI_EAVAIL) {
			ret = ft_cq_readerr(cq);
			(*cur)++;
		} else {
			FT_PRINTERR("ft_get_cq_comp", ret);
		}
	}
	return ret;
}

int ft_get_rx_comp(struct ct_pingpong *ct, uint64_t total)
{
	int ret = FI_SUCCESS;

	if (ct->rxcq) {
		ret = ft_get_cq_comp(ct->rxcq, &(ct->rx_cq_cntr), total, ct->timeout);
	} else if (ct->rxcntr) {
		while (fi_cntr_read(ct->rxcntr) < total) {
			ret = fi_cntr_wait(ct->rxcntr, total, ct->timeout);
			if (ret)
				FT_PRINTERR("fi_cntr_wait", ret);
			else
				break;
		}
	} else {
		FT_ERR("Trying to get a RX completion when no RX CQ or counter were opened");
		ret = -FI_EOTHER;
	}
	return ret;
}

int ft_get_tx_comp(struct ct_pingpong *ct, uint64_t total)
{
	int ret;

	if (ct->txcq) {
		ret = ft_get_cq_comp(ct->txcq, &(ct->tx_cq_cntr), total, -1);
	} else if (ct->txcntr) {
		ret = fi_cntr_wait(ct->txcntr, total, -1);
		if (ret)
			FT_PRINTERR("fi_cntr_wait", ret);
	} else {
		FT_ERR("Trying to get a TX completion when no TX CQ or counter were opened");
		ret = -FI_EOTHER;
	}
	return ret;
}

int ft_cq_readerr(struct fid_cq *cq)
{
	struct fi_cq_err_entry cq_err;
	int ret;

	ret = fi_cq_readerr(cq, &cq_err, 0);
	if (ret < 0) {
		FT_PRINTERR("fi_cq_readerr", ret);
	} else {
		FT_CQ_ERR(cq, cq_err, NULL, 0);
		ret = -cq_err.err;
	}
	return ret;
}


int ft_sync(struct ct_pingpong *ct)
{
	int ret;

	if (ct->opts.dst_addr) {
		ret = ft_tx(ct, ct->ep, 1);
		if (ret)
			return ret;

		ret = ft_rx(ct, ct->ep, 1);
	} else {
		ret = ft_rx(ct, ct->ep, 1);
		if (ret)
			return ret;

		ret = ft_tx(ct, ct->ep, 1);
	}

	return ret;
}

#define FT_EP_BIND(ep, fd, flags)					\
	do {								\
		int ret;						\
		if ((fd)) {						\
			ret = fi_ep_bind((ep), &(fd)->fid, (flags));	\
			if (ret) {					\
				FT_PRINTERR("fi_ep_bind", ret);		\
				return ret;				\
			}						\
		}							\
	} while (0)

int ft_init_alias_ep(struct ct_pingpong *ct, uint64_t flags)
{
	int ret;
	ret = fi_ep_alias(ct->ep, &(ct->alias_ep), flags);
	if (ret) {
		FT_PRINTERR("fi_ep_alias", ret);
		return ret;
	}
	return 0;
}

int ft_init_ep(struct ct_pingpong *ct)
{
	int flags, ret;

	if (ct->fi->ep_attr->type == FI_EP_MSG)
		FT_EP_BIND(ct->ep, ct->eq, 0);
	FT_EP_BIND(ct->ep, ct->av, 0);
	FT_EP_BIND(ct->ep, ct->txcq, FI_TRANSMIT);
	FT_EP_BIND(ct->ep, ct->rxcq, FI_RECV);

	/* TODO: use control structure to select counter bindings explicitly */
	flags = !ct->txcq ? FI_SEND : 0;
	if (ct->hints->caps & (FI_WRITE | FI_READ))
		flags |= ct->hints->caps & (FI_WRITE | FI_READ);
	else if (ct->hints->caps & FI_RMA)
		flags |= FI_WRITE | FI_READ;
	FT_EP_BIND(ct->ep, ct->txcntr, flags);
	flags = !ct->rxcq ? FI_RECV : 0;
	if (ct->hints->caps & (FI_REMOTE_WRITE | FI_REMOTE_READ))
		flags |= ct->hints->caps & (FI_REMOTE_WRITE | FI_REMOTE_READ);
	else if (ct->hints->caps & FI_RMA)
		flags |= FI_REMOTE_WRITE | FI_REMOTE_READ;
	FT_EP_BIND(ct->ep, ct->rxcntr, flags);

	ret = fi_enable(ct->ep);
	if (ret) {
		FT_PRINTERR("fi_enable", ret);
		return ret;
	}

	if (ct->fi->rx_attr->op_flags != FI_MULTI_RECV) {
		/* Initial receive will get remote address for unconnected EPs */
		ret = ft_post_rx(ct, ct->ep, MAX(ct->rx_size, FT_MAX_CTRL_MSG), &(ct->rx_ctx));
		if (ret)
			return ret;
	}

	return 0;
}


int ft_av_insert(struct fid_av *av, void *addr, size_t count, fi_addr_t *fi_addr,
		uint64_t flags, void *context)
{
	int ret;

	ret = fi_av_insert(av, addr, count, fi_addr, flags, context);
	if (ret < 0) {
		FT_PRINTERR("fi_av_insert", ret);
		return ret;
	} else if (ret != count) {
		FT_ERR("fi_av_insert: number of addresses inserted = %d;"
			       " number of addresses given = %zd\n", ret, count);
		return -EXIT_FAILURE;
	}

	return 0;
}

/* TODO: retry send for unreliable endpoints */
int ft_init_av(struct ct_pingpong *ct)
{
	size_t addrlen;
	int ret;

	if (ct->opts.dst_addr) {
		ret = ft_av_insert(ct->av, ct->fi->dest_addr, 1, &(ct->remote_fi_addr), 0, NULL);
		if (ret)
			return ret;

		addrlen = FT_MAX_CTRL_MSG;
		ret = fi_getname(&(ct->ep->fid), (char *) ct->tx_buf,
				 &addrlen);
		if (ret) {
			FT_PRINTERR("fi_getname", ret);
			return ret;
		}

		ret = (int) ft_tx(ct, ct->ep, addrlen);
		if (ret)
			return ret;

		ret = ft_rx(ct, ct->ep, 1);
	} else {
		ret = (int) ft_rx(ct, ct->ep, FT_MAX_CTRL_MSG);
		if (ret)
			return ret;

		ret = ft_av_insert(ct->av, (char *) ct->rx_buf,
				   1, &(ct->remote_fi_addr), 0, NULL);
		if (ret)
			return ret;

		ret = (int) ft_tx(ct, ct->ep, 1);
	}

	return ret;
}

int ft_start_server(struct ct_pingpong *ct)
{
	int ret;

	ret = ft_getinfo(ct, ct->hints, &(ct->fi_pep));
	if (ret)
		return ret;

	ret = fi_fabric(ct->fi_pep->fabric_attr, &(ct->fabric), NULL);
	if (ret) {
		FT_PRINTERR("fi_fabric", ret);
		return ret;
	}

	ret = fi_eq_open(ct->fabric, &(ct->eq_attr), &(ct->eq), NULL);
	if (ret) {
		FT_PRINTERR("fi_eq_open", ret);
		return ret;
	}

	ret = fi_passive_ep(ct->fabric, ct->fi_pep, &(ct->pep), NULL);
	if (ret) {
		FT_PRINTERR("fi_passive_ep", ret);
		return ret;
	}

	ret = fi_pep_bind(ct->pep, &(ct->eq->fid), 0);
	if (ret) {
		FT_PRINTERR("fi_pep_bind", ret);
		return ret;
	}

	ret = fi_listen(ct->pep);
	if (ret) {
		FT_PRINTERR("fi_listen", ret);
		return ret;
	}

	return 0;
}

int ft_server_connect(struct ct_pingpong *ct)
{
	struct fi_eq_cm_entry entry;
	uint32_t event;
	ssize_t rd;
	int ret;

	rd = fi_eq_sread(ct->eq, &event, &entry, sizeof entry, -1, 0);
	if (rd != sizeof entry) {
		FT_PROCESS_EQ_ERR(rd, ct->eq, "fi_eq_sread", "listen");
		return (int) rd;
	}

	ct->fi = entry.info;
	if (event != FI_CONNREQ) {
		fprintf(stderr, "Unexpected CM event %d\n", event);
		ret = -FI_EOTHER;
		goto err;
	}

	ret = fi_domain(ct->fabric, ct->fi, &(ct->domain), NULL);
	if (ret) {
		FT_PRINTERR("fi_domain", ret);
		goto err;
	}

	ret = ft_alloc_active_res(ct, ct->fi);
	if (ret)
		goto err;

	ret = ft_init_ep(ct);
	if (ret)
		goto err;

	ret = fi_accept(ct->ep, NULL, 0);
	if (ret) {
		FT_PRINTERR("fi_accept", ret);
		goto err;
	}

	rd = fi_eq_sread(ct->eq, &event, &entry, sizeof entry, -1, 0);
	if (rd != sizeof entry) {
		FT_PROCESS_EQ_ERR(rd, ct->eq, "fi_eq_sread", "accept");
		ret = (int) rd;
		goto err;
	}

	if (event != FI_CONNECTED || entry.fid != &(ct->ep->fid)) {
		fprintf(stderr, "Unexpected CM event %d fid %p (ep %p)\n",
			event, entry.fid, ct->ep);
		ret = -FI_EOTHER;
		goto err;
	}

	return 0;

err:
	fi_reject(ct->pep, ct->fi->handle, NULL, 0);
	return ret;
}

int ft_client_connect(struct ct_pingpong *ct)
{
	struct fi_eq_cm_entry entry;
	uint32_t event;
	ssize_t rd;
	int ret;

	ret = ft_getinfo(ct, ct->hints, &(ct->fi));
	if (ret)
		return ret;

	ret = ft_open_fabric_res(ct);
	if (ret)
		return ret;

	ret = ft_alloc_active_res(ct, ct->fi);
	if (ret)
		return ret;

	ret = ft_init_ep(ct);
	if (ret)
		return ret;

	ret = fi_connect(ct->ep, ct->fi->dest_addr, NULL, 0);
	if (ret) {
		FT_PRINTERR("fi_connect", ret);
		return ret;
	}

	rd = fi_eq_sread(ct->eq, &event, &entry, sizeof entry, -1, 0);
	if (rd != sizeof entry) {
		FT_PROCESS_EQ_ERR(rd, ct->eq, "fi_eq_sread", "connect");
		ret = (int) rd;
		return ret;
	}

	if (event != FI_CONNECTED || entry.fid != &(ct->ep->fid)) {
		fprintf(stderr, "Unexpected CM event %d fid %p (ep %p)\n",
			event, entry.fid, ct->ep);
		ret = -FI_EOTHER;
		return ret;
	}

	return 0;
}

int ft_init_fabric(struct ct_pingpong *ct)
{
	int ret;

	ret = ft_getinfo(ct, ct->hints, &(ct->fi));
	if (ret)
		return ret;

	ret = ft_open_fabric_res(ct);
	if (ret)
		return ret;

	ret = ft_alloc_active_res(ct, ct->fi);
	if (ret)
		return ret;

	ret = ft_init_ep(ct);
	if (ret)
		return ret;

	ret = ft_init_av(ct);
	if (ret)
		return ret;

	return 0;
}

int ft_finalize(struct ct_pingpong *ct)
{
	struct iovec iov;
	int ret;
	struct fi_context ctx;

	strcpy(ct->tx_buf, "fin");
	iov.iov_base = ct->tx_buf;
	iov.iov_len = 4;

	if (ct->hints->caps & FI_TAGGED) {
		struct fi_msg_tagged tmsg;

		memset(&tmsg, 0, sizeof tmsg);
		tmsg.msg_iov = &iov;
		tmsg.iov_count = 1;
		tmsg.addr = ct->remote_fi_addr;
		tmsg.tag = ct->tx_seq;
		tmsg.ignore = 0;
		tmsg.context = &ctx;

		ret = fi_tsendmsg(ct->ep, &tmsg, FI_INJECT | FI_TRANSMIT_COMPLETE);
	} else {
		struct fi_msg msg;

		memset(&msg, 0, sizeof msg);
		msg.msg_iov = &iov;
		msg.iov_count = 1;
		msg.addr = ct->remote_fi_addr;
		msg.context = &ctx;

		ret = fi_sendmsg(ct->ep, &msg, FI_INJECT | FI_TRANSMIT_COMPLETE);
	}
	if (ret) {
		FT_PRINTERR("transmit", ret);
		return ret;
	}


	ret = ft_get_tx_comp(ct, ++ct->tx_seq);
	if (ret)
		return ret;

	ret = ft_get_rx_comp(ct, ct->rx_seq);
	if (ret)
		return ret;

	return 0;
}

int64_t get_elapsed(const struct timespec *b, const struct timespec *a,
		    enum precision p)
{
	int64_t elapsed;

	elapsed = difftime(a->tv_sec, b->tv_sec) * 1000 * 1000 * 1000;
	elapsed += a->tv_nsec - b->tv_nsec;
	return elapsed / p;
}

void show_perf(char *name, int tsize, int iters, struct timespec *start,
		struct timespec *end, int xfers_per_iter)
{
	static int header = 1;
	char str[FT_STR_LEN];
	int64_t elapsed = get_elapsed(start, end, MICRO);
	long long bytes = (long long) iters * tsize * xfers_per_iter;
	float usec_per_xfer;

	if (name) {
		if (header) {
			printf("%-50s%-8s%-8s%-8s%8s %10s%13s%13s\n",
					"name", "bytes", "iters",
					"total", "time", "MB/sec",
					"usec/xfer", "Mxfers/sec");
			header = 0;
		}

		printf("%-50s", name);
	} else {
		if (header) {
			printf("%-8s%-8s%-8s%8s %10s%13s%13s\n",
					"bytes", "iters", "total",
					"time", "MB/sec", "usec/xfer",
					"Mxfers/sec");
			header = 0;
		}
	}

	printf("%-8s", size_str(str, tsize));

	printf("%-8s", cnt_str(str, iters));

	printf("%-8s", size_str(str, bytes));

	usec_per_xfer = ((float)elapsed / iters / xfers_per_iter);
	printf("%8.2fs%10.2f%11.2f%11.2f\n",
		elapsed / 1000000.0, bytes / (1.0 * elapsed),
		usec_per_xfer, 1.0/usec_per_xfer);
}

void ft_usage(char *name, char *desc)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  %s [OPTIONS]\t\tstart server\n", name);
	fprintf(stderr, "  %s [OPTIONS] <host>\tconnect to server\n", name);

	if (desc)
		fprintf(stderr, "\n%s\n", desc);

	fprintf(stderr, "\nOptions:\n");
	FT_PRINT_OPTS_USAGE("-n <domain>", "domain name");
	FT_PRINT_OPTS_USAGE("-b <src_port>", "non default source port number");
	FT_PRINT_OPTS_USAGE("-p <dst_port>", "non default destination port number");
	FT_PRINT_OPTS_USAGE("-f <provider>", "specific provider name eg sockets, verbs");
	FT_PRINT_OPTS_USAGE("-s <address>", "source address");
	FT_PRINT_OPTS_USAGE("-a <address vector name>", "name of address vector");
	FT_PRINT_OPTS_USAGE("-h", "display this help output");

	return;
}

void ft_csusage(char *name, char *desc)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  %s [OPTIONS]\t\tstart server\n", name);
	fprintf(stderr, "  %s [OPTIONS] <host>\tconnect to server\n", name);

	if (desc)
		fprintf(stderr, "\n%s\n", desc);

	fprintf(stderr, "\nOptions:\n");
	FT_PRINT_OPTS_USAGE("-n <domain>", "domain name");
	FT_PRINT_OPTS_USAGE("-b <src_port>", "non default source port number");
	FT_PRINT_OPTS_USAGE("-p <dst_port>", "non default destination port number");
	FT_PRINT_OPTS_USAGE("-s <address>", "source address");
	FT_PRINT_OPTS_USAGE("-f <provider>", "specific provider name eg sockets, verbs");
	FT_PRINT_OPTS_USAGE("-e <ep_type>", "Endpoint type: msg|rdm|dgram (default:dgram)");
	FT_PRINT_OPTS_USAGE("-I <number>", "number of iterations");
	FT_PRINT_OPTS_USAGE("-S <size>", "specific transfer size or 'all'");
	FT_PRINT_OPTS_USAGE("-h", "display this help output");

	return;
}

void ft_parseinfo(int op, char *optarg, struct fi_info *hints)
{
	switch (op) {
	case 'n':
		if (!hints->domain_attr) {
			hints->domain_attr = malloc(sizeof *(hints->domain_attr));
			if (!hints->domain_attr) {
				perror("malloc");
				exit(EXIT_FAILURE);
			}
		}
		hints->domain_attr->name = strdup(optarg);
		break;
	case 'f':
		if (!hints->fabric_attr) {
			hints->fabric_attr = malloc(sizeof *(hints->fabric_attr));
			if (!hints->fabric_attr) {
				perror("malloc");
				exit(EXIT_FAILURE);
			}
		}
		hints->fabric_attr->prov_name = strdup(optarg);
		break;
	case 'e':
		if (!strncasecmp("msg", optarg, 3))
			hints->ep_attr->type = FI_EP_MSG;
		if (!strncasecmp("rdm", optarg, 3))
			hints->ep_attr->type = FI_EP_RDM;
		if (!strncasecmp("dgram", optarg, 5))
			hints->ep_attr->type = FI_EP_DGRAM;
		break;
	default:
		/* let getopt handle unknown opts*/
		break;

	}
}

void ft_parse_addr_opts(int op, char *optarg, struct ft_opts *opts)
{
	switch (op) {
	case 's':
		opts->src_addr = optarg;
		break;
	case 'b':
		opts->src_port = optarg;
		break;
	case 'p':
		opts->dst_port = optarg;
		break;
	default:
		/* let getopt handle unknown opts*/
		break;
	}
}

void ft_parsecsopts(int op, char *optarg, struct ft_opts *opts)
{
	ft_parse_addr_opts(op, optarg, opts);

	switch (op) {

	case 'I':
		opts->options |= FT_OPT_ITER;
		opts->iterations = atoi(optarg);
		break;
	
	case 'S':
		if (!strncasecmp("all", optarg, 3)) {
			opts->sizes_enabled = FT_ENABLE_ALL;
		} else {
			opts->options |= FT_OPT_SIZE;
			opts->transfer_size = atoi(optarg);
		}
		break;
	
	default:
		/* let getopt handle unknown opts*/
		break;
	}
}

void ft_parse_benchmark_opts(struct ct_pingpong *ct, int op, char *optarg)
{
	switch (op) {
	case 'v':
		ct->opts.options |= FT_OPT_VERIFY_DATA;
		break;

	default:
		break;
	}
}

void ft_benchmark_usage(void)
{
	FT_PRINT_OPTS_USAGE("-v", "enables data_integrity checks");
}

/*******************************************************************************************/
/*                                      PING PONG                                          */
/*******************************************************************************************/

int pingpong(struct ct_pingpong *ct)
{
	int ret, i;

	ret = ft_sync(ct);
	if (ret)
		return ret;

	ft_start(ct);
	if (ct->opts.dst_addr) {
		for (i = 0; i < ct->opts.iterations; i++) {

			if (ct->opts.transfer_size < ct->fi->tx_attr->inject_size)
				ret = ft_inject(ct, ct->ep, ct->opts.transfer_size);
			else
				ret = ft_tx(ct, ct->ep, ct->opts.transfer_size);
			if (ret)
				return ret;

			ret = ft_rx(ct, ct->ep, ct->opts.transfer_size);
			if (ret)
				return ret;
		}
	} else {
		for (i = 0; i < ct->opts.iterations; i++) {

			ret = ft_rx(ct, ct->ep, ct->opts.transfer_size);
			if (ret)
				return ret;

			if (ct->opts.transfer_size < ct->fi->tx_attr->inject_size)
				ret = ft_inject(ct, ct->ep, ct->opts.transfer_size);
			else
				ret = ft_tx(ct, ct->ep, ct->opts.transfer_size);
			if (ret)
				return ret;
		}
	}
	ft_stop(ct);

	show_perf(NULL, ct->opts.transfer_size, ct->opts.iterations, &(ct->start), &(ct->end), 2);

	return 0;
}

static int run_pingpong_dgram(struct ct_pingpong *ct)
{
	int i, ret;

	fprintf(stderr, "Running pingpong test with DGRAM endpoint\n");

	ret = ft_init_fabric(ct);
	if (ret)
		return ret;

	/* Post an extra receive to avoid lacking a posted receive in the
	 * finalize.
	 */
	ret = fi_recv(ct->ep, ct->rx_buf, ct->rx_size, fi_mr_desc(ct->mr),
			0, &ct->rx_ctx);

	if (!(ct->opts.options & FT_OPT_SIZE)) {
		for (i = 0; i < TEST_CNT; i++) {
			if (!ft_use_size(i, ct->opts.sizes_enabled))
				continue;

			ct->opts.transfer_size = test_size[i].size;
			if (ct->opts.transfer_size > ct->fi->ep_attr->max_msg_size)
			{
				fprintf(stderr,
					"Message size [%d] unsupported for endpoint %s "
					"(maximum message size = %d)\n",
					ct->opts.transfer_size,
					ep_name(ct->hints->ep_attr->type),
					(int) ct->fi->ep_attr->max_msg_size);
				continue;
			}

			init_test(ct, &(ct->opts), ct->test_name, sizeof(ct->test_name));
			ret = pingpong(ct);
			if (ret)
				return ret;
		}
	} else {
		init_test(ct, &(ct->opts), ct->test_name, sizeof(ct->test_name));
		ret = pingpong(ct);
		if (ret)
			return ret;
	}

	return ft_finalize(ct);
}

static int run_pingpong_rdm(struct ct_pingpong *ct)
{
	int i, ret = 0;

	fprintf(stderr, "Running pingpong test with RDM endpoint\n");

	ret = ft_init_fabric(ct);
	if (ret)
		return ret;

	if (!(ct->opts.options & FT_OPT_SIZE)) {
		for (i = 0; i < TEST_CNT; i++) {
			if (!ft_use_size(i, ct->opts.sizes_enabled))
				continue;
			ct->opts.transfer_size = test_size[i].size;
			init_test(ct, &(ct->opts), ct->test_name, sizeof(ct->test_name));
			ret = pingpong(ct);
			if (ret)
				return ret;
		}
	} else {
		init_test(ct, &(ct->opts), ct->test_name, sizeof(ct->test_name));
		ret = pingpong(ct);
		if (ret)
			return ret;
	}

	return ft_finalize(ct);
}

static int run_pingpong_msg(struct ct_pingpong *ct)
{
	int i, ret;

	fprintf(stderr, "Running pingpong test with MSG endpoint\n");

	if (!ct->opts.dst_addr) {
		ret = ft_start_server(ct);
		if (ret)
			return ret;
	}

	ret = ct->opts.dst_addr ? ft_client_connect(ct) : ft_server_connect(ct);
	if (ret) {
		return ret;
	}

	if (!(ct->opts.options & FT_OPT_SIZE)) {
		for (i = 0; i < TEST_CNT; i++) {
			if (!ft_use_size(i, ct->opts.sizes_enabled))
				continue;
			ct->opts.transfer_size = test_size[i].size;
			init_test(ct, &(ct->opts), ct->test_name, sizeof(ct->test_name));
			ret = pingpong(ct);
			if (ret)
				goto out;
		}
	} else {
		init_test(ct, &(ct->opts), ct->test_name, sizeof(ct->test_name));
		ret = pingpong(ct);
		if (ret)
			goto out;
	}

	ret = ft_finalize(ct);
out:
	fi_shutdown(ct->ep, 0);
	return ret;
}


void ft_init_ct_pingpong(struct ct_pingpong *ct)
{
	ct->fi_pep = NULL;
	ct->fi = NULL;
	ct->hints = NULL;
	ct->fabric = NULL;
	ct->waitset = NULL;
	ct->domain = NULL;
	ct->pollset = NULL;
	ct->pep = NULL;
	ct->ep = NULL;
	ct->alias_ep = NULL;
	ct->txcq = NULL;
	ct->rxcq = NULL;
	ct->txcntr = NULL;
	ct->rxcntr = NULL;
	ct->mr = NULL;
	ct->av = NULL;
	ct->eq = NULL;

	//no_mr;
	//tx_ctx, rx_ctx;
	ct->ctx_arr = NULL;
	ct->remote_cq_data = 0;

	ct->tx_seq = 0;
	ct->rx_seq = 0;
       	ct->tx_cq_cntr = 0;
	ct->rx_cq_cntr = 0;

	ct->ft_skip_mr = 0;
	ct->ft_parent_proc = 0;
	ct->ft_child_pid = 0;
	//ft_socket_pair[2];

	ct->remote_fi_addr = FI_ADDR_UNSPEC;
	ct->buf = NULL;
	ct->tx_buf = NULL;
	ct->rx_buf = NULL;

	ct->buf_size = 0;
       	ct->tx_size = 0;
	ct->rx_size = 0;
	ct->rx_fd = -1;
	ct->tx_fd = -1;
	strncpy(ct->default_port, "9228", 8);

	strncpy(ct->test_name, "custom", 50);
	ct->timeout = -1;
	//start, end;

	ct->av_attr = (struct fi_av_attr) {
		.type = FI_AV_MAP,
		.count = 1
	};
	ct->eq_attr = (struct fi_eq_attr) {
		.wait_obj = FI_WAIT_UNSPEC
	};
	ct->cq_attr = (struct fi_cq_attr) {
		.wait_obj = FI_WAIT_NONE
	};
	ct->cntr_attr = (struct fi_cntr_attr) {
		.events = FI_CNTR_EVENTS_COMP,
		.wait_obj = FI_WAIT_NONE
	};

}

int main(int argc, char **argv)
{
	int ret, op;

	ret = EXIT_SUCCESS;

	struct ct_pingpong ct;

	ft_init_ct_pingpong(&ct);
	ct.opts = INIT_OPTS;

	ct.hints = fi_allocinfo();
	if (!ct.hints)
		return EXIT_FAILURE;

	while ((op = getopt(argc, argv, "h:" CS_OPTS INFO_OPTS BENCHMARK_OPTS)) !=
			-1) {
		switch (op) {
		default:
			ft_parse_benchmark_opts(&ct, op, optarg);
			ft_parseinfo(op, optarg, ct.hints);
			ft_parsecsopts(op, optarg, &(ct.opts));
			break;
		case '?':
		case 'h':
			ft_csusage(argv[0], "Ping pong client and server.");
			ft_benchmark_usage();
			return EXIT_FAILURE;
		}
	}

	if (optind < argc)
		ct.opts.dst_addr = argv[optind];

	if (!ct.hints->ep_attr->type || ct.hints->ep_attr->type == FI_EP_UNSPEC) {
		ct.hints->ep_attr->type = FI_EP_DGRAM;
	}

	switch(ct.hints->ep_attr->type) {
	case FI_EP_DGRAM:
		if (ct.opts.options & FT_OPT_SIZE)
			ct.hints->ep_attr->max_msg_size = ct.opts.transfer_size;
		ct.hints->caps = FI_MSG;
		ct.hints->mode |= FI_LOCAL_MR;
		ret = run_pingpong_dgram(&ct);
		break;
	case FI_EP_RDM:
		//ct->hints->ep_attr->type = FI_EP_RDM;
		ct.hints->caps = FI_MSG;
		ct.hints->mode = FI_CONTEXT | FI_LOCAL_MR;
		ret = run_pingpong_rdm(&ct);
		break;
	case FI_EP_MSG:
		ct.hints->caps = FI_MSG;
		ct.hints->mode = FI_LOCAL_MR;
		ret = run_pingpong_msg(&ct);
		break;
	default:
		fprintf(stderr, "Endpoint unsupported : %d\n", ct.hints->ep_attr->type);
		ret = EXIT_FAILURE;
	}


	ft_free_res(&ct);
	return -ret;
}
