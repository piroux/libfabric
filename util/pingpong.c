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

#define ADDR_OPTS "b:p:s:a:"
#define INFO_OPTS "n:f:e:"
#define CS_OPTS ADDR_OPTS "I:S:mc:t:w:l"

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


#define STR(s) #s

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
struct fi_context *ctx_arr = NULL;
uint64_t remote_cq_data = 0;

uint64_t tx_seq, rx_seq, tx_cq_cntr, rx_cq_cntr;
int ft_skip_mr = 0;
int ft_parent_proc = 0;
pid_t ft_child_pid = 0;
int ft_socket_pair[2];

fi_addr_t remote_fi_addr = FI_ADDR_UNSPEC;
void *buf, *tx_buf, *rx_buf;
size_t buf_size, tx_size, rx_size;
int rx_fd = -1, tx_fd = -1;
char default_port[8] = "9228";

char test_name[50] = "custom";
int timeout = -1;
struct timespec start, end;

struct fi_av_attr av_attr = {
	.type = FI_AV_MAP,
	.count = 1
};
struct fi_eq_attr eq_attr = {
	.wait_obj = FI_WAIT_UNSPEC
};
struct fi_cq_attr cq_attr = {
	.wait_obj = FI_WAIT_NONE
};
struct fi_cntr_attr cntr_attr = {
	.events = FI_CNTR_EVENTS_COMP,
	.wait_obj = FI_WAIT_NONE
};

struct ft_opts opts;

struct test_size_param {
	int size;
	int enable_flags;
};

const unsigned int test_cnt;
#define TEST_CNT test_cnt

#define FT_ENABLE_ALL		(~0)
#define FT_DEFAULT_SIZE		(1 << 0)

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

#define INTEG_SEED 7
static const char integ_alphabet[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const int integ_alphabet_length = (sizeof(integ_alphabet)/sizeof(*integ_alphabet)) - 1;

#define BENCHMARK_OPTS "vPj:W:"
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
int ft_alloc_bufs();
int ft_open_fabric_res();
int ft_getinfo(struct fi_info *hints, struct fi_info **info);
int ft_init_fabric();
int ft_start_server();
int ft_server_connect();
int ft_client_connect();
int ft_alloc_active_res(struct fi_info *fi);
int ft_init_ep(void);
int ft_init_alias_ep(uint64_t flags);
int ft_av_insert(struct fid_av *av, void *addr, size_t count, fi_addr_t *fi_addr,
		uint64_t flags, void *context);
int ft_init_av(void);
void ft_free_res();
void init_test(struct ft_opts *opts, char *test_name, size_t test_name_len);

int ft_sync();
int ft_finalize(void);

ssize_t ft_post_rx(struct fid_ep *ep, size_t size, struct fi_context* ctx);
ssize_t ft_post_tx(struct fid_ep *ep, size_t size, struct fi_context* ctx);
ssize_t ft_rx(struct fid_ep *ep, size_t size);
ssize_t ft_tx(struct fid_ep *ep, size_t size);
ssize_t ft_inject(struct fid_ep *ep, size_t size);

int ft_cq_readerr(struct fid_cq *cq);
int ft_get_rx_comp(uint64_t total);
int ft_get_tx_comp(uint64_t total);

void eq_readerr(struct fid_eq *eq, const char *eq_str);

int64_t get_elapsed(const struct timespec *b, const struct timespec *a,
		enum precision p);
void show_perf(char *name, int tsize, int iters, struct timespec *start,
		struct timespec *end, int xfers_per_iter);

int ft_getsrcaddr(char *node, char *service, struct fi_info *hints);
int ft_read_addr_opts(char **node, char **service, struct fi_info *hints,
		uint64_t *flags, struct ft_opts *opts);
char *size_str(char str[FT_STR_LEN], long long size);
char *cnt_str(char str[FT_STR_LEN], long long cnt);
int size_to_count(int size);

void ft_parse_benchmark_opts(int op, char *optarg);
void ft_benchmark_usage(void);
int pingpong(void);

/*******************************************************************************************/
/*                                       FT func                                           */
/*******************************************************************************************/


static inline int ft_use_size(int index, int enable_flags)
{
	return (enable_flags == FT_ENABLE_ALL) ||
		(enable_flags & test_size[index].enable_flags);
}

static inline void ft_start(void)
{
	opts.options |= FT_OPT_ACTIVE;
	clock_gettime(CLOCK_MONOTONIC, &start);
}

static inline void ft_stop(void)
{
	clock_gettime(CLOCK_MONOTONIC, &end);
	opts.options &= ~FT_OPT_ACTIVE;
}

static int ft_check_opts(uint64_t flags)
{
	return (opts.options & flags) == flags;
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


static void ft_cq_set_wait_attr(void)
{
	cq_attr.wait_obj = FI_WAIT_NONE;
}

static void ft_cntr_set_wait_attr(void)
{
	cntr_attr.wait_obj = FI_WAIT_NONE;
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
int ft_alloc_msgs(void)
{
	int ret;
	long alignment = 1;

	/* TODO: support multi-recv tests */
	if (fi->rx_attr->op_flags == FI_MULTI_RECV)
		return 0;

	tx_size = opts.options & FT_OPT_SIZE ?
		  opts.transfer_size : test_size[TEST_CNT - 1].size;
	if (tx_size > fi->ep_attr->max_msg_size)
		tx_size = fi->ep_attr->max_msg_size;
	rx_size = tx_size;
	buf_size = MAX(tx_size, FT_MAX_CTRL_MSG) + MAX(rx_size, FT_MAX_CTRL_MSG);

	if (opts.options & FT_OPT_ALIGN) {
		alignment = sysconf(_SC_PAGESIZE);
		if (alignment < 0)
			return -errno;
		buf_size += alignment;

		ret = posix_memalign(&buf, (size_t) alignment, buf_size);
		if (ret) {
			FT_PRINTERR("posix_memalign", ret);
			return ret;
		}
	} else {
		buf = malloc(buf_size);
		if (!buf) {
			perror("malloc");
			return -FI_ENOMEM;
		}
	}
	memset(buf, 0, buf_size);
	rx_buf = buf;
	tx_buf = (char *) buf + MAX(rx_size, FT_MAX_CTRL_MSG);
	tx_buf = (void *) (((uintptr_t) tx_buf + alignment - 1) &
			   ~(alignment - 1));

	remote_cq_data = ft_init_cq_data(fi);

	if (opts.window_size > 0) {
		ctx_arr = calloc(opts.window_size, sizeof(struct fi_context));
		if (!ctx_arr)
			return -FI_ENOMEM;
	}

	if (!ft_skip_mr && ((fi->mode & FI_LOCAL_MR) ||
				(fi->caps & (FI_RMA | FI_ATOMIC)))) {
		ret = fi_mr_reg(domain, buf, buf_size, ft_caps_to_mr_access(fi->caps),
				0, FT_MR_KEY, 0, &mr, NULL);
		if (ret) {
			FT_PRINTERR("fi_mr_reg", ret);
			return ret;
		}
	} else {
		mr = &no_mr;
	}

	return 0;
}

int ft_open_fabric_res(void)
{
	int ret;

	ret = fi_fabric(fi->fabric_attr, &fabric, NULL);
	if (ret) {
		FT_PRINTERR("fi_fabric", ret);
		return ret;
	}

	ret = fi_eq_open(fabric, &eq_attr, &eq, NULL);
	if (ret) {
		FT_PRINTERR("fi_eq_open", ret);
		return ret;
	}

	ret = fi_domain(fabric, fi, &domain, NULL);
	if (ret) {
		FT_PRINTERR("fi_domain", ret);
		return ret;
	}

	return 0;
}

int ft_alloc_active_res(struct fi_info *fi) // ... SNIP ??
{
	int ret;

	ret = ft_alloc_msgs();
	if (ret)
		return ret;

	if (cq_attr.format == FI_CQ_FORMAT_UNSPEC) { // ...
		if (fi->caps & FI_TAGGED)
			cq_attr.format = FI_CQ_FORMAT_TAGGED;
		else
			cq_attr.format = FI_CQ_FORMAT_CONTEXT;
	}

	if (opts.options & FT_OPT_TX_CQ) {
		ft_cq_set_wait_attr(); // ??
		cq_attr.size = fi->tx_attr->size;
		ret = fi_cq_open(domain, &cq_attr, &txcq, &txcq);
		if (ret) {
			FT_PRINTERR("fi_cq_open", ret);
			return ret;
		}
	}

	if (opts.options & FT_OPT_TX_CNTR) {
		ft_cntr_set_wait_attr(); // ??
		ret = fi_cntr_open(domain, &cntr_attr, &txcntr, &txcntr);
		if (ret) {
			FT_PRINTERR("fi_cntr_open", ret);
			return ret;
		}
	}

	if (opts.options & FT_OPT_RX_CQ) {
		ft_cq_set_wait_attr(); // ??
		cq_attr.size = fi->rx_attr->size;
		ret = fi_cq_open(domain, &cq_attr, &rxcq, &rxcq);
		if (ret) {
			FT_PRINTERR("fi_cq_open", ret);
			return ret;
		}
	}

	if (opts.options & FT_OPT_RX_CNTR) {
		ft_cntr_set_wait_attr(); // ??
		ret = fi_cntr_open(domain, &cntr_attr, &rxcntr, &rxcntr);
		if (ret) {
			FT_PRINTERR("fi_cntr_open", ret);
			return ret;
		}
	}

	if (fi->ep_attr->type == FI_EP_RDM || fi->ep_attr->type == FI_EP_DGRAM) {
		if (fi->domain_attr->av_type != FI_AV_UNSPEC)
			av_attr.type = fi->domain_attr->av_type;

		ret = fi_av_open(domain, &av_attr, &av, NULL);
		if (ret) {
			FT_PRINTERR("fi_av_open", ret);
			return ret;
		}
	}

	ret = fi_endpoint(domain, fi, &ep, NULL);
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

int ft_read_addr_opts(char **node, char **service, struct fi_info *hints,
		uint64_t *flags, struct ft_opts *opts)
{
	int ret;

	if (opts->dst_addr) {
		if (!opts->dst_port)
			opts->dst_port = default_port;

		ret = ft_getsrcaddr(opts->src_addr, opts->src_port, hints);
		if (ret)
			return ret;
		*node = opts->dst_addr;
		*service = opts->dst_port;
	} else {
		if (!opts->src_port)
			opts->src_port = default_port;

		*node = opts->src_addr;
		*service = opts->src_port;
		*flags = FI_SOURCE;
	}

	return 0;
}

int ft_getinfo(struct fi_info *hints, struct fi_info **info)
{
	char *node, *service;
	uint64_t flags = 0;
	int ret;

	ret = ft_read_addr_opts(&node, &service, hints, &flags, &opts);
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

static void ft_close_fids(void)
{
	if (mr != &no_mr)
		FT_CLOSE_FID(mr);
	FT_CLOSE_FID(alias_ep);
	FT_CLOSE_FID(ep);
	FT_CLOSE_FID(pep);
	FT_CLOSE_FID(pollset);
	FT_CLOSE_FID(rxcq);
	FT_CLOSE_FID(txcq);
	FT_CLOSE_FID(rxcntr);
	FT_CLOSE_FID(txcntr);
	FT_CLOSE_FID(av);
	FT_CLOSE_FID(eq);
	FT_CLOSE_FID(domain);
	FT_CLOSE_FID(waitset);
	FT_CLOSE_FID(fabric);
}

void ft_free_res(void)
{
	ft_close_fids();
	if (ctx_arr) {
		free(ctx_arr);
		ctx_arr = NULL;
	}

	if (buf) {
		free(buf);
		buf = rx_buf = tx_buf = NULL;
		buf_size = rx_size = tx_size = 0;
	}
	if (fi_pep) {
		fi_freeinfo(fi_pep);
		fi_pep = NULL;
	}
	if (fi) {
		fi_freeinfo(fi);
		fi = NULL;
	}
	if (hints) {
		fi_freeinfo(hints);
		hints = NULL;
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

int size_to_count(int size)
{
	if (size >= (1 << 20))
		return (opts.options & FT_OPT_BW) ? 200 : 100;
	else if (size >= (1 << 16))
		return (opts.options & FT_OPT_BW) ? 2000 : 1000;
	else
		return (opts.options & FT_OPT_BW) ? 20000: 10000;
}

void init_test(struct ft_opts *opts, char *test_name, size_t test_name_len)
{
	char sstr[FT_STR_LEN];

	size_str(sstr, opts->transfer_size);
	if (!strcmp(test_name, "custom"))
		snprintf(test_name, test_name_len, "%s_lat", sstr);
	if (!(opts->options & FT_OPT_ITER))
		opts->iterations = size_to_count(opts->transfer_size);
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
			timeout_save = timeout;					\
			timeout = 0;						\
			rc = comp_fn(seq);					\
			if (rc && rc != -FI_EAGAIN) {				\
				FT_ERR("Failed to get " op_str " completion");	\
				return rc;					\
			}							\
			timeout = timeout_save;					\
		}								\
		seq++;								\
	} while (0)

ssize_t ft_post_tx(struct fid_ep *ep, size_t size, struct fi_context* ctx)
{
	FT_POST(fi_send, ft_get_tx_comp, tx_seq, "transmit", ep,
			tx_buf,	size, fi_mr_desc(mr),
			remote_fi_addr, ctx);
	return 0;
}

ssize_t ft_tx(struct fid_ep *ep, size_t size)
{
	ssize_t ret;

	if (ft_check_opts(FT_OPT_VERIFY_DATA | FT_OPT_ACTIVE))
		ft_fill_buf((char *) tx_buf, size);

	ret = ft_post_tx(ep, size, &tx_ctx);
	if (ret)
		return ret;

	ret = ft_get_tx_comp(tx_seq);
	return ret;
}

ssize_t ft_post_inject(struct fid_ep *ep, size_t size)
{
	FT_POST(fi_inject, ft_get_tx_comp, tx_seq, "inject",
			ep, tx_buf, size,
			remote_fi_addr);
	tx_cq_cntr++;
	return 0;
}

ssize_t ft_inject(struct fid_ep *ep, size_t size)
{
	ssize_t ret;

	if (ft_check_opts(FT_OPT_VERIFY_DATA | FT_OPT_ACTIVE))
		ft_fill_buf((char *) tx_buf, size);

	ret = ft_post_inject(ep, size);
	if (ret)
		return ret;

	return ret;
}


ssize_t ft_post_rx(struct fid_ep *ep, size_t size, struct fi_context* ctx)
{
	FT_POST(fi_recv, ft_get_rx_comp, rx_seq, "receive", ep, rx_buf,
			MAX(size, FT_MAX_CTRL_MSG),
			fi_mr_desc(mr),	0, ctx);
	return 0;
}

ssize_t ft_rx(struct fid_ep *ep, size_t size)
{
	ssize_t ret;

	ret = ft_get_rx_comp(rx_seq);
	if (ret)
		return ret;

	if (ft_check_opts(FT_OPT_VERIFY_DATA | FT_OPT_ACTIVE)) {
		ret = ft_check_buf((char *) rx_buf, size);
		if (ret)
			return ret;
	}
	/* TODO: verify CQ data, if available */

	/* Ignore the size arg. Post a buffer large enough to handle all message
	 * sizes. ft_sync() makes use of ft_rx() and gets called in tests just before
	 * message size is updated. The recvs posted are always for the next incoming
	 * message */
	ret = ft_post_rx(ep, rx_size, &rx_ctx);
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

int ft_get_rx_comp(uint64_t total)
{
	int ret = FI_SUCCESS;

	if (rxcq) {
		ret = ft_get_cq_comp(rxcq, &rx_cq_cntr, total, timeout);
	} else if (rxcntr) {
		while (fi_cntr_read(rxcntr) < total) {
			ret = fi_cntr_wait(rxcntr, total, timeout);
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

int ft_get_tx_comp(uint64_t total)
{
	int ret;

	if (txcq) {
		ret = ft_get_cq_comp(txcq, &tx_cq_cntr, total, -1);
	} else if (txcntr) {
		ret = fi_cntr_wait(txcntr, total, -1);
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


int ft_sync()
{
	int ret;

	if (opts.dst_addr) {
		ret = ft_tx(ep, 1);
		if (ret)
			return ret;

		ret = ft_rx(ep, 1);
	} else {
		ret = ft_rx(ep, 1);
		if (ret)
			return ret;

		ret = ft_tx(ep, 1);
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

int ft_init_alias_ep(uint64_t flags)
{
	int ret;
	ret = fi_ep_alias(ep, &alias_ep, flags);
	if (ret) {
		FT_PRINTERR("fi_ep_alias", ret);
		return ret;
	}
	return 0;
}

int ft_init_ep(void)
{
	int flags, ret;

	if (fi->ep_attr->type == FI_EP_MSG)
		FT_EP_BIND(ep, eq, 0);
	FT_EP_BIND(ep, av, 0);
	FT_EP_BIND(ep, txcq, FI_TRANSMIT);
	FT_EP_BIND(ep, rxcq, FI_RECV);

	/* TODO: use control structure to select counter bindings explicitly */
	flags = !txcq ? FI_SEND : 0;
	if (hints->caps & (FI_WRITE | FI_READ))
		flags |= hints->caps & (FI_WRITE | FI_READ);
	else if (hints->caps & FI_RMA)
		flags |= FI_WRITE | FI_READ;
	FT_EP_BIND(ep, txcntr, flags);
	flags = !rxcq ? FI_RECV : 0;
	if (hints->caps & (FI_REMOTE_WRITE | FI_REMOTE_READ))
		flags |= hints->caps & (FI_REMOTE_WRITE | FI_REMOTE_READ);
	else if (hints->caps & FI_RMA)
		flags |= FI_REMOTE_WRITE | FI_REMOTE_READ;
	FT_EP_BIND(ep, rxcntr, flags);

	ret = fi_enable(ep);
	if (ret) {
		FT_PRINTERR("fi_enable", ret);
		return ret;
	}

	if (fi->rx_attr->op_flags != FI_MULTI_RECV) {
		/* Initial receive will get remote address for unconnected EPs */
		ret = ft_post_rx(ep, MAX(rx_size, FT_MAX_CTRL_MSG), &rx_ctx);
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
int ft_init_av(void)
{
	size_t addrlen;
	int ret;

	if (opts.dst_addr) {
		ret = ft_av_insert(av, fi->dest_addr, 1, &remote_fi_addr, 0, NULL);
		if (ret)
			return ret;

		addrlen = FT_MAX_CTRL_MSG;
		ret = fi_getname(&ep->fid, (char *) tx_buf,
				 &addrlen);
		if (ret) {
			FT_PRINTERR("fi_getname", ret);
			return ret;
		}

		ret = (int) ft_tx(ep, addrlen);
		if (ret)
			return ret;

		ret = ft_rx(ep, 1);
	} else {
		ret = (int) ft_rx(ep, FT_MAX_CTRL_MSG);
		if (ret)
			return ret;

		ret = ft_av_insert(av, (char *) rx_buf,
				   1, &remote_fi_addr, 0, NULL);
		if (ret)
			return ret;

		ret = (int) ft_tx(ep, 1);
	}

	return ret;
}

int ft_start_server(void)
{
	int ret;

	ret = ft_getinfo(hints, &fi_pep);
	if (ret)
		return ret;

	ret = fi_fabric(fi_pep->fabric_attr, &fabric, NULL);
	if (ret) {
		FT_PRINTERR("fi_fabric", ret);
		return ret;
	}

	ret = fi_eq_open(fabric, &eq_attr, &eq, NULL);
	if (ret) {
		FT_PRINTERR("fi_eq_open", ret);
		return ret;
	}

	ret = fi_passive_ep(fabric, fi_pep, &pep, NULL);
	if (ret) {
		FT_PRINTERR("fi_passive_ep", ret);
		return ret;
	}

	ret = fi_pep_bind(pep, &eq->fid, 0);
	if (ret) {
		FT_PRINTERR("fi_pep_bind", ret);
		return ret;
	}

	ret = fi_listen(pep);
	if (ret) {
		FT_PRINTERR("fi_listen", ret);
		return ret;
	}

	return 0;
}

int ft_server_connect(void)
{
	struct fi_eq_cm_entry entry;
	uint32_t event;
	ssize_t rd;
	int ret;

	rd = fi_eq_sread(eq, &event, &entry, sizeof entry, -1, 0);
	if (rd != sizeof entry) {
		FT_PROCESS_EQ_ERR(rd, eq, "fi_eq_sread", "listen");
		return (int) rd;
	}

	fi = entry.info;
	if (event != FI_CONNREQ) {
		fprintf(stderr, "Unexpected CM event %d\n", event);
		ret = -FI_EOTHER;
		goto err;
	}

	ret = fi_domain(fabric, fi, &domain, NULL);
	if (ret) {
		FT_PRINTERR("fi_domain", ret);
		goto err;
	}

	ret = ft_alloc_active_res(fi);
	if (ret)
		goto err;

	ret = ft_init_ep();
	if (ret)
		goto err;

	ret = fi_accept(ep, NULL, 0);
	if (ret) {
		FT_PRINTERR("fi_accept", ret);
		goto err;
	}

	rd = fi_eq_sread(eq, &event, &entry, sizeof entry, -1, 0);
	if (rd != sizeof entry) {
		FT_PROCESS_EQ_ERR(rd, eq, "fi_eq_sread", "accept");
		ret = (int) rd;
		goto err;
	}

	if (event != FI_CONNECTED || entry.fid != &ep->fid) {
		fprintf(stderr, "Unexpected CM event %d fid %p (ep %p)\n",
			event, entry.fid, ep);
		ret = -FI_EOTHER;
		goto err;
	}

	return 0;

err:
	fi_reject(pep, fi->handle, NULL, 0);
	return ret;
}

int ft_client_connect(void)
{
	struct fi_eq_cm_entry entry;
	uint32_t event;
	ssize_t rd;
	int ret;

	ret = ft_getinfo(hints, &fi);
	if (ret)
		return ret;

	ret = ft_open_fabric_res();
	if (ret)
		return ret;

	ret = ft_alloc_active_res(fi);
	if (ret)
		return ret;

	ret = ft_init_ep();
	if (ret)
		return ret;

	ret = fi_connect(ep, fi->dest_addr, NULL, 0);
	if (ret) {
		FT_PRINTERR("fi_connect", ret);
		return ret;
	}

	rd = fi_eq_sread(eq, &event, &entry, sizeof entry, -1, 0);
	if (rd != sizeof entry) {
		FT_PROCESS_EQ_ERR(rd, eq, "fi_eq_sread", "connect");
		ret = (int) rd;
		return ret;
	}

	if (event != FI_CONNECTED || entry.fid != &ep->fid) {
		fprintf(stderr, "Unexpected CM event %d fid %p (ep %p)\n",
			event, entry.fid, ep);
		ret = -FI_EOTHER;
		return ret;
	}

	return 0;
}

int ft_init_fabric(void)
{
	int ret;

	ret = ft_getinfo(hints, &fi);
	if (ret)
		return ret;

	ret = ft_open_fabric_res();
	if (ret)
		return ret;

	ret = ft_alloc_active_res(fi);
	if (ret)
		return ret;

	ret = ft_init_ep();
	if (ret)
		return ret;

	ret = ft_init_av();
	if (ret)
		return ret;

	return 0;
}

int ft_finalize(void)
{
	struct iovec iov;
	int ret;
	struct fi_context ctx;

	strcpy(tx_buf, "fin");
	iov.iov_base = tx_buf;
	iov.iov_len = 4;

	if (hints->caps & FI_TAGGED) {
		struct fi_msg_tagged tmsg;

		memset(&tmsg, 0, sizeof tmsg);
		tmsg.msg_iov = &iov;
		tmsg.iov_count = 1;
		tmsg.addr = remote_fi_addr;
		tmsg.tag = tx_seq;
		tmsg.ignore = 0;
		tmsg.context = &ctx;

		ret = fi_tsendmsg(ep, &tmsg, FI_INJECT | FI_TRANSMIT_COMPLETE);
	} else {
		struct fi_msg msg;

		memset(&msg, 0, sizeof msg);
		msg.msg_iov = &iov;
		msg.iov_count = 1;
		msg.addr = remote_fi_addr;
		msg.context = &ctx;

		ret = fi_sendmsg(ep, &msg, FI_INJECT | FI_TRANSMIT_COMPLETE);
	}
	if (ret) {
		FT_PRINTERR("transmit", ret);
		return ret;
	}


	ret = ft_get_tx_comp(++tx_seq);
	if (ret)
		return ret;

	ret = ft_get_rx_comp(rx_seq);
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

/*******************************************************************************************/
/*                                      PING PONG                                          */
/*******************************************************************************************/

void ft_parse_benchmark_opts(int op, char *optarg)
{
	switch (op) {
	case 'v':
		opts.options |= FT_OPT_VERIFY_DATA;
		break;

	default:
		break;
	}
}

void ft_benchmark_usage(void)
{
	FT_PRINT_OPTS_USAGE("-v", "enables data_integrity checks");
}

int pingpong(void)
{
	int ret, i;

	ret = ft_sync();
	if (ret)
		return ret;

	ft_start();
	if (opts.dst_addr) {
		for (i = 0; i < opts.iterations; i++) {

			if (opts.transfer_size < fi->tx_attr->inject_size)
				ret = ft_inject(ep, opts.transfer_size);
			else
				ret = ft_tx(ep, opts.transfer_size);
			if (ret)
				return ret;

			ret = ft_rx(ep, opts.transfer_size);
			if (ret)
				return ret;
		}
	} else {
		for (i = 0; i < opts.iterations; i++) {

			ret = ft_rx(ep, opts.transfer_size);
			if (ret)
				return ret;

			if (opts.transfer_size < fi->tx_attr->inject_size)
				ret = ft_inject(ep, opts.transfer_size);
			else
				ret = ft_tx(ep, opts.transfer_size);
			if (ret)
				return ret;
		}
	}
	ft_stop();

	show_perf(NULL, opts.transfer_size, opts.iterations, &start, &end, 2);

	return 0;
}

static int run_pingpong_dgram(void)
{
	int i, ret;

	fprintf(stderr, "Running pingpong test with DGRAM endpoint\n");

	ret = ft_init_fabric();
	if (ret)
		return ret;

	/* Post an extra receive to avoid lacking a posted receive in the
	 * finalize.
	 */
	ret = fi_recv(ep, rx_buf, rx_size, fi_mr_desc(mr),
			0, &rx_ctx);

	if (!(opts.options & FT_OPT_SIZE)) {
		for (i = 0; i < TEST_CNT; i++) {
			if (!ft_use_size(i, opts.sizes_enabled))
				continue;

			opts.transfer_size = test_size[i].size;
			if (opts.transfer_size > fi->ep_attr->max_msg_size)
			{
				fprintf(stderr,
					"Message size [%d] unsupported for endpoint %s "
					"(maximum message size = %d)\n",
					opts.transfer_size,
					ep_name(hints->ep_attr->type),
					(int) fi->ep_attr->max_msg_size);
				continue;
			}

			init_test(&opts, test_name, sizeof(test_name));
			ret = pingpong();
			if (ret)
				return ret;
		}
	} else {
		init_test(&opts, test_name, sizeof(test_name));
		ret = pingpong();
		if (ret)
			return ret;
	}

	return ft_finalize();
}

static int run_pingpong_rdm(void)
{
	int i, ret = 0;

	fprintf(stderr, "Running pingpong test with RDM endpoint\n");

	ret = ft_init_fabric();
	if (ret)
		return ret;

	if (!(opts.options & FT_OPT_SIZE)) {
		for (i = 0; i < TEST_CNT; i++) {
			if (!ft_use_size(i, opts.sizes_enabled))
				continue;
			opts.transfer_size = test_size[i].size;
			init_test(&opts, test_name, sizeof(test_name));
			ret = pingpong();
			if (ret)
				return ret;
		}
	} else {
		init_test(&opts, test_name, sizeof(test_name));
		ret = pingpong();
		if (ret)
			return ret;
	}

	return ft_finalize();
}

static int run_pingpong_msg(void)
{
	int i, ret;

	fprintf(stderr, "Running pingpong test with MSG endpoint\n");

	if (!opts.dst_addr) {
		ret = ft_start_server();
		if (ret)
			return ret;
	}

	ret = opts.dst_addr ? ft_client_connect() : ft_server_connect();
	if (ret) {
		return ret;
	}

	if (!(opts.options & FT_OPT_SIZE)) {
		for (i = 0; i < TEST_CNT; i++) {
			if (!ft_use_size(i, opts.sizes_enabled))
				continue;
			opts.transfer_size = test_size[i].size;
			init_test(&opts, test_name, sizeof(test_name));
			ret = pingpong();
			if (ret)
				goto out;
		}
	} else {
		init_test(&opts, test_name, sizeof(test_name));
		ret = pingpong();
		if (ret)
			goto out;
	}

	ret = ft_finalize();
out:
	fi_shutdown(ep, 0);
	return ret;
}

int main(int argc, char **argv)
{
	int ret, op;

	ret = EXIT_SUCCESS;

	opts = INIT_OPTS;

	hints = fi_allocinfo();
	if (!hints)
		return EXIT_FAILURE;

	while ((op = getopt(argc, argv, "h:" CS_OPTS INFO_OPTS BENCHMARK_OPTS)) !=
			-1) {
		switch (op) {
		default:
			ft_parse_benchmark_opts(op, optarg);
			ft_parseinfo(op, optarg, hints);
			ft_parsecsopts(op, optarg, &opts);
			break;
		case '?':
		case 'h':
			ft_csusage(argv[0], "Ping pong client and server.");
			ft_benchmark_usage();
			return EXIT_FAILURE;
		}
	}

	if (optind < argc)
		opts.dst_addr = argv[optind];

	if (!hints->ep_attr->type || hints->ep_attr->type == FI_EP_UNSPEC) {
		hints->ep_attr->type = FI_EP_DGRAM;
	}

	switch(hints->ep_attr->type) {
	case FI_EP_DGRAM:
		if (opts.options & FT_OPT_SIZE)
			hints->ep_attr->max_msg_size = opts.transfer_size;
		hints->caps = FI_MSG;
		hints->mode |= FI_LOCAL_MR;
		ret = run_pingpong_dgram();
		break;
	case FI_EP_RDM:
		//hints->ep_attr->type = FI_EP_RDM;
		hints->caps = FI_MSG;
		hints->mode = FI_CONTEXT | FI_LOCAL_MR;
		ret = run_pingpong_rdm();
		break;
	case FI_EP_MSG:
		hints->caps = FI_MSG;
		hints->mode = FI_LOCAL_MR;
		ret = run_pingpong_msg();
		break;
	default:
		fprintf(stderr, "Endpoint unsupported : %d\n", hints->ep_attr->type);
		ret = EXIT_FAILURE;
	}


	ft_free_res();
	return -ret;
}
