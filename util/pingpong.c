/*
 * Copyright (c) 2013-2015 Intel Corporation.  All rights reserved.
 * Copyright (c) 2014-2016, Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2015 Los Alamos Nat. Security, LLC. All rights reserved.
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

#include <config.h>

#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <assert.h>
#include <getopt.h>
#include <inttypes.h>
#include <netdb.h>
#include <poll.h>
#include <limits.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>

#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_errno.h>

#ifndef PP_FIVERSION
#define PP_FIVERSION FI_VERSION(1,3)
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
	PP_OPT_ACTIVE		= 1 << 0,
	PP_OPT_ITER		= 1 << 1,
	PP_OPT_SIZE		= 1 << 2,
	PP_OPT_VERIFY_DATA	= 1 << 3,
};

struct pp_opts {
	char *src_port;
	char *dst_port;
	char *src_addr;
	char *dst_addr;
	int iterations;
	int transfer_size;
	int sizes_enabled;
	int options;
	int argc;
	char **argv;
};

#define PP_SIZE_MAX_POWER_TWO 22
#define PP_MAX_DATA_MSG (1 << (PP_SIZE_MAX_POWER_TWO + 1)) + (1 << PP_SIZE_MAX_POWER_TWO);

#define PP_STR_LEN 32
#define PP_MAX_CTRL_MSG 64
#define PP_CTRL_BUF_LEN 64
#define PP_MR_KEY 0xC0DE

#define INTEG_SEED 7
#define PP_ENABLE_ALL (~0)
#define PP_DEFAULT_SIZE (1 << 0)

#define PP_MSG_CHECK_PORT_OK "port ok"
#define PP_MSG_LEN_PORT 5
#define PP_MSG_CHECK_CNT_OK "cnt ok"
#define PP_MSG_LEN_CNT 10
#define PP_MSG_SYNC_Q "q"
#define PP_MSG_SYNC_A "a"

#define PP_PRINTERR(call, retv)						\
	do {								\
		fprintf(stderr, "%s(): %s:%-4d, ret=%d (%s)\n", call,	\
			__FILE__, __LINE__, (int) retv,			\
			fi_strerror((int) -retv));			\
	} while (0)

#define PP_ERR(fmt, ...)						\
	do {								\
		fprintf(stderr, "[%s] %s:%-4d: " fmt "\n", "error",	\
			__FILE__, __LINE__, ##__VA_ARGS__);		\
	} while (0)							\

int PP_ACTIVATE_DEBUG = 0;

#define PP_DEBUG(fmt, ...)						\
	if (PP_ACTIVATE_DEBUG) {					\
		fprintf(stderr, "[%s] %s:%-4d: " fmt, "debug",		\
			__FILE__, __LINE__, ##__VA_ARGS__);		\
	}								\

#define PP_CLOSE_FID(fd)						\
	do {								\
		int ret;						\
		if ((fd)) {						\
			ret = fi_close(&(fd)->fid);			\
			if (ret)					\
				PP_ERR("fi_close (%d) fid %d",		\
					ret, (int) (fd)->fid.fclass);	\
			fd = NULL;					\
		}							\
	} while (0)

#define MAX(a,b) (((a)>(b))?(a):(b))

struct ct_pingpong {
	struct fi_info *fi_pep, *fi, *hints;
	struct fid_fabric *fabric;
	struct fid_domain *domain;
	struct fid_pep *pep;
	struct fid_ep *ep;
	struct fid_cq *txcq, *rxcq;
	struct fid_mr *mr;
	struct fid_av *av;
	struct fid_eq *eq;

	struct fid_mr no_mr;
	struct fi_context tx_ctx, rx_ctx;
	struct fi_context *ctx_arr;
	uint64_t remote_cq_data;

	uint64_t tx_seq, rx_seq, tx_cq_cntr, rx_cq_cntr;
	int pp_parent_proc;
	pid_t pp_child_pid;

	fi_addr_t remote_fi_addr;
	void *buf, *tx_buf, *rx_buf;
	size_t buf_size, tx_size, rx_size;
	int rx_fd, tx_fd;
	int data_default_port;
	char data_port[8];

	char test_name[50];
	int timeout;
	struct timespec start, end;

	struct fi_av_attr av_attr;
	struct fi_eq_attr eq_attr;
	struct fi_cq_attr cq_attr;
	struct pp_opts opts;

	long cnt_ack_msg;

	int ctrl_port;
	int ctrl_listenfd;
	int ctrl_connfd;
	struct sockaddr_in ctrl_addr;
	char ctrl_buf[PP_CTRL_BUF_LEN + 1];
};

static const char integ_alphabet[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const int integ_alphabet_length = (sizeof(integ_alphabet)/sizeof(*integ_alphabet)) - 1;

/*******************************************************************************************/
/*                                  Compatibility methods                                  */
/*******************************************************************************************/

#ifdef __APPLE__
int clock_gettime(clockid_t clk_id, struct timespec *tp) {
	int retval;
	struct timeval tv;

	retval = gettimeofday(&tv, NULL);

	tp->tv_sec = tv.tv_sec;
	tp->tv_nsec = tv.tv_usec * 1000;

	return retval;
}
#endif


/*******************************************************************************************/
/*                                         Utils                                           */
/*******************************************************************************************/

long parse_ulong(char *str, long max) {
	long ret;
	char *end;
	errno = 0;

	ret = strtol(str, &end, 10);
	if (*end != '\0' || errno != 0) {
		if (errno == 0)
			ret = -EINVAL;
		else
			ret = -errno;
		fprintf(stderr, "Error parsing \"%s\" : %s\n", str, strerror(-ret));
		return ret;
	}

	if ((ret < 0) || (max > 0 && ret > max)) {
		ret = -ERANGE;
		fprintf(stderr, "Error parsing \"%s\" : %s\n", str, strerror(-ret));
		return -ERANGE;
	}
	return ret;
}

int size_to_count(int size)
{
	if (size >= (1 << 20))
		return 100;
	else if (size >= (1 << 16))
		return 1000;
	else
		return 10000;
}

char *ep_name(int ep_type) {
	char *en;
	switch(ep_type) {
		case FI_EP_DGRAM:	en = "dgram"; break;
		case FI_EP_RDM:		en = "rdm"; break;
		case FI_EP_MSG:		en = "msg"; break;
		default:		en = "none(error)"; break;
	}
	return en;
}

void pp_banner_fabric_info(struct ct_pingpong *ct)
{
	PP_DEBUG("Running pingpong test with the %s endpoint trough a %s provider ...\n", ep_name(ct->fi->ep_attr->type), ct->fi->fabric_attr->prov_name);
	PP_DEBUG(" * Fabric Attributes:\n");
	PP_DEBUG("  - %-20s : %s\n", "name", ct->fi->fabric_attr->name);
	PP_DEBUG("  - %-20s : %s\n", "prov_name", ct->fi->fabric_attr->prov_name);
	PP_DEBUG("  - %-20s : %"PRIu32"\n", "prov_version", ct->fi->fabric_attr->prov_version);
	PP_DEBUG(" * Domain Attributes:\n");
	PP_DEBUG("  - %-20s : %s\n", "name", ct->fi->domain_attr->name);
	PP_DEBUG("  - %-20s : %zu\n", "cq_cnt", ct->fi->domain_attr->cq_cnt);
	PP_DEBUG("  - %-20s : %zu\n", "cq_data_size", ct->fi->domain_attr->cq_data_size);
	PP_DEBUG("  - %-20s : %zu\n", "ep_cnt", ct->fi->domain_attr->ep_cnt);
	PP_DEBUG(" * Endpoint Attributes:\n");
	PP_DEBUG("  - %-20s : %s\n", "type", ep_name(ct->fi->ep_attr->type));
	PP_DEBUG("  - %-20s : %"PRIu32"\n", "protocol", ct->fi->ep_attr->protocol);
	PP_DEBUG("  - %-20s : %"PRIu32"\n", "protocol_version", ct->fi->ep_attr->protocol_version);
	PP_DEBUG("  - %-20s : %zu\n", "max_msg_size", ct->fi->ep_attr->max_msg_size);
	PP_DEBUG("  - %-20s : %zu\n", "max_order_raw_size", ct->fi->ep_attr->max_order_raw_size);
}

void pp_banner_options(struct ct_pingpong *ct)
{
	char size_msg[50];
	char iter_msg[50];

	struct pp_opts opts = ct->opts;
	if ((opts.src_addr == NULL) || (opts.src_addr[0] == '\0'))
		opts.src_addr = "None";
	if ((opts.src_port == NULL) || (opts.src_port[0] == '\0'))
		opts.src_port = "None";
	if ((opts.dst_addr == NULL) || (opts.dst_addr[0] == '\0'))
		opts.dst_addr = "None";
	if ((opts.dst_port == NULL) || (opts.dst_addr[0] == '\0'))
		opts.dst_port = "None";

	if (opts.sizes_enabled == PP_ENABLE_ALL)
		snprintf(size_msg, 50, "%s", "All sizes");
	else if (opts.options & PP_OPT_SIZE)
		snprintf(size_msg, 50, "selected size = %d", opts.transfer_size);

	if (opts.options & PP_OPT_ITER)
		snprintf(iter_msg, 50, "selected iterations : %d", opts.iterations);
	else {
		opts.iterations = size_to_count(opts.transfer_size);
		snprintf(iter_msg, 50, "default iterations : %d", opts.iterations);
	}

	PP_DEBUG(" * PingPong options :\n");
	PP_DEBUG("  - %-20s : [%s]\n", "src_addr", opts.src_addr);
	PP_DEBUG("  - %-20s : [%s]\n", "src_port", opts.src_port);
	PP_DEBUG("  - %-20s : [%s]\n", "dst_addr", opts.dst_addr);
	PP_DEBUG("  - %-20s : [%s]\n", "dst_port", opts.dst_port);
	PP_DEBUG("  - %-20s : %s\n", "sizes_enabled", size_msg);
	PP_DEBUG("  - %-20s : %s\n", "iterations", iter_msg);
	PP_DEBUG("  - %-20s : %s\n", "provider", ct->hints->fabric_attr->prov_name);
}

/*******************************************************************************************/
/*                                   Control Messaging                                     */
/*******************************************************************************************/

int pp_ctrl_init(struct ct_pingpong  *ct)
{
	int err, ret;
	struct timeval tv;

	tv.tv_sec = 5;
	tv.tv_usec = 0;

	PP_DEBUG("Initializing control messages ...\n");

	if (ct->opts.dst_addr) {
		ct->ctrl_connfd = socket(AF_INET, SOCK_STREAM, 0);
		if (ct->ctrl_connfd == -1) {
			err = -errno;
			PP_PRINTERR("socket", err);
			return err;
		}

		memset(&ct->ctrl_addr, '\0', sizeof(ct->ctrl_addr));
		ct->ctrl_addr.sin_family = AF_INET;
		ret = inet_pton(AF_INET, ct->opts.dst_addr, &(ct->ctrl_addr.sin_addr));
		if (ret == 0) {
			err = -errno;
			PP_PRINTERR("inet_pton", err);
			return err;
		}
		ct->ctrl_addr.sin_port = htons(ct->ctrl_port);

		PP_DEBUG("CLIENT: connecting to <%s>\n", ct->opts.dst_addr);
		ret = connect(ct->ctrl_connfd, (struct sockaddr *)&ct->ctrl_addr, sizeof(ct->ctrl_addr));
		if (ret == -1) {
			err = -errno;
			PP_PRINTERR("connect", err);
			return err;
		}
		PP_DEBUG("CLIENT: connected\n");
	} else {
		ct->ctrl_listenfd = socket(AF_INET, SOCK_STREAM, 0);
		if (ct->ctrl_listenfd == -1) {
			err = -errno;
			PP_PRINTERR("socket", err);
		}
		ret = setsockopt(ct->ctrl_listenfd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
		if (ret == -1) {
			err = -errno;
			PP_PRINTERR("setsockopt(SO_REUSEADDR)", err);
			return err;
		}

		memset(&ct->ctrl_addr, '\0', sizeof(ct->ctrl_addr));
		ct->ctrl_addr.sin_family = AF_INET;
		ct->ctrl_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		ct->ctrl_addr.sin_port = htons(ct->ctrl_port);

		ret = bind(ct->ctrl_listenfd, (struct sockaddr*)&ct->ctrl_addr, sizeof(ct->ctrl_addr));
		if (ret == -1) {
			err = -errno;
			PP_PRINTERR("bind", err);
			return err;
		}

		ret = listen(ct->ctrl_listenfd, 1);
		if (ret == -1) {
			err = -errno;
			PP_PRINTERR("listen", err);
			return err;
		}

		PP_DEBUG("SERVER: waiting for connection ...\n");
		ct->ctrl_connfd = accept(ct->ctrl_listenfd, (struct sockaddr*)NULL, NULL);
		if (ct->ctrl_connfd == -1) {
			err = -errno;
			PP_PRINTERR("accept", err);
			return err;
		}
		PP_DEBUG("SERVER: connection acquired\n");
	}

	ret = setsockopt(ct->ctrl_connfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));
	if (ret == -1) {
		err = -errno;
		PP_PRINTERR("setsockopt(SO_RCVTIMEO)", err);
		return err;
	}

	PP_DEBUG("Control messages initialized\n");

	return 0;
}

int pp_ctrl_send(struct ct_pingpong *ct, char *buf, size_t size)
{
	int ret, err;

	ret = send(ct->ctrl_connfd, buf, size, 0);
	if (ret < 0) {
		err = -errno;
		PP_PRINTERR("ctrl/send", err);
		return err;
	}
	if (ret == 0) {
		err = -ECONNABORTED;
		PP_ERR("ctrl/read : no data or remote connection closed");
		return err;
	}
	PP_DEBUG("----> sent (%d/%ld) : \"", ret, size);
	if (PP_ACTIVATE_DEBUG) {
		int i;
		for (i = 0; i < size; i++) {
			fprintf(stderr, "%c.", buf[i]);
		}
		fprintf(stderr,"\"\n");
	}

	return ret;
}

int pp_ctrl_recv(struct ct_pingpong *ct, char *buf, size_t size)
{
	int ret, err;

	ret = recv(ct->ctrl_connfd, buf, size, 0);
	if (ret < 0) {
		err = -errno;
		PP_PRINTERR("ctrl/read", err);
		return err;
	}
	if (ret == 0) {
		err = -ECONNABORTED;
		PP_ERR("ctrl/read : no data or remote connection closed");
		return err;
	}
	PP_DEBUG("----> received (%d/%ld) : \"", ret, size);
	if (PP_ACTIVATE_DEBUG) {
		int i;
		for (i = 0; i < size; i++) {
			fprintf(stderr, "%c.", buf[i]);
		}
		fprintf(stderr, "\"\n");
	}

	return ret;
}

int pp_ctrl_finish(struct ct_pingpong *ct)
{
	if (ct->ctrl_connfd != -1)
		close(ct->ctrl_connfd);
	if (ct->ctrl_listenfd != -1)
		close(ct->ctrl_listenfd);

	return 0;
}

int pp_ctrl_txrx_data_port(struct ct_pingpong *ct)
{
	int ret;

	PP_DEBUG("Exchanging data port ...\n");

	if (ct->opts.dst_addr) {
		memset(&ct->ctrl_buf, '\0', PP_MSG_LEN_PORT + 1);

		PP_DEBUG("CLIENT: receiving port ...\n");
		ret = pp_ctrl_recv(ct, ct->ctrl_buf, PP_MSG_LEN_PORT);
		if (ret < 0)
			return ret;
		ct->data_default_port = (int) parse_ulong(ct->ctrl_buf, (1 << 16) - 1);
		if (ct->data_default_port < 0)
			return ret;
		PP_DEBUG("CLIENT: received port = <%d> (len=%lu)\n", ct->data_default_port, strlen(ct->ctrl_buf));

		snprintf(ct->ctrl_buf, sizeof(PP_MSG_CHECK_PORT_OK) , "%s", PP_MSG_CHECK_PORT_OK);
		ret = pp_ctrl_send(ct, ct->ctrl_buf, sizeof(PP_MSG_CHECK_PORT_OK));
		if (ret < 0)
			return ret;
		PP_DEBUG("CLIENT: acked port to server\n");
	} else {
		snprintf(ct->ctrl_buf, PP_MSG_LEN_PORT + 1, "%d", ct->data_default_port);

		PP_DEBUG("SERVER: sending port = <%s> (len=%lu) ...\n", ct->ctrl_buf, strlen(ct->ctrl_buf));
		ret = pp_ctrl_send(ct, ct->ctrl_buf, PP_MSG_LEN_PORT);
		if (ret < 0)
			return ret;
		PP_DEBUG("SERVER: sent port\n");

		memset(&ct->ctrl_buf, '\0', sizeof(PP_MSG_CHECK_PORT_OK));
		ret = pp_ctrl_recv(ct, ct->ctrl_buf, sizeof(PP_MSG_CHECK_PORT_OK));
		if (ret < 0)
			return ret;

		if (strcmp(ct->ctrl_buf, PP_MSG_CHECK_PORT_OK)) {
			PP_DEBUG("SERVER: error while client acking the port : <%s> (len=%lu)\n", ct->ctrl_buf, strlen(ct->ctrl_buf));
			return -EBADMSG;
		}
		PP_DEBUG("SERVER: port acked by client\n");
	}

	snprintf(ct->data_port, sizeof(ct->data_port), "%d", ct->data_default_port);

	PP_DEBUG("Data port exchanged\n");

	return 0;
}

int pp_ctrl_sync(struct ct_pingpong *ct)
{
	int ret;

	PP_DEBUG("Syncing nodes ...\n");

	if (ct->opts.dst_addr) {
		snprintf(ct->ctrl_buf, sizeof(PP_MSG_SYNC_Q), "%s", PP_MSG_SYNC_Q);

		PP_DEBUG("CLIENT: syncing ...\n");
		ret = pp_ctrl_send(ct, ct->ctrl_buf, sizeof(PP_MSG_SYNC_Q));
		if (ret < 0)
			return ret;
		if (ret < sizeof(PP_MSG_SYNC_Q)) {
			PP_ERR("CLIENT: bad length of sent data (len=%d/%zu)", ret, sizeof(PP_MSG_SYNC_Q));
			return -EBADMSG;
		}
		PP_DEBUG("CLIENT: syncing now\n");

		ret = pp_ctrl_recv(ct, ct->ctrl_buf, sizeof(PP_MSG_SYNC_A));
		if (ret < 0)
			return ret;
		if (strcmp(ct->ctrl_buf, PP_MSG_SYNC_A)) {
			ct->ctrl_buf[PP_CTRL_BUF_LEN] = '\0';
			PP_DEBUG("CLIENT: sync error while acking A : <%s> (len=%lu)\n", ct->ctrl_buf, strlen(ct->ctrl_buf));
			return -EBADMSG;
		}
		PP_DEBUG("CLIENT: synced\n");
	} else {
		PP_DEBUG("SERVER: syncing ...\n");
		ret = pp_ctrl_recv(ct, ct->ctrl_buf, sizeof(PP_MSG_SYNC_Q));
		if (ret < 0)
			return ret;
		if (strcmp(ct->ctrl_buf, PP_MSG_SYNC_Q)) {
			ct->ctrl_buf[PP_CTRL_BUF_LEN] = '\0';
			PP_DEBUG("SERVER: sync error while acking Q : <%s> (len=%lu)\n", ct->ctrl_buf, strlen(ct->ctrl_buf));
			return -EBADMSG;
		}

		PP_DEBUG("SERVER: syncing now\n");
		snprintf(ct->ctrl_buf, sizeof(PP_MSG_SYNC_A) , "%s", PP_MSG_SYNC_A);

		ret = pp_ctrl_send(ct, ct->ctrl_buf, sizeof(PP_MSG_SYNC_A));
		if (ret < 0)
			return ret;
		if (ret < sizeof(PP_MSG_SYNC_A)) {
			PP_ERR("SERVER: bad length of sent data (len=%d/%zu)", ret, sizeof(PP_MSG_SYNC_A));
			return -EBADMSG;
		}
		PP_DEBUG("SERVER: synced\n");
	}

	PP_DEBUG("Nodes synced\n");

	return 0;
}

int pp_ctrl_txrx_msg_count(struct ct_pingpong *ct)
{
	int ret;

	PP_DEBUG("Exchanging ack count\n");

	if (ct->opts.dst_addr) {
		memset(&ct->ctrl_buf, '\0', PP_MSG_LEN_CNT + 1);
		snprintf(ct->ctrl_buf, PP_MSG_LEN_CNT + 1, "%ld", ct->cnt_ack_msg);

		PP_DEBUG("CLIENT: sending count = <%s> (len=%lu)\n", ct->ctrl_buf, strlen(ct->ctrl_buf));
		ret = pp_ctrl_send(ct, ct->ctrl_buf, PP_MSG_LEN_CNT);
		if (ret < 0)
			return ret;
		if (ret < PP_MSG_LEN_CNT) {
			PP_ERR("CLIENT: bad length of sent data (len=%d/%d)", ret, PP_MSG_LEN_CNT);
			return -EBADMSG;
		}
		PP_DEBUG("CLIENT: sent count ...\n");

		ret = pp_ctrl_recv(ct, ct->ctrl_buf, sizeof(PP_MSG_CHECK_CNT_OK));
		if (ret < 0)
			return ret;
		if (ret < sizeof(PP_MSG_CHECK_CNT_OK)) {
			PP_ERR("CLIENT: bad length of received data (len=%d/%zu)", ret, sizeof(PP_MSG_CHECK_CNT_OK));
			return -EBADMSG;
		}

		if (strcmp(ct->ctrl_buf, PP_MSG_CHECK_CNT_OK)) {
			PP_DEBUG("CLIENT: error while server acking the count : <%s> (len=%lu)\n", ct->ctrl_buf, strlen(ct->ctrl_buf));
			return ret;
		}
		PP_DEBUG("CLIENT: count acked by server\n");
	} else {
		memset(&ct->ctrl_buf, '\0', PP_MSG_LEN_CNT + 1);

		PP_DEBUG("SERVER: receiving count ...\n");
		ret = pp_ctrl_recv(ct, ct->ctrl_buf, PP_MSG_LEN_CNT);
		if (ret < 0)
			return ret;
		if (ret < PP_MSG_LEN_CNT) {
			PP_ERR("SERVER: bad length of received data (len=%d/%d)", ret, PP_MSG_LEN_CNT);
			return -EBADMSG;
		}
		ct->cnt_ack_msg = parse_ulong(ct->ctrl_buf, -1);
		if (ct->cnt_ack_msg < 0)
			return ret;
		PP_DEBUG("SERVER: received count = <%ld> (len=%lu)\n", ct->cnt_ack_msg, strlen(ct->ctrl_buf));

		snprintf(ct->ctrl_buf, sizeof(PP_MSG_CHECK_CNT_OK), "%s", PP_MSG_CHECK_CNT_OK);
		ret = pp_ctrl_send(ct, ct->ctrl_buf, sizeof(PP_MSG_CHECK_CNT_OK));
		if (ret < 0)
			return ret;
		if (ret < sizeof(PP_MSG_CHECK_CNT_OK)) {
			PP_ERR("CLIENT: bad length of received data (len=%d/%zu)", ret, sizeof(PP_MSG_CHECK_CNT_OK));
			return -EBADMSG;
		}
		PP_DEBUG("SERVER: acked count to client\n");
	}

	PP_DEBUG("Ack count exchanged\n");

	return 0;
}

/*******************************************************************************************/
/*                                        Options                                          */
/*******************************************************************************************/

static inline void pp_start(struct ct_pingpong *ct)
{
	PP_DEBUG("Starting test chrono\n");
	ct->opts.options |= PP_OPT_ACTIVE;
	clock_gettime(CLOCK_MONOTONIC, &(ct->start));
}

static inline void pp_stop(struct ct_pingpong *ct)
{
	clock_gettime(CLOCK_MONOTONIC, &(ct->end));
	ct->opts.options &= ~PP_OPT_ACTIVE;
	PP_DEBUG("Stopped test chrono\n");
}

static int pp_check_opts(struct ct_pingpong *ct, uint64_t flags)
{
	return (ct->opts.options & flags) == flags;
}

/*******************************************************************************************/
/*                                     Data verification                                   */
/*******************************************************************************************/

void pp_fill_buf(void *buf, int size)
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

int pp_check_buf(void *buf, int size)
{
	char *recv_data;
	char c;
	static unsigned int iter = 0;
	int msg_index;
	int i;

	PP_DEBUG("Verifying buffer content\n");

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
		PP_DEBUG("Finished veryfing buffer : content is corrupted\n");
		printf("Error at iteration=%d size=%d byte=%d\n",
			iter, size, i);
		return 1;
	}

	PP_DEBUG("Buffer verified\n");

	return 0;
}

/*******************************************************************************************/
/*                                      Error handling                                     */
/*******************************************************************************************/


void eq_readerr(struct fid_eq *eq)
{
	struct fi_eq_err_entry eq_err;
	int rd;

	rd = fi_eq_readerr(eq, &eq_err, 0);
	if (rd != sizeof(eq_err)) {
		PP_PRINTERR("fi_eq_readerr", rd);
	} else {
		PP_ERR("eq_readerr: %s", fi_eq_strerror(eq, eq_err.prov_errno,
					eq_err.err_data, NULL, 0));

	}
}

void pp_process_eq_err(ssize_t rd, struct fid_eq *eq, const char *fn) {
	if (rd == -FI_EAVAIL) {
		eq_readerr(eq);
	} else {
		PP_PRINTERR(fn, rd);
	}
}

/*******************************************************************************************/
/*                                    Addresses handling                                   */
/*******************************************************************************************/

static int pp_getsrcaddr(char *node, char *service, struct fi_info *hints)
{
	struct fi_info *info;
	int ret = 0;

	ret = fi_getinfo(PP_FIVERSION, node, service, FI_SOURCE, NULL, &info);
	if (ret) {
		PP_PRINTERR("fi_getinfo", ret);
		return ret;
	}

	hints->src_addrlen = info->src_addrlen;
	hints->src_addr = calloc(1, hints->src_addrlen);
	if (!hints->src_addr) {
		ret = -errno;
		PP_PRINTERR("calloc", ret);
		goto err;
	}

	memcpy(hints->src_addr, info->src_addr, hints->src_addrlen);
	if (!hints->src_addr) {
		ret = -errno;
		PP_PRINTERR("memcpy", ret);
		goto err;
	}

err:
	fi_freeinfo(info);
	return ret;
}

int pp_read_addr_opts(struct ct_pingpong *ct, char **node, char **service, struct fi_info *hints,
		uint64_t *flags, struct pp_opts *opts)
{
	int ret;

	if (opts->dst_addr) {
		if (opts->src_addr) {
			ret = pp_getsrcaddr(opts->src_addr, opts->src_port, hints);
			if (ret) {
				PP_ERR("Trying to get the source address for the client");
				return ret;
			}
		}

		if (!opts->dst_port)
			opts->dst_port = ct->data_port;

		*node = opts->dst_addr;
		*service = opts->dst_port;
	} else {
		if (!opts->src_port)
			opts->src_port = ct->data_port;

		*node = opts->src_addr;
		*service = opts->src_port;
		*flags = FI_SOURCE;
	}

	return 0;
}


/*******************************************************************************************/
/*                                       Test sizes                                        */
/*******************************************************************************************/

int generate_test_sizes(struct pp_opts *opts, size_t provider_maximum, int **sizes_, int size_power_two_max)
{
	int defaults[6] = {64, 256, 1024, 4096, 655616, 1048576};
	int power_of_two;
	int half_up;
	int n = 0;
	int *sizes = NULL;

	PP_DEBUG("Generating test sizes\n");

	sizes = calloc(64, sizeof(*sizes));
	if (sizes == NULL)
		return 0;
	*sizes_ = sizes;

	if (opts->options & PP_OPT_SIZE) {
		if (opts->transfer_size > provider_maximum)
			return 0;

		sizes[0] = opts->transfer_size;
		n = 1;
	} else if (opts->sizes_enabled != PP_ENABLE_ALL) {
		for (int i = 0; i < (sizeof defaults / sizeof defaults[0]); i++) {
			if (defaults[i] > provider_maximum)
				break;

			sizes[i] = defaults[i];
			n++;
		}
	} else {
		for (int i = 0; i < size_power_two_max; i++) {
			power_of_two = (1 << (i + 1));
			half_up = power_of_two + (power_of_two / 2);

			if (power_of_two > provider_maximum)
				break;

			sizes[i * 2] = power_of_two;
			n++;

			if (half_up > provider_maximum)
				break;

			sizes[(i * 2) + 1] = half_up;
			n++;
		}
	}

	PP_DEBUG("Generated %d test sizes\n", n);

	return n;
}

/*******************************************************************************************/
/*                                    Performance output                                   */
/*******************************************************************************************/

char *size_str(char str[PP_STR_LEN], long long size)
{
	long long base, fraction = 0;
	char mag;

	memset(str, '\0', PP_STR_LEN);

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
		snprintf(str, PP_STR_LEN, "%lld.%lld%c", size / base, fraction, mag);
	else
		snprintf(str, PP_STR_LEN, "%lld%c", size / base, mag);

	return str;
}

char *cnt_str(char str[PP_STR_LEN], long long cnt)
{
	if (cnt >= 1000000000)
		snprintf(str, PP_STR_LEN, "%lldb", cnt / 1000000000);
	else if (cnt >= 1000000)
		snprintf(str, PP_STR_LEN, "%lldm", cnt / 1000000);
	else if (cnt >= 1000)
		snprintf(str, PP_STR_LEN, "%lldk", cnt / 1000);
	else
		snprintf(str, PP_STR_LEN, "%lld", cnt);

	return str;
}

int64_t get_elapsed(const struct timespec *b, const struct timespec *a,
		    enum precision p)
{
	int64_t elapsed;

	elapsed = difftime(a->tv_sec, b->tv_sec) * 1000 * 1000 * 1000;
	elapsed += a->tv_nsec - b->tv_nsec;
	return elapsed / p;
}

void show_perf(char *name, int tsize, int sent, int acked, struct timespec *start,
		struct timespec *end, int xfers_per_iter)
{
	static int header = 1;
	char str[PP_STR_LEN];
	int64_t elapsed = get_elapsed(start, end, MICRO);
	long long bytes = (long long) sent * tsize * xfers_per_iter;
	float usec_per_xfer;

	if (sent == 0)
		return;

	if (name) {
		if (header) {
			printf("%-50s%-8s%-8s%-9s%-8s%8s %10s%13s%13s\n",
					"name", "bytes", "#sent", "#ack",
					"total", "time", "MB/sec",
					"usec/xfer", "Mxfers/sec");
			header = 0;
		}

		printf("%-50s", name);
	} else {
		if (header) {
			printf("%-8s%-8s%-9s%-8s%8s %10s%13s%13s\n",
					"bytes", "#sent", "#ack", "total",
					"time", "MB/sec", "usec/xfer",
					"Mxfers/sec");
			header = 0;
		}
	}

	printf("%-8s", size_str(str, tsize));

	printf("%-8s", cnt_str(str, sent));

	if (sent == acked) {
		printf("=%-8s", cnt_str(str, acked));
	} else if (sent < acked) {
		printf("-%-8s", cnt_str(str, abs(acked - sent)));
	} else {
		printf("+%-8s", cnt_str(str, abs(acked - sent)));
	}

	printf("%-8s", size_str(str, bytes));

	usec_per_xfer = ((float)elapsed / sent / xfers_per_iter);
	printf("%8.2fs%10.2f%11.2f%11.2f\n",
		elapsed / 1000000.0, bytes / (1.0 * elapsed),
		usec_per_xfer, 1.0/usec_per_xfer);
}

/*******************************************************************************************/
/*                                      Data Messaging                                     */
/*******************************************************************************************/

int pp_cq_readerr(struct fid_cq *cq)
{
	struct fi_cq_err_entry cq_err;
	int ret;

	ret = fi_cq_readerr(cq, &cq_err, 0);
	if (ret < 0) {
		PP_PRINTERR("fi_cq_readerr", ret);
	} else {
		PP_ERR("cq_readerr: %s", fi_cq_strerror(cq, cq_err.prov_errno,
					cq_err.err_data, NULL, 0));
		ret = -cq_err.err;
	}
	return ret;
}

/*
 * fi_cq_err_entry can be cast to any CQ entry format.
 */
static int pp_spin_for_comp(struct fid_cq *cq, uint64_t *cur,
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

static int pp_get_cq_comp(struct fid_cq *cq, uint64_t *cur,
			  uint64_t total, int timeout)
{
	int ret = pp_spin_for_comp(cq, cur, total, timeout);

	if (ret) {
		if (ret == -FI_EAVAIL) {
			ret = pp_cq_readerr(cq);
			(*cur)++;
		} else {
			PP_PRINTERR("pp_get_cq_comp", ret);
		}
	}
	return ret;
}

int pp_get_rx_comp(struct ct_pingpong *ct, uint64_t total)
{
	int ret = FI_SUCCESS;

	if (ct->rxcq) {
		ret = pp_get_cq_comp(ct->rxcq, &(ct->rx_cq_cntr), total, ct->timeout);
	} else {
		PP_ERR("Trying to get a RX completion when no RX CQ was opened");
		ret = -FI_EOTHER;
	}
	return ret;
}

int pp_get_tx_comp(struct ct_pingpong *ct, uint64_t total)
{
	int ret;

	if (ct->txcq) {
		ret = pp_get_cq_comp(ct->txcq, &(ct->tx_cq_cntr), total, -1);
	} else {
		PP_ERR("Trying to get a TX completion when no TX CQ was opened");
		ret = -FI_EOTHER;
	}
	return ret;
}

#define PP_POST(post_fn, comp_fn, seq, op_str, ...)				\
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
				PP_PRINTERR(op_str, ret);			\
				return ret;					\
			}							\
										\
			timeout_save = ct->timeout;				\
			ct->timeout = 0;					\
			rc = comp_fn(ct, seq);					\
			if (rc && rc != -FI_EAGAIN) {				\
				PP_ERR("Failed to get " op_str " completion");	\
				return rc;					\
			}							\
			ct->timeout = timeout_save;				\
		}								\
		seq++;								\
	} while (0)

ssize_t pp_post_tx(struct ct_pingpong *ct, struct fid_ep *ep, size_t size, struct fi_context* ctx)
{
	PP_POST(fi_send, pp_get_tx_comp, ct->tx_seq, "transmit", ep,
			ct->tx_buf, size, fi_mr_desc(ct->mr),
			ct->remote_fi_addr, ctx);
	return 0;
}

ssize_t pp_tx(struct ct_pingpong *ct, struct fid_ep *ep, size_t size)
{
	ssize_t ret;

	if (pp_check_opts(ct, PP_OPT_VERIFY_DATA | PP_OPT_ACTIVE))
		pp_fill_buf((char *) ct->tx_buf, size);

	ret = pp_post_tx(ct, ep, size, &(ct->tx_ctx));
	if (ret)
		return ret;

	ret = pp_get_tx_comp(ct, ct->tx_seq);

	return ret;
}

ssize_t pp_post_inject(struct ct_pingpong *ct, struct fid_ep *ep, size_t size)
{
	PP_POST(fi_inject, pp_get_tx_comp, ct->tx_seq, "inject",
			ep, ct->tx_buf, size,
			ct->remote_fi_addr);
	ct->tx_cq_cntr++;
	return 0;
}

ssize_t pp_inject(struct ct_pingpong *ct, struct fid_ep *ep, size_t size)
{
	ssize_t ret;

	if (pp_check_opts(ct, PP_OPT_VERIFY_DATA | PP_OPT_ACTIVE))
		pp_fill_buf((char *) ct->tx_buf, size);

	ret = pp_post_inject(ct, ep, size);
	if (ret)
		return ret;

	return ret;
}

ssize_t pp_post_rx(struct ct_pingpong *ct, struct fid_ep *ep, size_t size, struct fi_context* ctx)
{
	PP_POST(fi_recv, pp_get_rx_comp, ct->rx_seq, "receive", ep, ct->rx_buf,
			MAX(size, PP_MAX_CTRL_MSG),
			fi_mr_desc(ct->mr), 0, ctx);
	return 0;
}

ssize_t pp_rx(struct ct_pingpong *ct, struct fid_ep *ep, size_t size)
{
	ssize_t ret;

	ret = pp_get_rx_comp(ct, ct->rx_seq);
	if (ret)
		return ret;

	if (pp_check_opts(ct, PP_OPT_VERIFY_DATA | PP_OPT_ACTIVE)) {
		ret = pp_check_buf((char *) ct->rx_buf, size);
		if (ret)
			return ret;
	}
	/* TODO: verify CQ data, if available */

	/* Ignore the size arg. Post a buffer large enough to handle all message
	 * sizes. pp_sync() makes use of pp_rx() and gets called in tests just before
	 * message size is updated. The recvs posted are always for the next incoming
	 * message */
	ret = pp_post_rx(ct, ct->ep, ct->rx_size, &(ct->rx_ctx));
	if (!ret)
		ct->cnt_ack_msg++;

	return ret;
}

/*******************************************************************************************/
/*                                Initialization and allocations                          */
/*******************************************************************************************/

void init_test(struct ct_pingpong *ct, struct pp_opts *opts, char *test_name, size_t test_name_len)
{
	char sstr[PP_STR_LEN];

	size_str(sstr, opts->transfer_size);
	if (!strcmp(test_name, "custom"))
		snprintf(test_name, test_name_len, "%s_lat", sstr);
	if (!(opts->options & PP_OPT_ITER))
		opts->iterations = size_to_count(opts->transfer_size);

	ct->cnt_ack_msg = 0;
}

uint64_t pp_init_cq_data(struct fi_info *info)
{
	if (info->domain_attr->cq_data_size >= sizeof(uint64_t)) {
		return 0x0123456789abcdefULL;
	} else {
		return 0x0123456789abcdef &
			((0x1ULL << (info->domain_attr->cq_data_size * 8)) - 1);
	}
}

/*
 * Include FI_MSG_PREFIX space in the allocated buffer, and ensure that the
 * buffer is large enough for a control message used to exchange addressing
 * data.
 */
int pp_alloc_msgs(struct ct_pingpong *ct)
{
	int ret;
	long alignment = 1;

	ct->tx_size = ct->opts.options & PP_OPT_SIZE ? ct->opts.transfer_size : PP_MAX_DATA_MSG;
	if (ct->tx_size > ct->fi->ep_attr->max_msg_size)
		ct->tx_size = ct->fi->ep_attr->max_msg_size;
	ct->rx_size = ct->tx_size;
	ct->buf_size = MAX(ct->tx_size, PP_MAX_CTRL_MSG) + MAX(ct->rx_size, PP_MAX_CTRL_MSG);

	alignment = sysconf(_SC_PAGESIZE);
	if (alignment < 0) {
		ret = -errno;
		PP_PRINTERR("sysconf", ret);
		return ret;
	}
	ct->buf_size += alignment;

	ret = posix_memalign(&(ct->buf), (size_t) alignment, ct->buf_size);
	if (ret) {
		PP_PRINTERR("posix_memalign", ret);
		return ret;
	}
	memset(ct->buf, 0, ct->buf_size);
	ct->rx_buf = ct->buf;
	ct->tx_buf = (char *) ct->buf + MAX(ct->rx_size, PP_MAX_CTRL_MSG);
	ct->tx_buf = (void *) (((uintptr_t) ct->tx_buf + alignment - 1) & ~(alignment - 1));

	ct->remote_cq_data = pp_init_cq_data(ct->fi);

	if (ct->fi->mode & FI_LOCAL_MR) {
		ret = fi_mr_reg(ct->domain, ct->buf, ct->buf_size, 0,
				0, PP_MR_KEY, 0, &(ct->mr), NULL);
		if (ret) {
			PP_PRINTERR("fi_mr_reg", ret);
			return ret;
		}
	} else {
		ct->mr = &(ct->no_mr);
	}

	return 0;
}

int pp_open_fabric_res(struct ct_pingpong *ct)
{
	int ret;

	PP_DEBUG("Opening fabric resources : fabric, eq & domain\n");

	ret = fi_fabric(ct->fi->fabric_attr, &(ct->fabric), NULL);
	if (ret) {
		PP_PRINTERR("fi_fabric", ret);
		return ret;
	}

	ret = fi_eq_open(ct->fabric, &(ct->eq_attr), &(ct->eq), NULL);
	if (ret) {
		PP_PRINTERR("fi_eq_open", ret);
		return ret;
	}

	ret = fi_domain(ct->fabric, ct->fi, &(ct->domain), NULL);
	if (ret) {
		PP_PRINTERR("fi_domain", ret);
		return ret;
	}

	PP_DEBUG("Fabric resources opened\n");

	return 0;
}

int pp_alloc_active_res(struct ct_pingpong *ct, struct fi_info *fi)
{
	int ret;

	ret = pp_alloc_msgs(ct);
	if (ret)
		return ret;

	if (ct->cq_attr.format == FI_CQ_FORMAT_UNSPEC) {
		ct->cq_attr.format = FI_CQ_FORMAT_CONTEXT;
	}

	ct->cq_attr.wait_obj = FI_WAIT_NONE;
	ct->cq_attr.size = fi->tx_attr->size;
	ret = fi_cq_open(ct->domain, &(ct->cq_attr), &(ct->txcq), &(ct->txcq));
	if (ret) {
		PP_PRINTERR("fi_cq_open", ret);
		return ret;
	}

	ct->cq_attr.wait_obj = FI_WAIT_NONE;
	ct->cq_attr.size = fi->rx_attr->size;
	ret = fi_cq_open(ct->domain, &(ct->cq_attr), &(ct->rxcq), &(ct->rxcq));
	if (ret) {
		PP_PRINTERR("fi_cq_open", ret);
		return ret;
	}

	if (fi->ep_attr->type == FI_EP_RDM || fi->ep_attr->type == FI_EP_DGRAM) {
		if (fi->domain_attr->av_type != FI_AV_UNSPEC)
			ct->av_attr.type = fi->domain_attr->av_type;

		ret = fi_av_open(ct->domain, &(ct->av_attr), &(ct->av), NULL);
		if (ret) {
			PP_PRINTERR("fi_av_open", ret);
			return ret;
		}
	}

	ret = fi_endpoint(ct->domain, fi, &(ct->ep), NULL);
	if (ret) {
		PP_PRINTERR("fi_endpoint", ret);
		return ret;
	}

	return 0;
}

int pp_getinfo(struct ct_pingpong *ct, struct fi_info *hints, struct fi_info **info)
{
	char *node, *service;
	uint64_t flags = 0;
	int ret;

	ret = pp_read_addr_opts(ct, &node, &service, hints, &flags, &(ct->opts));
	if (ret)
		return ret;

	if (!hints->ep_attr->type)
		hints->ep_attr->type = FI_EP_DGRAM;

	ret = fi_getinfo(PP_FIVERSION, node, service, flags, hints, info);
	if (ret) {
		PP_PRINTERR("fi_getinfo", ret);
		return ret;
	}
	return 0;
}

#define PP_EP_BIND(ep, fd, flags)					\
	do {								\
		int ret;						\
		if ((fd)) {						\
			ret = fi_ep_bind((ep), &(fd)->fid, (flags));	\
			if (ret) {					\
				PP_PRINTERR("fi_ep_bind", ret);		\
				return ret;				\
			}						\
		}							\
	} while (0)

int pp_init_ep(struct ct_pingpong *ct)
{
	int flags, ret;

	PP_DEBUG("Initializing endpoint\n");

	if (ct->fi->ep_attr->type == FI_EP_MSG)
		PP_EP_BIND(ct->ep, ct->eq, 0);
	PP_EP_BIND(ct->ep, ct->av, 0);
	PP_EP_BIND(ct->ep, ct->txcq, FI_TRANSMIT);
	PP_EP_BIND(ct->ep, ct->rxcq, FI_RECV);

	/* TODO: use control structure to select counter bindings explicitly */
	flags = !ct->txcq ? FI_SEND : 0;
	if (ct->hints->caps & (FI_WRITE | FI_READ))
		flags |= ct->hints->caps & (FI_WRITE | FI_READ);
	else if (ct->hints->caps & FI_RMA)
		flags |= FI_WRITE | FI_READ;
	flags = !ct->rxcq ? FI_RECV : 0;
	if (ct->hints->caps & (FI_REMOTE_WRITE | FI_REMOTE_READ))
		flags |= ct->hints->caps & (FI_REMOTE_WRITE | FI_REMOTE_READ);
	else if (ct->hints->caps & FI_RMA)
		flags |= FI_REMOTE_WRITE | FI_REMOTE_READ;

	ret = fi_enable(ct->ep);
	if (ret) {
		PP_PRINTERR("fi_enable", ret);
		return ret;
	}

	if (ct->fi->rx_attr->op_flags != FI_MULTI_RECV) {
		/* Initial receive will get remote address for unconnected EPs */
		ret = pp_post_rx(ct, ct->ep, MAX(ct->rx_size, PP_MAX_CTRL_MSG), &(ct->rx_ctx));
		if (ret)
			return ret;
	}

	PP_DEBUG("Endpoint initialzed\n");

	return 0;
}

int pp_av_insert(struct fid_av *av, void *addr, size_t count, fi_addr_t *fi_addr,
		uint64_t flags, void *context)
{
	int ret;

	PP_DEBUG("Connection-less endpoint: inserting new address in vector\n");

	ret = fi_av_insert(av, addr, count, fi_addr, flags, context);
	if (ret < 0) {
		PP_PRINTERR("fi_av_insert", ret);
		return ret;
	} else if (ret != count) {
		PP_ERR("fi_av_insert: number of addresses inserted = %d;"
			       " number of addresses given = %zd\n", ret, count);
		return -EXIT_FAILURE;
	}

	PP_DEBUG("Connection-less endpoint: new address inserted in vector\n");

	return 0;
}

int pp_init_av(struct ct_pingpong *ct)
{
	size_t addrlen;
	int ret;

	PP_DEBUG("Connection-less endpoint: initializing address vector\n");

	addrlen = PP_MAX_CTRL_MSG;

	if (ct->opts.dst_addr) {
		ret = pp_av_insert(ct->av, ct->fi->dest_addr, 1, &(ct->remote_fi_addr), 0, NULL);
		if (ret)
			return ret;

		ret = fi_getname(&(ct->ep->fid), (char *) ct->ctrl_buf,
				 &addrlen);
		if (ret) {
			PP_PRINTERR("fi_getname", ret);
			return ret;
		}

		PP_DEBUG("CLIENT: sending av ...\n");
		ret = pp_ctrl_send(ct, ct->ctrl_buf, addrlen);
		if (ret < 0)
			return ret;
		PP_DEBUG("CLIENT: sent av ...\n");

		PP_DEBUG("CLIENT: waiting for acked av ....\n");
		ret = pp_ctrl_recv(ct, ct->ctrl_buf, sizeof(PP_MSG_CHECK_PORT_OK));
		if (ret < 0)
			return ret;
		PP_DEBUG("CLIENT: av acked\n");
	} else {
		PP_DEBUG("SERVER: receiving av ...\n");
		ret = pp_ctrl_recv(ct, ct->ctrl_buf, addrlen);
		if (ret < 0)
			return ret;
		PP_DEBUG("SERVER: received av\n");

		ret = pp_av_insert(ct->av, (char *) ct->ctrl_buf, 1, &(ct->remote_fi_addr), 0, NULL);
		if (ret)
			return ret;

		PP_DEBUG("SERVER: acking av ....\n");
		ret = pp_ctrl_send(ct, ct->ctrl_buf, sizeof(PP_MSG_CHECK_PORT_OK));
		if (ret < 0)
			return ret;
		PP_DEBUG("SERVER: acked av\n");
	}

	PP_DEBUG("Connection-less endpoint: address vector initialized\n");

	return 0;
}

int pp_start_server(struct ct_pingpong *ct)
{
	int ret;

	PP_DEBUG("Connected endpoint: starting server\n");

	ret = pp_getinfo(ct, ct->hints, &(ct->fi_pep));
	if (ret)
		return ret;

	ret = fi_fabric(ct->fi_pep->fabric_attr, &(ct->fabric), NULL);
	if (ret) {
		PP_PRINTERR("fi_fabric", ret);
		return ret;
	}

	ret = fi_eq_open(ct->fabric, &(ct->eq_attr), &(ct->eq), NULL);
	if (ret) {
		PP_PRINTERR("fi_eq_open", ret);
		return ret;
	}

	ret = fi_passive_ep(ct->fabric, ct->fi_pep, &(ct->pep), NULL);
	if (ret) {
		PP_PRINTERR("fi_passive_ep", ret);
		return ret;
	}

	ret = fi_pep_bind(ct->pep, &(ct->eq->fid), 0);
	if (ret) {
		PP_PRINTERR("fi_pep_bind", ret);
		return ret;
	}

	ret = fi_listen(ct->pep);
	if (ret) {
		PP_PRINTERR("fi_listen", ret);
		return ret;
	}

	PP_DEBUG("Connected endpoint: server started\n");

	return 0;
}

int pp_server_connect(struct ct_pingpong *ct)
{
	struct fi_eq_cm_entry entry;
	uint32_t event;
	ssize_t rd;
	int ret;

	PP_DEBUG("Connected endpoint: connecting server\n");

	/* Check that the remote is still up */
	ret = pp_ctrl_sync(ct);
	if (ret)
		return ret;

	/* Listen */
	rd = fi_eq_sread(ct->eq, &event, &entry, sizeof entry, -1, 0);
	if (rd != sizeof entry) {
		pp_process_eq_err(rd, ct->eq, "fi_eq_sread");
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
		PP_PRINTERR("fi_domain", ret);
		goto err;
	}

	ret = pp_alloc_active_res(ct, ct->fi);
	if (ret)
		goto err;

	ret = pp_init_ep(ct);
	if (ret)
		goto err;

	ret = fi_accept(ct->ep, NULL, 0);
	if (ret) {
		PP_PRINTERR("fi_accept", ret);
		goto err;
	}

	/* Accept */
	rd = fi_eq_sread(ct->eq, &event, &entry, sizeof entry, -1, 0);
	if (rd != sizeof entry) {
		pp_process_eq_err(rd, ct->eq, "fi_eq_sread");
		ret = (int) rd;
		goto err;
	}

	if (event != FI_CONNECTED || entry.fid != &(ct->ep->fid)) {
		fprintf(stderr, "Unexpected CM event %d fid %p (ep %p)\n",
			event, entry.fid, ct->ep);
		ret = -FI_EOTHER;
		goto err;
	}

	PP_DEBUG("Connected endpoint: server connected\n");

	return 0;

err:
	fi_reject(ct->pep, ct->fi->handle, NULL, 0);
	return ret;
}

int pp_client_connect(struct ct_pingpong *ct)
{
	struct fi_eq_cm_entry entry;
	uint32_t event;
	ssize_t rd;
	int ret;

	ret = pp_getinfo(ct, ct->hints, &(ct->fi));
	if (ret)
		return ret;

	/* Check that the remote is still up */
	ret = pp_ctrl_sync(ct);
	if (ret)
		return ret;

	ret = pp_open_fabric_res(ct);
	if (ret)
		return ret;

	ret = pp_alloc_active_res(ct, ct->fi);
	if (ret)
		return ret;

	ret = pp_init_ep(ct);
	if (ret)
		return ret;

	ret = fi_connect(ct->ep, ct->fi->dest_addr, NULL, 0);
	if (ret) {
		PP_PRINTERR("fi_connect", ret);
		return ret;
	}

	/* Connect */
	rd = fi_eq_sread(ct->eq, &event, &entry, sizeof entry, -1, 0);
	if (rd != sizeof entry) {
		pp_process_eq_err(rd, ct->eq, "fi_eq_sread");
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

int pp_init_fabric(struct ct_pingpong *ct)
{
	int ret;

	PP_DEBUG("Initializing fabric ...\n");

	ret = pp_ctrl_init(ct);
	if (ret)
		return ret;

	ret = pp_ctrl_txrx_data_port(ct);
	if (ret)
		return ret;

	ret = pp_getinfo(ct, ct->hints, &(ct->fi));
	if (ret)
		return ret;

	/* Check that the remote is still up */
	ret = pp_ctrl_sync(ct);
	if (ret)
		return ret;

	ret = pp_open_fabric_res(ct);
	if (ret)
		return ret;

	ret = pp_alloc_active_res(ct, ct->fi);
	if (ret)
		return ret;

	ret = pp_init_ep(ct);
	if (ret)
		return ret;

	ret = pp_init_av(ct);
	if (ret)
		return ret;

	PP_DEBUG("Fabric Initialized\n");

	return 0;
}

void pp_init_ct_pingpong(struct ct_pingpong *ct)
{
	ct->fi_pep = NULL;
	ct->fi = NULL;
	ct->hints = NULL;
	ct->fabric = NULL;
	ct->domain = NULL;
	ct->pep = NULL;
	ct->ep = NULL;
	ct->txcq = NULL;
	ct->rxcq = NULL;
	ct->mr = NULL;
	ct->av = NULL;
	ct->eq = NULL;

	ct->ctx_arr = NULL;
	ct->remote_cq_data = 0;

	ct->tx_seq = 0;
	ct->rx_seq = 0;
	ct->tx_cq_cntr = 0;
	ct->rx_cq_cntr = 0;

	ct->pp_parent_proc = 0;
	ct->pp_child_pid = 0;

	ct->remote_fi_addr = FI_ADDR_UNSPEC;
	ct->buf = NULL;
	ct->tx_buf = NULL;
	ct->rx_buf = NULL;

	ct->buf_size = 0;
	ct->tx_size = 0;
	ct->rx_size = 0;
	ct->rx_fd = -1;
	ct->tx_fd = -1;

	strncpy(ct->test_name, "custom", 50);
	ct->timeout = -1;

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

	ct->ctrl_listenfd = -1;
	ct->ctrl_connfd = -1;
	ct->data_default_port = 9228;
	ct->ctrl_port = 47592;

	memset(ct->ctrl_buf, '\0', sizeof(ct->ctrl_buf));
}

/*******************************************************************************************/
/*                                Deallocations and Final                                  */
/*******************************************************************************************/

void pp_free_res(struct ct_pingpong *ct)
{
	PP_DEBUG("Freeing ressources of test suite ...\n");

	if (ct->mr != &(ct->no_mr))
		PP_CLOSE_FID(ct->mr);
	PP_CLOSE_FID(ct->ep);
	PP_CLOSE_FID(ct->pep);
	PP_CLOSE_FID(ct->rxcq);
	PP_CLOSE_FID(ct->txcq);
	PP_CLOSE_FID(ct->av);
	PP_CLOSE_FID(ct->eq);
	PP_CLOSE_FID(ct->domain);
	PP_CLOSE_FID(ct->fabric);

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

	PP_DEBUG("Resources of test suite freed\n");
}

int pp_finalize(struct ct_pingpong *ct)
{
	struct iovec iov;
	int ret;
	struct fi_context ctx;
	struct fi_msg msg;

	PP_DEBUG("Terminating test ...\n");

	strcpy(ct->tx_buf, "fin");
	iov.iov_base = ct->tx_buf;
	iov.iov_len = 4;

	memset(&msg, 0, sizeof msg);
	msg.msg_iov = &iov;
	msg.iov_count = 1;
	msg.addr = ct->remote_fi_addr;
	msg.context = &ctx;

	ret = fi_sendmsg(ct->ep, &msg, FI_INJECT | FI_TRANSMIT_COMPLETE); // control message ?
	if (ret) {
		PP_PRINTERR("transmit", ret);
		return ret;
	}

	ret = pp_get_tx_comp(ct, ++ct->tx_seq); // control message ?
	if (ret)
		return ret;

	ret = pp_get_rx_comp(ct, ct->rx_seq); // control message ?
	if (ret)
		return ret;

	ret = pp_ctrl_finish(ct);
	if (ret)
		return ret;

	PP_DEBUG("Test terminated\n");

	return 0;
}

/*******************************************************************************************/
/*                                CLI: Usage and Options parsing                           */
/*******************************************************************************************/

void pp_pingpong_usage(char *name, char *desc)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  %s [OPTIONS]\t\tstart server\n", name);
	fprintf(stderr, "  %s [OPTIONS] <srv_addr>\tconnect to server\n", name);

	if (desc)
		fprintf(stderr, "\n%s\n", desc);

	fprintf(stderr, "\nOptions:\n");

	fprintf(stderr, " %-20s %s\n", "-b <src_port>", "non default source port number");
	fprintf(stderr, " %-20s %s\n", "-p <dst_port>", "non default destination port number");
	fprintf(stderr, " %-20s %s\n", "-s <address>", "server address");

	fprintf(stderr, " %-20s %s\n", "-n <domain>", "domain name");
	fprintf(stderr, " %-20s %s\n", "-f <provider>", "specific provider name eg sockets, verbs");
	fprintf(stderr, " %-20s %s\n", "-e <ep_type>", "Endpoint type: msg|rdm|dgram (default:dgram)");

	fprintf(stderr, " %-20s %s\n", "-I <number>", "number of iterations");
	fprintf(stderr, " %-20s %s\n", "-S <size>", "specific transfer size or 'all'");

	fprintf(stderr, " %-20s %s\n", "-v", "enables data_integrity checks");

	fprintf(stderr, " %-20s %s\n", "-h", "display this help output");
	fprintf(stderr, " %-20s %s\n", "-d", "enable debugging output");
}

void pp_parse_opts(struct ct_pingpong *ct, int op, char *optarg)
{
	switch (op) {
	
	/* Domain */
	case 'n':
		if (!ct->hints->domain_attr) {
			ct->hints->domain_attr = malloc(sizeof *(ct->hints->domain_attr));
			if (!ct->hints->domain_attr) {
				perror("malloc");
				exit(EXIT_FAILURE);
			}
		}
		ct->hints->domain_attr->name = strdup(optarg);
		break;
	
	/* Fabric */
	case 'f':
		if (!ct->hints->fabric_attr) {
			ct->hints->fabric_attr = malloc(sizeof *(ct->hints->fabric_attr));
			if (!ct->hints->fabric_attr) {
				perror("malloc");
				exit(EXIT_FAILURE);
			}
		}
		ct->hints->fabric_attr->prov_name = strdup(optarg);
		/* The provider name will be checked during the fabric initialization. */
		break;
	
	/* Endpoint */
	case 'e':
		if (!strncasecmp("msg", optarg, 3))
			ct->hints->ep_attr->type = FI_EP_MSG;
		else if (!strncasecmp("rdm", optarg, 3))
			ct->hints->ep_attr->type = FI_EP_RDM;
		else if (!strncasecmp("dgram", optarg, 5))
			ct->hints->ep_attr->type = FI_EP_DGRAM;
		else {
			fprintf(stderr, "Unknown endpoint : %s\n", optarg);
			exit(EXIT_FAILURE);
		}
		break;
	
	/* Iterations */
	case 'I':
		ct->opts.options |= PP_OPT_ITER;
		ct->opts.iterations = (int) parse_ulong(optarg, INT_MAX);
		if (ct->opts.iterations < 0)
			ct->opts.iterations = 0;
		break;
	
	/* Message Size */
	case 'S':
		if (!strncasecmp("all", optarg, 3)) {
			ct->opts.sizes_enabled = PP_ENABLE_ALL;
		} else {
			ct->opts.options |= PP_OPT_SIZE;
			ct->opts.transfer_size = (int) parse_ulong(optarg, INT_MAX);
		}
		break;
	
	/* Verbose */
	case 'v':
		ct->opts.options |= PP_OPT_VERIFY_DATA;
		break;
	
	/* Address */
	case 's':
		ct->opts.src_addr = optarg;
		break;
	case 'b':
		ct->opts.src_port = optarg;
		break;
	case 'p':
		ct->opts.dst_port = optarg;
		break;
	default:
		/* let getopt handle unknown opts*/
		break;

	}
}

/*******************************************************************************************/
/*                        PingPong core and implemenations for endpoints                   */
/*******************************************************************************************/

int pingpong(struct ct_pingpong *ct)
{
	int ret, i;

	PP_DEBUG("PingPong test starting ...\n");

	ret = pp_ctrl_sync(ct);
	if (ret)
		return ret;

	pp_start(ct);
	if (ct->opts.dst_addr) {
		for (i = 0; i < ct->opts.iterations; i++) {

			if (ct->opts.transfer_size < ct->fi->tx_attr->inject_size)
				ret = pp_inject(ct, ct->ep, ct->opts.transfer_size);
			else
				ret = pp_tx(ct, ct->ep, ct->opts.transfer_size);
			if (ret)
				return ret;

			ret = pp_rx(ct, ct->ep, ct->opts.transfer_size);
			if (ret)
				return ret;
		}
	} else {
		for (i = 0; i < ct->opts.iterations; i++) {

			ret = pp_rx(ct, ct->ep, ct->opts.transfer_size);
			if (ret)
				return ret;

			if (ct->opts.transfer_size < ct->fi->tx_attr->inject_size)
				ret = pp_inject(ct, ct->ep, ct->opts.transfer_size);
			else
				ret = pp_tx(ct, ct->ep, ct->opts.transfer_size);
			if (ret)
				return ret;
		}
	}
	pp_stop(ct);

	ret = pp_ctrl_txrx_msg_count(ct);
	if (ret)
		return ret;

	PP_DEBUG("Results :\n");
	show_perf(NULL, ct->opts.transfer_size, ct->opts.iterations, ct->cnt_ack_msg, &(ct->start), &(ct->end), 2);

	PP_DEBUG("PingPong test successfuly handled\n");
	return 0;
}

static int run_pingpong_dgram(struct ct_pingpong *ct)
{
	int i, ret, sizes_cnt;
	int *sizes = NULL;

	PP_DEBUG("Selected endpoint : DGRAM\n");

	ret = pp_init_fabric(ct);
	if (ret)
		return ret;

	/* Post an extra receive to avoid lacking a posted receive in the finalize. */
	ret = fi_recv(ct->ep, ct->rx_buf, ct->rx_size, fi_mr_desc(ct->mr), 0, &ct->rx_ctx);

	pp_banner_fabric_info(ct);

	sizes_cnt = generate_test_sizes(&ct->opts, ct->fi->ep_attr->max_msg_size, &sizes, PP_SIZE_MAX_POWER_TWO);

	PP_DEBUG("Count of sizes to test : %d\n", sizes_cnt);

	for (i = 0; i < sizes_cnt; i++) {
		ct->opts.transfer_size = sizes[i];
		if (ct->opts.transfer_size > ct->fi->ep_attr->max_msg_size) {
			PP_DEBUG("Transfer size too high for endpoint : %d\n", ct->opts.transfer_size);
			continue;
		}
		init_test(ct, &(ct->opts), ct->test_name, sizeof(ct->test_name));
		ret = pingpong(ct);
		if (ret)
			return ret;
	}

	free(sizes);

	return pp_finalize(ct);
}

static int run_pingpong_rdm(struct ct_pingpong *ct)
{
	int i, ret, sizes_cnt;
	int *sizes = NULL;

	PP_DEBUG("Selected endpoint : RDM\n");

	ret = pp_init_fabric(ct);
	if (ret)
		return ret;

	pp_banner_fabric_info(ct);

	sizes_cnt = generate_test_sizes(&ct->opts, ct->fi->ep_attr->max_msg_size, &sizes, PP_SIZE_MAX_POWER_TWO);

	PP_DEBUG("Count of sizes to test : %d\n", sizes_cnt);

	for (i = 0; i < sizes_cnt; i++) {
		ct->opts.transfer_size = sizes[i];
		if (ct->opts.transfer_size > ct->fi->ep_attr->max_msg_size) {
			PP_DEBUG("Transfer size too high for endpoint : %d\n", ct->opts.transfer_size);
			continue;
		}
		init_test(ct, &(ct->opts), ct->test_name, sizeof(ct->test_name));
		ret = pingpong(ct);
		if (ret)
			return ret;
	}

	free(sizes);

	return pp_finalize(ct);
}

static int run_pingpong_msg(struct ct_pingpong *ct)
{
	int i, ret, sizes_cnt;
	int *sizes = NULL;

	PP_DEBUG("Selected endpoint : DGRAM\n");

	ret = pp_ctrl_init(ct);
	if (ret) {
		return ret;
	}

	ret = pp_ctrl_txrx_data_port(ct);
	if (ret) {
		return ret;
	}

	if (!ct->opts.dst_addr) {
		ret = pp_start_server(ct);
		if (ret)
			return ret;
	}

	ret = ct->opts.dst_addr ? pp_client_connect(ct) : pp_server_connect(ct);
	if (ret) {
		return ret;
	}

	pp_banner_fabric_info(ct);

	sizes_cnt = generate_test_sizes(&ct->opts, ct->fi->ep_attr->max_msg_size, &sizes, PP_SIZE_MAX_POWER_TWO);

	PP_DEBUG("Count of sizes to test : %d\n", sizes_cnt);

	for (i = 0; i < sizes_cnt; i++) {
		ct->opts.transfer_size = sizes[i];
		if (ct->opts.transfer_size > ct->fi->ep_attr->max_msg_size) {
			PP_DEBUG("Transfer size too high for endpoint : %d\n", ct->opts.transfer_size);
			continue;
		}
		init_test(ct, &(ct->opts), ct->test_name, sizeof(ct->test_name));
		ret = pingpong(ct);
		if (ret)
			goto out;
	}

	free(sizes);

	ret = pp_finalize(ct);
out:
	fi_shutdown(ct->ep, 0);
	return ret;
}

int main(int argc, char **argv)
{
	int ret, op;

	ret = EXIT_SUCCESS;

	struct ct_pingpong ct;

	pp_init_ct_pingpong(&ct);
	ct.opts = (struct pp_opts) {
		.options = 0,
		.iterations = 1000,
		.transfer_size = 1024,
		.sizes_enabled = PP_DEFAULT_SIZE,
		.argc = argc, .argv = argv
	};

	ct.hints = fi_allocinfo();
	if (!ct.hints)
		return EXIT_FAILURE;

	while ((op = getopt(argc, argv, "hd" "b:p:s:n:f:e:I:S:v")) != -1) {
		switch (op) {
		default:
			pp_parse_opts(&ct, op, optarg);
			break;
		case 'd':
			PP_ACTIVATE_DEBUG = 1;
			break;
		case '?':
		case 'h':
			pp_pingpong_usage(argv[0], "Ping pong client and server.");
			return EXIT_FAILURE;
		}
	}

	if (optind < argc)
		ct.opts.dst_addr = argv[optind];

	if (!ct.hints->ep_attr->type || ct.hints->ep_attr->type == FI_EP_UNSPEC) {
		ct.hints->ep_attr->type = FI_EP_DGRAM;
	}

	pp_banner_options(&ct);

	switch(ct.hints->ep_attr->type) {
	case FI_EP_DGRAM:
		if (ct.opts.options & PP_OPT_SIZE)
			ct.hints->ep_attr->max_msg_size = ct.opts.transfer_size;
		ct.hints->caps = FI_MSG;
		ct.hints->mode = FI_LOCAL_MR;
		ret = run_pingpong_dgram(&ct);
		break;
	case FI_EP_RDM:
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

	pp_free_res(&ct);
	return -ret;
}
