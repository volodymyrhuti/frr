// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Frontend Server
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 */

#include <zebra.h>
#include "network.h"
#include "libfrr.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_fe_server.h"
#include "mgmtd/mgmt_fe_adapter.h"

#define MGMTD_FE_SRVR_DBG(fmt, ...)                                            \
	DEBUGD(&mgmt_debug_fe, "%s:" fmt, __func__, ##__VA_ARGS__)
#define MGMTD_FE_SRVR_ERR(fmt, ...)                                        \
	zlog_err("%s: ERROR: " fmt, __func__, ##__VA_ARGS__)

static int mgmt_fe_listen_fd = -1;
static struct event_loop *mgmt_fe_listen_tm;
static struct event *mgmt_fe_listen_ev;
static void mgmt_fe_server_register_event(enum mgmt_fe_event event);

static void mgmt_fe_conn_accept(struct event *thread)
{
	int client_conn_fd;
	union sockunion su;

	if (mgmt_fe_listen_fd < 0)
		return;

	/* We continue hearing server listen socket. */
	mgmt_fe_server_register_event(MGMTD_FE_SERVER);

	memset(&su, 0, sizeof(union sockunion));

	/* We can handle IPv4 or IPv6 socket. */
	client_conn_fd = sockunion_accept(mgmt_fe_listen_fd, &su);
	if (client_conn_fd < 0) {
		MGMTD_FE_SRVR_ERR(
			"Failed to accept MGMTD Frontend client connection : %s",
			safe_strerror(errno));
		return;
	}
	set_nonblocking(client_conn_fd);
	set_cloexec(client_conn_fd);

	MGMTD_FE_SRVR_DBG("Got a new MGMTD Frontend connection");

	mgmt_fe_create_adapter(client_conn_fd, &su);
}

static void mgmt_fe_server_register_event(enum mgmt_fe_event event)
{
	if (event == MGMTD_FE_SERVER) {
		event_add_read(mgmt_fe_listen_tm, mgmt_fe_conn_accept,
				NULL, mgmt_fe_listen_fd,
				&mgmt_fe_listen_ev);
		assert(mgmt_fe_listen_ev);
	} else {
		assert(!"mgmt_fe_server_post_event() called incorrectly");
	}
}

static void mgmt_fe_server_start(const char *hostname)
{
	int ret;
	int sock;
	struct sockaddr_un addr;
	mode_t old_mask;

	/* Set umask */
	old_mask = umask(0077);

	sock = socket(AF_UNIX, SOCK_STREAM, PF_UNSPEC);
	if (sock < 0) {
		MGMTD_FE_SRVR_ERR("Failed to create server socket: %s",
				      safe_strerror(errno));
		goto mgmt_fe_server_start_failed;
	}

	addr.sun_family = AF_UNIX,
	strlcpy(addr.sun_path, MGMTD_FE_SERVER_PATH, sizeof(addr.sun_path));
	unlink(addr.sun_path);
	ret = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		MGMTD_FE_SRVR_ERR(
			"Failed to bind server socket to '%s'. Err: %s",
			addr.sun_path, safe_strerror(errno));
		goto mgmt_fe_server_start_failed;
	}

	ret = listen(sock, MGMTD_FE_MAX_CONN);
	if (ret < 0) {
		MGMTD_FE_SRVR_ERR("Failed to listen on server socket: %s",
				      safe_strerror(errno));
		goto mgmt_fe_server_start_failed;
	}

	/* Restore umask */
	umask(old_mask);

	mgmt_fe_listen_fd = sock;
	mgmt_fe_server_register_event(MGMTD_FE_SERVER);

	MGMTD_FE_SRVR_DBG("Started MGMTD Frontend Server!");
	return;

mgmt_fe_server_start_failed:
	if (sock > 0)
		close(sock);

	mgmt_fe_listen_fd = -1;
	exit(-1);
}

int mgmt_fe_server_init(struct event_loop *master)
{
	if (mgmt_fe_listen_tm) {
		MGMTD_FE_SRVR_DBG("MGMTD Frontend Server already running!");
		return 0;
	}

	mgmt_fe_listen_tm = master;

	mgmt_fe_server_start("localhost");

	return 0;
}

void mgmt_fe_server_destroy(void)
{
	if (mgmt_fe_listen_tm) {
		MGMTD_FE_SRVR_DBG("Closing MGMTD Frontend Server!");

		if (mgmt_fe_listen_ev) {
			EVENT_OFF(mgmt_fe_listen_ev);
			mgmt_fe_listen_ev = NULL;
		}

		if (mgmt_fe_listen_fd >= 0) {
			close(mgmt_fe_listen_fd);
			mgmt_fe_listen_fd = -1;
		}

		mgmt_fe_listen_tm = NULL;
	}
}
