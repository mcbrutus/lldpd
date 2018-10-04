/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2018  <bcurtis@purestorage.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "lldpd.h"

#ifdef ENABLE_DCBX

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/dcbnl.h>

#include <sys/fsuid.h>

#define MAX_PAYLOAD 1024

/* Global socket and nlmsg seq value */
static int ifdcbx_nls = -1;
static int ifdcbx_seq = 0;

static int
ifdcbx_socket()
{
	struct sockaddr_nl nla = {
		.nl_family = AF_NETLINK,
		.nl_groups = RTMGRP_LINK | (1 << (RTNLGRP_DCB - 1)),
		.nl_pid = 0,
	};
	/* Global socket created ?*/
	if (ifdcbx_nls < 0) {
		setfsuid(0);
		/* Need a priviledged (root) socket for any netlink SET cmd writes */
		ifdcbx_nls = priv_netlink_socket();
		if (ifdcbx_nls < 0) {
			log_warnx("lldp",
			    "ifdcbx: unable to create a netlink socket");
			return 0;
		}
		if (bind(ifdcbx_nls, (struct sockaddr *)&nla, sizeof(nla))) {
			close(ifdcbx_nls);
			ifdcbx_nls = -1;
			log_warnx("lldp",
			    "ifdcbx: unable to bind a netlink socket");
			return 0;
		}
	}

	return 1;
}

struct nlmsg {
	struct nlmsghdr nlhdr;
	struct dcbmsg dcbmsg;
	char buf[MAX_PAYLOAD];
};

#define NLMSG_TAIL(nl) ((struct rtattr *)(((char *)(nl)) + NLMSG_ALIGN((nl)->nlmsg_len)))
#define RTA_TAIL(rta) ((struct rtattr *)(((char *)(rta)) + RTA_ALIGN((rta)->rta_len)))

static void
nlmsg_start(struct nlmsg *msg, u_int16_t typ, u_int8_t cmd)
{
	msg->nlhdr.nlmsg_len = NLMSG_ALIGN(sizeof(msg->nlhdr) + sizeof(msg->dcbmsg));
	msg->nlhdr.nlmsg_type = typ;
	msg->nlhdr.nlmsg_flags = NLM_F_REQUEST;
	msg->nlhdr.nlmsg_seq = ++ifdcbx_seq;
	msg->nlhdr.nlmsg_pid = getpid();

	msg->dcbmsg.cmd = cmd;
	msg->dcbmsg.dcb_family = AF_UNSPEC;
}

static void
nlmsg_attr_add(struct nlmsg *msg, u_int16_t typ, void *attr, int len)
{
	struct nlmsghdr *hdr = &msg->nlhdr;
	int al = RTA_LENGTH(len);
	struct rtattr *ap = NLMSG_TAIL(hdr);

	ap->rta_type = typ;
	ap->rta_len = al;
	if (attr && len)
		memcpy(RTA_DATA(ap), attr, len);

	hdr->nlmsg_len += NLMSG_ALIGN(al);
}

static void
rta_attr_add(struct rtattr *msg, u_int16_t typ, void *attr, int len)
{
	int al = RTA_LENGTH(len);
	struct rtattr *ap = RTA_TAIL(msg);

	ap->rta_type = typ;
	ap->rta_len = al;
	if (attr && len)
		memcpy(RTA_DATA(ap), attr, len);

	msg->rta_len += RTA_ALIGN(al);
}

static struct rtattr *
nlmsg_attr_nest_start(struct nlmsg *msg, u_int16_t typ)
{
	struct rtattr *nest = NLMSG_TAIL(&msg->nlhdr);

	nlmsg_attr_add(msg, typ, NULL, 0);
	return nest;
}

static struct rtattr *
rta_attr_nest_start(struct rtattr *msg, u_int16_t typ)
{
	struct rtattr *nest = RTA_TAIL(msg);

	rta_attr_add(msg, typ, NULL, 0);
	return nest;
}

static void
nlmsg_attr_nest_end(struct nlmsg *msg, struct rtattr *nest)
{
	msg->nlhdr.nlmsg_len += NLMSG_ALIGN(RTA_PAYLOAD(nest));
}

static void
rta_attr_nest_end(struct rtattr *msg, struct rtattr *nest)
{
	msg->rta_len += RTA_ALIGN(RTA_PAYLOAD(nest));
}

static int
ifdcbx_get(struct lldpd_hardware *hardware)
{
	int rc;
	struct rtattr *ap;
	int al;
	char *ifname = hardware->h_ifname;
	int iflen = strlen(ifname);
	struct lldpd_port *lport = &hardware->h_lport;
	struct nlmsg *msg = (struct nlmsg *)lport->p_dcbx_hwoffload.buf;
	struct rtattr **attr = (struct rtattr **)lport->p_dcbx_hwoffload.buf_attr;

	if (!lport->p_dcbx_hwoffload.supported)
		return -EOPNOTSUPP;

	/* reuse prev alloc'd msg buf */
	if (msg) {
		memset(msg, 0, sizeof(*msg));
	} else {
		msg = (struct nlmsg *)calloc(1, sizeof(*msg));
		if (!msg) {
			log_warnx("lldp",
			    "ifdcbx: unable to allocate memory for netlink buffer");
			return 0;
		}
		lport->p_dcbx_hwoffload.buf = (char *)msg;
	}

	/* reuse prev alloc'd attr buf */
	if (attr) {
		memset(attr, 0, lport->p_dcbx_hwoffload.buf_attr_len);
	} else {
		attr = (struct rtattr **)calloc(DCB_ATTR_MAX, sizeof(*attr));
		if (!attr) {
			log_warnx("lldp",
			    "ifdcbx: unable to allocate memory for netlink buffer attr index");
			return 0;
		}
		lport->p_dcbx_hwoffload.buf_attr = (char *)attr;
		lport->p_dcbx_hwoffload.buf_attr_len = DCB_ATTR_MAX * sizeof(*attr);
	}

	/* Send a DCB_CMD_IEEE_GET nlmsg for the named if */
	nlmsg_start(msg, RTM_GETDCB, DCB_CMD_IEEE_GET);
	nlmsg_attr_add(msg, DCB_ATTR_IFNAME, ifname, iflen + 1);

	if (write(ifdcbx_nls, msg, msg->nlhdr.nlmsg_len) != msg->nlhdr.nlmsg_len) {
		log_warnx("lldp",
		    "ifdcbx: RTM_GETDCB write failed on netlink socket");
		return 0;
	}

	/* Read (may not be sycnhronous?) nlmsg response */
	rc = read(ifdcbx_nls, msg, sizeof(*msg));
	if (rc == 0) {
		log_warnx("lldp",
		    "ifdcbx: RTM_GETDCB read empty on netlink socket");
		return 0;
	}
	if (rc < 0) {
		log_warnx("lldp",
		    "ifdcbx: RTM_GETDCB read faild on netlink socket");
		return 0;
	}
	lport->p_dcbx_hwoffload.buf_len = rc;

	if ((msg->nlhdr.nlmsg_seq != ifdcbx_seq)) {
		log_warnx("lldp",
		    "ifdcbx: %s RTM_GETDCB unexpected sequence %d != %d",
		    ifname, msg->nlhdr.nlmsg_seq, ifdcbx_seq);
		return 0;
	}
	if (msg->nlhdr.nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = NLMSG_DATA(&msg->nlhdr);

		if (err->error == -EOPNOTSUPP) {
			lport->p_dcbx_hwoffload.supported = 0;
			return -EOPNOTSUPP;
		}
		log_warnx("lldp",
		    "ifdcbx: %s netlink message error %d",
		    ifname, -(err->error));
		return -EOPNOTSUPP;
	}
	if ((msg->nlhdr.nlmsg_type != RTM_GETDCB) ||
	    (msg->dcbmsg.cmd != DCB_CMD_IEEE_GET)) {
		log_warnx("lldp",
		    "ifdcbx: %s RTM_GETDCB unexpected netlink message returned (%d != %d || %d != %d)",
		    ifname,
		    msg->nlhdr.nlmsg_type, RTM_GETDCB,
		    msg->dcbmsg.cmd, DCB_CMD_IEEE_GET);
		return 0;
	}

	/* Parse all the attrs and save pointers into */
	ap = (struct rtattr *)&msg->buf;
	al = rc - sizeof(msg->nlhdr) - sizeof(msg->dcbmsg);
	for (; RTA_OK(ap, al); ap = RTA_NEXT(ap, al)) {
		switch (ap->rta_type) {
		case DCB_ATTR_IFNAME:
			if (strncmp(ifname, RTA_DATA(ap), iflen)) {
				log_warnx("lldp",
				    "ifdcbx: %s netlink message for iface %s ???",
				    ifname, (char *)RTA_DATA(ap));
				return 0;
			}
			break;
		case DCB_ATTR_IEEE: {
			struct rtattr *nap = RTA_DATA(ap);
			int nal = RTA_PAYLOAD(ap);

			for (; RTA_OK(nap, nal); nap = RTA_NEXT(nap, nal)) {
				if (nap->rta_type > DCB_ATTR_MAX)
					continue;
				attr[nap->rta_type] = nap;
			}
			break;
		}
		default:
			/* ignore others */
			break;
		}
	}

	return 1;
}

static int
ifdcbx_set(struct lldpd_hardware *hardware)
{
	int rc;
	char *ifname = hardware->h_ifname;
	int iflen = strlen(ifname);
	struct lldpd_port *lport = &hardware->h_lport;
	struct lldpd_dcbx *dcbx = &lport->p_dcbx;
	struct rtattr **attr = (struct rtattr **)lport->p_dcbx_hwoffload.buf_attr;
	int change_app = 0, change_pfc = 0;
	struct rtattr *ieee;
	struct nlmsg msg;
	struct ieee_pfc dcb_pfc;

	if ((attr[DCB_ATTR_IEEE_APP_TABLE]) &&
	   (!TAILQ_EMPTY(&dcbx->apt_list))) {
		change_app++;
	}

	if (attr[DCB_ATTR_IEEE_PFC]) {
		u_int8_t state;

		memcpy(&dcb_pfc, RTA_DATA(attr[DCB_ATTR_IEEE_PFC]), sizeof(dcb_pfc));
		state = (dcb_pfc.mbc ? LLDP_DCBX_PFC_MBC : 0) |
		    (dcb_pfc.pfc_cap ? (dcb_pfc.pfc_cap & LLDP_DCBX_PFC_CAP) : 0);
		if ((dcb_pfc.pfc_en != dcbx->pfc.enable) ||
		    (state != (dcbx->pfc.state & (~~LLDP_DCBX_PFC_WILLING)))) {
			memset(&dcb_pfc, 0, sizeof(dcb_pfc));
			dcb_pfc.pfc_cap = dcbx->pfc.state & LLDP_DCBX_PFC_CAP;
			dcb_pfc.pfc_en = dcbx->pfc.enable;
			dcb_pfc.mbc = !!(dcbx->pfc.state & LLDP_DCBX_PFC_MBC);
			/* dcb_pfc.willing not offloaded */
			/* dcb_pfc.delay NYI */
			change_pfc++;
		}
	}

	if (!change_app && !change_pfc) {
		/* no change */
		return 1;
	}

	/* Send a DCB_CMD_IEEE_SET nlmsg for the named if */
	memset(&msg, 0, sizeof(msg));
	nlmsg_start(&msg, RTM_SETDCB, DCB_CMD_IEEE_SET);
	nlmsg_attr_add(&msg, DCB_ATTR_IFNAME, ifname, iflen + 1);
	ieee = nlmsg_attr_nest_start(&msg, DCB_ATTR_IEEE);

	if (change_pfc) {
		rta_attr_add(ieee, DCB_ATTR_IEEE_PFC, &dcb_pfc, sizeof(dcb_pfc));
	}

	if (change_app) {
		struct lldpd_dcbx_app *app;
		struct dcb_app dcb_app;
		struct rtattr *apt;

		apt = rta_attr_nest_start(ieee, DCB_ATTR_IEEE_APP_TABLE);
		TAILQ_FOREACH(app, &dcbx->apt_list, next) {
			dcb_app.priority = (app->app[0] & LLDP_DCBX_APP_PRI) >> LLDP_DCBX_APP_PRI_SHIFT;
			dcb_app.selector = (app->app[0] & LLDP_DCBX_APP_SEL);
			dcb_app.protocol = (app->app[1] << 8) | app->app[2];
			rta_attr_add(apt, DCB_ATTR_IEEE_APP, &dcb_app, sizeof(dcb_app));
		}
		rta_attr_nest_end(ieee, apt);
	}

	rta_attr_add(ieee, NLMSG_DONE, NULL, 0);
	nlmsg_attr_nest_end(&msg, ieee);

	/* Need to be root to do a RTM_SETDCB/DCB_CMD_IEEE_SET */
	if (priv_netlink_send(ifdcbx_nls, (char *)&msg, msg.nlhdr.nlmsg_len) != msg.nlhdr.nlmsg_len) {
		log_warnx("lldp",
		    "ifdcbx: RTM_SETDCB write failed on netlink socket");
		return 0;
	}

	/* Read (may not be sycnhronous?) nlmsg response */
	rc = read(ifdcbx_nls, &msg, sizeof(msg));
	if (rc == 0) {
		log_warnx("lldp",
		    "ifdcbx: RTM_SETDCB read empty on netlink socket");
		return 0;
	}
	if (rc < 0) {
		log_warnx("lldp",
		    "ifdcbx: RTM_SETDCB read faild on netlink socket");
		return 0;
	}

	if ((msg.nlhdr.nlmsg_seq != ifdcbx_seq)) {
		log_warnx("lldp",
		    "ifdcbx: %s RTM_SETDCB unexpected sequence %d != %d",
		    ifname, msg.nlhdr.nlmsg_seq, ifdcbx_seq);
		return 0;
	}
	if (msg.nlhdr.nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = NLMSG_DATA(&msg.nlhdr);

		log_warn("lldp",
		    "ifdcbx: %s netlink message error %d",
		    ifname, -(err->error));
		return 0;
	}
	if ((msg.nlhdr.nlmsg_type != RTM_SETDCB) ||
	    (msg.dcbmsg.cmd != DCB_CMD_IEEE_SET)) {
		log_warnx("lldp",
		    "ifdcbx: %s RTM_SETDCB unexpected netlink message returned (%d != %d || %d != %d)",
		    ifname,
		    msg.nlhdr.nlmsg_type, RTM_SETDCB,
		    msg.dcbmsg.cmd, DCB_CMD_IEEE_SET);
		return 0;
	}

	return 1;
}

void
ifdcbx_notify(struct lldpd_hardware *hardware, struct lldpd_port *rport)
{
	struct lldpd_dcbx *rdcbx = &rport->p_dcbx;
	struct lldpd_port *lport = &hardware->h_lport;
	struct lldpd_dcbx *ldcbx = &lport->p_dcbx;
	struct lldpd_dcbx_app *rapp, *lapp;
	u_int8_t rstate, lstate;
	int diff = 0;
	int rc;

	/* Note, the local LLDP_DCBX_PFC_WILLING state is maintained */
	rstate = rdcbx->pfc.state & (~LLDP_DCBX_PFC_WILLING);
	lstate = ldcbx->pfc.state & (~LLDP_DCBX_PFC_WILLING);

	if ((rstate & LLDP_DCBX_PFC_CAP) ^ (lstate & LLDP_DCBX_PFC_CAP)) {
		ldcbx->pfc.state &= ~LLDP_DCBX_PFC_CAP;
		ldcbx->pfc.state |= rstate & LLDP_DCBX_PFC_CAP;
		diff++;
	}
	if ((rstate & LLDP_DCBX_PFC_MBC) ^ (lstate & LLDP_DCBX_PFC_MBC)) {
		ldcbx->pfc.state &= ~LLDP_DCBX_PFC_MBC;
		ldcbx->pfc.state |= rstate & LLDP_DCBX_PFC_MBC;
		diff++;
	}
	if (rdcbx->pfc.enable != ldcbx->pfc.enable) {
		ldcbx->pfc.enable = rdcbx->pfc.enable;
		diff++;
	}

	lapp = TAILQ_FIRST(&ldcbx->apt_list);
	TAILQ_FOREACH(rapp, &rdcbx->apt_list, next) {
		if (!lapp || memcmp(rapp->app, lapp->app, sizeof(lapp->app)))
			break;
		lapp = TAILQ_NEXT(lapp, next);
	}
	if (lapp || rapp) {
		struct lldpd_dcbx_app *tapp;

		lapp = TAILQ_FIRST(&ldcbx->apt_list);
		while (lapp) {
			tapp = lapp;
			lapp = TAILQ_NEXT(lapp, next);
			TAILQ_REMOVE(&ldcbx->apt_list, tapp, next);
			free(tapp);
		}
		TAILQ_FOREACH(rapp, &rdcbx->apt_list, next) {
			TAILQ_INSERT_TAIL(&ldcbx->apt_list, rapp, next);
		}
		diff++;
	}

	if (!diff && !lport->p_dcbx_hwoffload.pend)
		return;

	/* Have new lport state or previous to be offload state so try to
	 * offload, on success or EOPNOTSUPP clear pend(ing), else leave
	 * pend(ing) set, will retry on next notify() call (next LLDP frame
	 * recieved for this port).
	 */
	lport->p_dcbx_hwoffload.pend |= !!diff;
	if (!ifdcbx_socket(hardware)) {
		log_warnx("lldp",
		    "ifdcbx_notify unable to open a netlink socket");
		return;
	}
	rc = ifdcbx_get(hardware);
	if (rc == -EOPNOTSUPP) {
		/* no hardware offload support */
		goto hwdone;
	}
	if (rc == 0) {
		log_warnx("lldp",
		    "ifdcbx_notify unable to get current offload state");
		return;
	}
	if (!ifdcbx_set(hardware)) {
		log_warnx("lldp",
		    "ifdcbx_notify unable to set new offload state");
		return;
	}
hwdone:
	lport->p_dcbx_hwoffload.pend = 0;

	/* Note, we only process hardware offload hwew, software offload
	 * (e.g. Linux tc) could be supported.
	 */
}

#endif
