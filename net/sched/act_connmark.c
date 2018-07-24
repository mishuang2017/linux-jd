/*
 * net/sched/act_connmark.c  netfilter connmark retriever action
 * skb mark is over-written
 *
 * Copyright (c) 2011 Felix Fietkau <nbd@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
*/

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/act_api.h>
#include <uapi/linux/tc_act/tc_connmark.h>
#include <net/tc_act/tc_connmark.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>

static int connmark_net_id;
static struct tc_action_ops act_connmark_ops;

static int tcf_connmark(struct sk_buff *skb, const struct tc_action *a,
			struct tcf_result *res)
{
	const struct nf_conntrack_tuple_hash *thash;
	struct nf_conntrack_tuple tuple;
	enum ip_conntrack_info ctinfo;
	struct tcf_connmark_info *ca = to_connmark(a);
	struct nf_conntrack_zone zone;
	struct nf_conn *c;
	int proto;

	spin_lock(&ca->tcf_lock);
	ca->tcf_tm.lastuse = jiffies;
	bstats_update(&ca->tcf_bstats, skb);

	if (skb->protocol == htons(ETH_P_IP)) {
		if (skb->len < sizeof(struct iphdr))
			goto out;

		proto = NFPROTO_IPV4;
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		if (skb->len < sizeof(struct ipv6hdr))
			goto out;

		proto = NFPROTO_IPV6;
	} else {
		goto out;
	}

	c = nf_ct_get(skb, &ctinfo);
	if (c) {
		skb->mark = c->mark;
		/* using overlimits stats to count how many packets marked */
		ca->tcf_qstats.overlimits++;
		goto out;
	}

	if (!nf_ct_get_tuplepr(skb, skb_network_offset(skb),
			       proto, &tuple))
		goto out;

	zone.id = ca->zone;
	zone.dir = NF_CT_DEFAULT_ZONE_DIR;

	thash = nf_conntrack_find_get(ca->net, &zone, &tuple);
	if (!thash)
		goto out;

	c = nf_ct_tuplehash_to_ctrack(thash);
	/* using overlimits stats to count how many packets marked */
	ca->tcf_qstats.overlimits++;
	skb->mark = c->mark;
	nf_ct_put(c);

out:
	spin_unlock(&ca->tcf_lock);
	return ca->tcf_action;
}

static const struct nla_policy connmark_policy[TCA_CONNMARK_MAX + 1] = {
	[TCA_CONNMARK_PARMS] = { .len = sizeof(struct tc_connmark) },
};

static int tcf_connmark_init(struct net *net, struct nlattr *nla,
			     struct nlattr *est, struct tc_action **a,
			     int ovr, int bind, bool rtnl_held)
{
	struct tc_action_net *tn = net_generic(net, connmark_net_id);
	struct nlattr *tb[TCA_CONNMARK_MAX + 1];
	struct tcf_connmark_info *ci;
	struct tc_connmark *parm;
	int ret = 0;

	if (!nla)
		return -EINVAL;

	ret = nla_parse_nested(tb, TCA_CONNMARK_MAX, nla, connmark_policy);
	if (ret < 0)
		return ret;

	if (!tb[TCA_CONNMARK_PARMS])
		return -EINVAL;

	parm = nla_data(tb[TCA_CONNMARK_PARMS]);

	ret = tcf_idr_check_alloc(tn, &parm->index, a, bind);
	if (!ret) {
		ret = tcf_idr_create(tn, parm->index, est, a,
				     &act_connmark_ops, bind, false);
		if (ret) {
			tcf_idr_cleanup(tn, parm->index);
			return ret;
		}

		ci = to_connmark(*a);
		ci->tcf_action = parm->action;
		ci->net = net;
		ci->zone = parm->zone;

		tcf_idr_insert(tn, *a);
		ret = ACT_P_CREATED;
	} else if (ret > 0) {
		ci = to_connmark(*a);
		if (bind)
			return 0;
		if (!ovr) {
			tcf_idr_release(*a, bind);
			return -EEXIST;
		}
		/* replacing action and zone */
		ci->tcf_action = parm->action;
		ci->zone = parm->zone;
		ret = 0;
	}

	return ret;
}

static inline int tcf_connmark_dump(struct sk_buff *skb, struct tc_action *a,
				    int bind, int ref)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct tcf_connmark_info *ci = to_connmark(a);

	struct tc_connmark opt = {
		.index   = ci->tcf_index,
		.refcnt  = refcount_read(&ci->tcf_refcnt) - ref,
		.bindcnt = atomic_read(&ci->tcf_bindcnt) - bind,
		.action  = ci->tcf_action,
		.zone   = ci->zone,
	};
	struct tcf_t t;

	if (nla_put(skb, TCA_CONNMARK_PARMS, sizeof(opt), &opt))
		goto nla_put_failure;

	t.install = jiffies_to_clock_t(jiffies - ci->tcf_tm.install);
	t.lastuse = jiffies_to_clock_t(jiffies - ci->tcf_tm.lastuse);
	t.expires = jiffies_to_clock_t(ci->tcf_tm.expires);
	if (nla_put_64bit(skb, TCA_CONNMARK_TM, sizeof(t), &t,
			  TCA_CONNMARK_PAD))
		goto nla_put_failure;

	return skb->len;
nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

static int tcf_connmark_walker(struct net *net, struct sk_buff *skb,
			       struct netlink_callback *cb, int type,
			       const struct tc_action_ops *ops)
{
	struct tc_action_net *tn = net_generic(net, connmark_net_id);

	return tcf_generic_walker(tn, skb, cb, type, ops);
}

static int tcf_connmark_search(struct net *net, struct tc_action **a, u32 index)
{
	struct tc_action_net *tn = net_generic(net, connmark_net_id);

	return tcf_idr_search(tn, a, index);
}

static int tcf_connmark_delete(struct net *net, u32 index)
{
	struct tc_action_net *tn = net_generic(net, connmark_net_id);

	return tcf_idr_delete_index(tn, index);
}

static struct tc_action_ops act_connmark_ops = {
	.kind		=	"connmark",
	.type		=	TCA_ACT_CONNMARK,
	.owner		=	THIS_MODULE,
	.act		=	tcf_connmark,
	.dump		=	tcf_connmark_dump,
	.init		=	tcf_connmark_init,
	.walk		=	tcf_connmark_walker,
	.lookup		=	tcf_connmark_search,
	.delete		=	tcf_connmark_delete,
	.size		=	sizeof(struct tcf_connmark_info),
};

static __net_init int connmark_init_net(struct net *net)
{
	struct tc_action_net *tn = net_generic(net, connmark_net_id);

	return tc_action_net_init(tn, &act_connmark_ops);
}

static void __net_exit connmark_exit_net(struct list_head *net_list)
{
	tc_action_net_exit(net_list, connmark_net_id);
}

static struct pernet_operations connmark_net_ops = {
	.init = connmark_init_net,
	.exit_batch = connmark_exit_net,
	.id   = &connmark_net_id,
	.size = sizeof(struct tc_action_net),
};

static int __init connmark_init_module(void)
{
	return tcf_register_action(&act_connmark_ops, &connmark_net_ops);
}

static void __exit connmark_cleanup_module(void)
{
	tcf_unregister_action(&act_connmark_ops, &connmark_net_ops);
}

module_init(connmark_init_module);
module_exit(connmark_cleanup_module);
MODULE_AUTHOR("Felix Fietkau <nbd@openwrt.org>");
MODULE_DESCRIPTION("Connection tracking mark restoring");
MODULE_LICENSE("GPL");
