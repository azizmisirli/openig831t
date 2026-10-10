/* SPDX-License-Identifier: GPL-2.0-only
 * Linux-derived offline test harness.
 * Copyright (C) 2010 Samsung Electronics
 * Based on GadgetFS: Copyright (C) 2003-2004 David Brownell
 * Copyright (C) 2003 Agilent Technologies
 * FunctionFS author: Michal Nazarewicz
 * Host test shims and experimental modifications:
 * Copyright (C) 2026 OpenIG831T contributors
 *
 * This distribution selects GPL version 2 for upstream GPL-2.0-or-later
 * portions. See ../upstream.json for pinned sources and function hashes.
 * Host-only shims do not validate a full kernel build or physical hardware.
 * Endpoint autoconfiguration: Copyright (C) 2004 David Brownell
 * UDC matcher: Copyright (C) 2010 Texas Instruments; author Felipe Balbi
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;
#define USB_DIR_IN 128
#define USB_ENDPOINT_NUMBER_MASK 15
#define USB_ENDPOINT_XFERTYPE_MASK 3
#define USB_ENDPOINT_XFER_CONTROL 0
#define USB_ENDPOINT_XFER_ISOC 1
#define USB_ENDPOINT_XFER_BULK 2
#define USB_ENDPOINT_XFER_INT 3
#define USB_DT_ENDPOINT 5
#define USB_DT_ENDPOINT_SIZE 7
#define ENOTSUPP 524
#define GFP_KERNEL 0
#define ARRAY_SIZE(a) ((int)(sizeof(a)/sizeof((a)[0])))
#define FUNCTIONFS_HAS_FS_DESC 1
#define FUNCTIONFS_HAS_HS_DESC 2
#define FUNCTIONFS_HAS_SS_DESC 4
#define FUNCTIONFS_HAS_MS_OS_DESC 8
#define FUNCTIONFS_VIRTUAL_ADDR 16
#define FUNCTIONFS_EVENTFD 32
#define FUNCTIONFS_ALL_CTRL_RECIP 64
#define FUNCTIONFS_CONFIG0_SETUP 128
#define FUNCTIONFS_EXPERIMENTAL_CDC_FUNCS (1U<<30)
#define FUNCTIONFS_EXPERIMENTAL_EXACT_ADDR (1U<<29)
#define pr_vdebug(...) do{}while(0)
#define pr_err(...) do{(void)speed_names;}while(0)
#define ffs_dump_mem(...) do{}while(0)
#define cpu_to_le16(x) (x)
#define simple_strtoul(s,e,b) strtoul(s,e,b)
struct list_head{struct list_head *next,*prev;};
#define list_for_each_entry(pos,head,member) \
 for(struct list_head *_n=(head)->next; _n!=(head) && ((pos)=(void*)((char*)_n - offsetof(struct usb_ep,member)),1);_n=_n->next)
struct usb_descriptor_header{u8 bLength,bDescriptorType;};
struct usb_endpoint_descriptor{u8 bLength,bDescriptorType,bEndpointAddress,bmAttributes;u16 wMaxPacketSize;u8 bInterval,bRefresh,bSynchAddress;} __attribute__((packed));
struct usb_ss_ep_comp_descriptor{u8 bmAttributes;};
struct caps{bool dir_in,dir_out,type_iso,type_bulk,type_int;};
struct usb_ep{const char *name;struct list_head ep_list;struct caps caps;bool claimed;u8 address;unsigned maxpacket_limit;unsigned max_streams:16;void *desc,*comp_desc,*driver_data;};
struct usb_gadget;
struct gadget_ops{struct usb_ep *(*match_ep)(struct usb_gadget*,struct usb_endpoint_descriptor*,struct usb_ss_ep_comp_descriptor*);};
struct usb_gadget{struct list_head ep_list;struct gadget_ops *ops;bool dual,super;unsigned in_epnum,out_epnum;};
static unsigned usb_endpoint_type(const struct usb_endpoint_descriptor*d){return d->bmAttributes&3;}
static unsigned usb_endpoint_maxp(const struct usb_endpoint_descriptor*d){return d->wMaxPacketSize&2047;}
static unsigned usb_endpoint_maxp_mult(const struct usb_endpoint_descriptor*d){return 1+((d->wMaxPacketSize>>11)&3);}
static bool usb_endpoint_dir_in(const struct usb_endpoint_descriptor*d){return d->bEndpointAddress&128;}
static bool usb_endpoint_dir_out(const struct usb_endpoint_descriptor*d){return !(d->bEndpointAddress&128);}
static bool gadget_is_dualspeed(struct usb_gadget*g){return g->dual;}
static bool gadget_is_superspeed(struct usb_gadget*g){return g->super;}
struct usb_request{unsigned marker;};
struct ffs_data{unsigned eps_count,user_flags;u8 eps_addrmap[31];int eps_lock;};
struct ffs_ep{struct usb_ep *ep;struct usb_request *req;struct usb_endpoint_descriptor *descs[3];};
struct usb_function{struct usb_descriptor_header **fs_descriptors,**hs_descriptors,**ss_descriptors,**ssp_descriptors;void *os_desc_table;unsigned os_desc_n;};
struct ffs_function{struct ffs_data *ffs;struct usb_gadget *gadget;struct ffs_ep *eps;short *interfaces_nums;struct usb_function function;u8 eps_revmap[16];};
enum ffs_entity_type{FFS_DESCRIPTOR,FFS_INTERFACE,FFS_STRING,FFS_ENDPOINT,FFS_INTERFACE_REF};
static unsigned request_calls,request_frees,request_fail_at,releases;
static struct usb_request *usb_ep_alloc_request(struct usb_ep *ep,int gfp){(void)ep;(void)gfp;++request_calls;return request_calls==request_fail_at?NULL:calloc(1,sizeof(struct usb_request));}
static void usb_ep_free_request(struct usb_ep *ep,struct usb_request*req){(void)ep;++request_frees;free(req);}
static void usb_ep_autoconfig_release(struct usb_ep*ep){++releases;ep->claimed=false;ep->driver_data=NULL;}
#define kfree(p) free(p)
#define spin_lock_irqsave(lock,flags) do{(void)(lock);(flags)=0;}while(0)
#define spin_unlock_irqrestore(lock,flags) do{(void)(lock);(void)(flags);}while(0)
static unsigned checks;
#define CHECK(x) do{++checks;if(!(x)){fprintf(stderr,"FAIL:%d %s\n",__LINE__,#x);exit(1);}}while(0)

static int cdc_flags(unsigned flags){int ret=-EINVAL;
		if (flags & ~(FUNCTIONFS_HAS_FS_DESC |
			      FUNCTIONFS_HAS_HS_DESC |
			      FUNCTIONFS_HAS_SS_DESC |
			      FUNCTIONFS_HAS_MS_OS_DESC |
			      FUNCTIONFS_VIRTUAL_ADDR |
			      FUNCTIONFS_EVENTFD |
			      FUNCTIONFS_ALL_CTRL_RECIP |
			      FUNCTIONFS_CONFIG0_SETUP |
			      FUNCTIONFS_EXPERIMENTAL_CDC_FUNCS)) {
			ret = -ENOSYS;
			goto error;
		}

return 0;error:return ret;}

static int combined_flags(unsigned flags){int ret=-EINVAL;
		if (flags & ~(FUNCTIONFS_HAS_FS_DESC |
			      FUNCTIONFS_HAS_HS_DESC |
			      FUNCTIONFS_HAS_SS_DESC |
			      FUNCTIONFS_HAS_MS_OS_DESC |
			      FUNCTIONFS_VIRTUAL_ADDR |
			      FUNCTIONFS_EVENTFD |
			      FUNCTIONFS_ALL_CTRL_RECIP |
			      FUNCTIONFS_CONFIG0_SETUP |
			      FUNCTIONFS_EXPERIMENTAL_CDC_FUNCS |
			      FUNCTIONFS_EXPERIMENTAL_EXACT_ADDR)) {
			ret = -ENOSYS;
			goto error;
		}
		/* This private allocator currently covers FS/HS, no virtual mode. */
		if ((flags & FUNCTIONFS_EXPERIMENTAL_EXACT_ADDR) &&
		    (flags & (FUNCTIONFS_HAS_SS_DESC | FUNCTIONFS_VIRTUAL_ADDR)))
			goto error;

return 0;error:return ret;}

int usb_gadget_ep_match_desc(struct usb_gadget *gadget,
		struct usb_ep *ep, struct usb_endpoint_descriptor *desc,
		struct usb_ss_ep_comp_descriptor *ep_comp)
{
	u8		type;
	u16		max;
	int		num_req_streams = 0;

	/* endpoint already claimed? */
	if (ep->claimed)
		return 0;

	type = usb_endpoint_type(desc);
	max = usb_endpoint_maxp(desc);

	if (usb_endpoint_dir_in(desc) && !ep->caps.dir_in)
		return 0;
	if (usb_endpoint_dir_out(desc) && !ep->caps.dir_out)
		return 0;

	if (max > ep->maxpacket_limit)
		return 0;

	/* "high bandwidth" works only at high speed */
	if (!gadget_is_dualspeed(gadget) && usb_endpoint_maxp_mult(desc) > 1)
		return 0;

	switch (type) {
	case USB_ENDPOINT_XFER_CONTROL:
		/* only support ep0 for portable CONTROL traffic */
		return 0;
	case USB_ENDPOINT_XFER_ISOC:
		if (!ep->caps.type_iso)
			return 0;
		/* ISO:  limit 1023 bytes full speed, 1024 high/super speed */
		if (!gadget_is_dualspeed(gadget) && max > 1023)
			return 0;
		break;
	case USB_ENDPOINT_XFER_BULK:
		if (!ep->caps.type_bulk)
			return 0;
		if (ep_comp && gadget_is_superspeed(gadget)) {
			/* Get the number of required streams from the
			 * EP companion descriptor and see if the EP
			 * matches it
			 */
			num_req_streams = ep_comp->bmAttributes & 0x1f;
			if (num_req_streams > ep->max_streams)
				return 0;
		}
		break;
	case USB_ENDPOINT_XFER_INT:
		/* Bulk endpoints handle interrupt transfers,
		 * except the toggle-quirky iso-synch kind
		 */
		if (!ep->caps.type_int && !ep->caps.type_bulk)
			return 0;
		/* INT:  limit 64 bytes full speed, 1024 high/super speed */
		if (!gadget_is_dualspeed(gadget) && max > 64)
			return 0;
		break;
	}

	return 1;
}

struct usb_ep *usb_ep_autoconfig_ss(
	struct usb_gadget		*gadget,
	struct usb_endpoint_descriptor	*desc,
	struct usb_ss_ep_comp_descriptor *ep_comp
)
{
	struct usb_ep	*ep;

	if (gadget->ops->match_ep) {
		ep = gadget->ops->match_ep(gadget, desc, ep_comp);
		if (ep)
			goto found_ep;
	}

	/* Second, look at endpoints until an unclaimed one looks usable */
	list_for_each_entry (ep, &gadget->ep_list, ep_list) {
		if (usb_gadget_ep_match_desc(gadget, ep, desc, ep_comp))
			goto found_ep;
	}

	/* Fail */
	return NULL;
found_ep:

	/*
	 * If the protocol driver hasn't yet decided on wMaxPacketSize
	 * and wants to know the maximum possible, provide the info.
	 */
	if (desc->wMaxPacketSize == 0)
		desc->wMaxPacketSize = cpu_to_le16(ep->maxpacket_limit);

	/* report address */
	desc->bEndpointAddress &= USB_DIR_IN;
	if (isdigit(ep->name[2])) {
		u8 num = simple_strtoul(&ep->name[2], NULL, 10);
		desc->bEndpointAddress |= num;
	} else if (desc->bEndpointAddress & USB_DIR_IN) {
		if (++gadget->in_epnum > 15)
			return NULL;
		desc->bEndpointAddress = USB_DIR_IN | gadget->in_epnum;
	} else {
		if (++gadget->out_epnum > 15)
			return NULL;
		desc->bEndpointAddress |= gadget->out_epnum;
	}

	ep->address = desc->bEndpointAddress;
	ep->desc = NULL;
	ep->comp_desc = NULL;
	ep->claimed = true;
	return ep;
}

struct usb_ep *usb_ep_autoconfig(
	struct usb_gadget		*gadget,
	struct usb_endpoint_descriptor	*desc
)
{
	struct usb_ep	*ep;
	u8		type;

	ep = usb_ep_autoconfig_ss(gadget, desc, NULL);
	if (!ep)
		return NULL;

	type = desc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK;

	/* report (variable) full speed bulk maxpacket */
	if (type == USB_ENDPOINT_XFER_BULK) {
		int size = ep->maxpacket_limit;

		/* min() doesn't work on bitfields with gcc-3.5 */
		if (size > 64)
			size = 64;
		desc->wMaxPacketSize = cpu_to_le16(size);
	}

	return ep;
}

static int ffs_ep_addr2idx(struct ffs_data *ffs, u8 endpoint_address)
{
	int i;

	for (i = 1; i < ARRAY_SIZE(ffs->eps_addrmap); ++i)
		if (ffs->eps_addrmap[i] == endpoint_address)
			return i;
	return -ENOENT;
}

static bool ffs_ep_matches_exact(struct usb_gadget *gadget, struct usb_ep *ep,
				 const struct usb_endpoint_descriptor *desc)
{
	struct usb_ep candidate;
	struct usb_endpoint_descriptor wanted = { };
	char name[16];
	u8 address = desc->bEndpointAddress;

	if (!ep->name || !(address & USB_ENDPOINT_NUMBER_MASK) ||
	    (address & ~(USB_DIR_IN | USB_ENDPOINT_NUMBER_MASK)) ||
	    desc->bLength != USB_DT_ENDPOINT_SIZE ||
	    !usb_endpoint_maxp(desc))
		return false;
	/* The wire descriptor is 7 bytes; the C struct also has audio fields. */
	memcpy(&wanted, desc, USB_DT_ENDPOINT_SIZE);
	snprintf(name, sizeof(name), "ep%u%s", address & USB_ENDPOINT_NUMBER_MASK,
		 address & USB_DIR_IN ? "in" : "out");
	if (strcmp(ep->name, name))
		return false;
	/* Match capabilities without temporarily unclaiming the real endpoint. */
	candidate = *ep;
	candidate.claimed = false;
	return usb_gadget_ep_match_desc(gadget, &candidate, &wanted, NULL);
}

static struct usb_ep *ffs_ep_autoconfig_exact(struct usb_gadget *gadget,
					    struct usb_endpoint_descriptor *desc)
{
	struct usb_ep *ep, *match = NULL;

	list_for_each_entry(ep, &gadget->ep_list, ep_list) {
		if (!ffs_ep_matches_exact(gadget, ep, desc))
			continue;
		/* Ambiguous aliases and existing claims never trigger fallback. */
		if (match || ep->claimed)
			return NULL;
		match = ep;
	}
	if (!match)
		return NULL;
	match->address = desc->bEndpointAddress;
	match->desc = NULL;
	match->comp_desc = NULL;
	match->claimed = true;
	return match;
}

static void ffs_exact_bind_rollback(struct ffs_function *func)
{
	unsigned i;

	for (i = 0; func->eps && i < func->ffs->eps_count; ++i) {
		struct ffs_ep *ep = &func->eps[i];

		if (!ep->ep)
			continue;
		if (ep->req)
			usb_ep_free_request(ep->ep, ep->req);
		usb_ep_autoconfig_release(ep->ep);
		ep->ep = NULL;
		ep->req = NULL;
	}
	kfree(func->eps);
	func->eps = NULL;
	func->interfaces_nums = NULL;
	func->function.fs_descriptors = NULL;
	func->function.hs_descriptors = NULL;
	func->function.ss_descriptors = NULL;
	func->function.ssp_descriptors = NULL;
	func->function.os_desc_table = NULL;
	func->function.os_desc_n = 0;
	memset(func->eps_revmap, 0, sizeof(func->eps_revmap));
}

static int __ffs_func_bind_do_descs(enum ffs_entity_type type, u8 *valuep,
				    struct usb_descriptor_header *desc,
				    void *priv)
{
	struct usb_endpoint_descriptor *ds = (void *)desc;
	struct ffs_function *func = priv;
	struct ffs_ep *ffs_ep;
	unsigned ep_desc_id;
	int idx;
	static const char *speed_names[] = { "full", "high", "super" };

	if (type != FFS_DESCRIPTOR)
		return 0;

	/*
	 * If ss_descriptors is not NULL, we are reading super speed
	 * descriptors; if hs_descriptors is not NULL, we are reading high
	 * speed descriptors; otherwise, we are reading full speed
	 * descriptors.
	 */
	if (func->function.ss_descriptors) {
		ep_desc_id = 2;
		func->function.ss_descriptors[(long)valuep] = desc;
	} else if (func->function.hs_descriptors) {
		ep_desc_id = 1;
		func->function.hs_descriptors[(long)valuep] = desc;
	} else {
		ep_desc_id = 0;
		func->function.fs_descriptors[(long)valuep]    = desc;
	}

	if (!desc || desc->bDescriptorType != USB_DT_ENDPOINT)
		return 0;

	idx = ffs_ep_addr2idx(func->ffs, ds->bEndpointAddress) - 1;
	if (idx < 0)
		return idx;

	ffs_ep = func->eps + idx;

	if (ffs_ep->descs[ep_desc_id]) {
		pr_err("two %sspeed descriptors for EP %d\n",
			  speed_names[ep_desc_id],
			  ds->bEndpointAddress & USB_ENDPOINT_NUMBER_MASK);
		return -EINVAL;
	}
	ffs_ep->descs[ep_desc_id] = ds;

	ffs_dump_mem(": Original  ep desc", ds, ds->bLength);
	if (ffs_ep->ep &&
	    (func->ffs->user_flags & FUNCTIONFS_EXPERIMENTAL_EXACT_ADDR)) {
		/* Every advertised speed must fit the same fixed physical EP. */
		if (ds->bEndpointAddress != ffs_ep->ep->address ||
		    !ffs_ep_matches_exact(func->gadget, ffs_ep->ep, ds))
			return -ENOTSUPP;
	} else if (ffs_ep->ep) {
		ds->bEndpointAddress = ffs_ep->descs[0]->bEndpointAddress;
		if (!ds->wMaxPacketSize)
			ds->wMaxPacketSize = ffs_ep->descs[0]->wMaxPacketSize;
	} else {
		struct usb_request *req;
		struct usb_ep *ep;
		u8 bEndpointAddress;
		u16 wMaxPacketSize;

		/*
		 * We back up bEndpointAddress because autoconfig overwrites
		 * it with physical endpoint address.
		 */
		bEndpointAddress = ds->bEndpointAddress;
		/*
		 * We back up wMaxPacketSize because autoconfig treats
		 * endpoint descriptors as if they were full speed.
		 */
		wMaxPacketSize = ds->wMaxPacketSize;
		pr_vdebug("autoconfig\n");
		if (func->ffs->user_flags & FUNCTIONFS_EXPERIMENTAL_EXACT_ADDR)
			ep = ffs_ep_autoconfig_exact(func->gadget, ds);
		else
			ep = usb_ep_autoconfig(func->gadget, ds);
		if (!ep)
			return -ENOTSUPP;
		ep->driver_data = func->eps + idx;

		req = usb_ep_alloc_request(ep, GFP_KERNEL);
		if (!req) {
			if (func->ffs->user_flags & FUNCTIONFS_EXPERIMENTAL_EXACT_ADDR)
				usb_ep_autoconfig_release(ep);
			return -ENOMEM;
		}

		ffs_ep->ep  = ep;
		ffs_ep->req = req;
		func->eps_revmap[ds->bEndpointAddress &
				 USB_ENDPOINT_NUMBER_MASK] = idx + 1;
		/*
		 * If we use virtual address mapping, we restore
		 * original bEndpointAddress value.
		 */
		if (func->ffs->user_flags & FUNCTIONFS_VIRTUAL_ADDR)
			ds->bEndpointAddress = bEndpointAddress;
		/*
		 * Restore wMaxPacketSize which was potentially
		 * overwritten by autoconfig.
		 */
		ds->wMaxPacketSize = wMaxPacketSize;
	}
	ffs_dump_mem(": Rewritten ep desc", ds, ds->bLength);

	return 0;
}

static void normal_cleanup_allocations(struct ffs_function *func){
struct ffs_data *ffs=func->ffs;struct ffs_ep *ep=func->eps;unsigned count=ffs->eps_count;unsigned long flags;
	/* cleanup after autoconfig */
	spin_lock_irqsave(&func->ffs->eps_lock, flags);
	while (ep && count--) {
		if (ep->ep && ep->req)
			usb_ep_free_request(ep->ep, ep->req);
		ep->req = NULL;
		if ((ffs->user_flags & FUNCTIONFS_EXPERIMENTAL_EXACT_ADDR) && ep->ep) {
			usb_ep_autoconfig_release(ep->ep);
			ep->ep = NULL;
		}
		++ep;
	}
	spin_unlock_irqrestore(&func->ffs->eps_lock, flags);
	kfree(func->eps);
	func->eps = NULL;
	/*
	 * eps, descriptors and interfaces_nums are allocated in the
	 * same chunk so only one free is required.
	 */
	func->function.fs_descriptors = NULL;
	func->function.hs_descriptors = NULL;
	func->function.ss_descriptors = NULL;
	func->function.ssp_descriptors = NULL;
	func->interfaces_nums = NULL;

}

static const u8 exact_fs[]={9,4,0,0,2,255,255,255,0,7,5,129,2,64,0,0,7,5,1,2,64,0,0,9,4,1,0,3,255,0,0,0,5,36,0,16,1,5,36,1,0,0,4,36,2,2,5,36,6,0,0,7,5,131,3,10,0,32,7,5,130,2,64,0,0,7,5,2,2,64,0,0,9,4,2,0,3,255,0,0,0,5,36,0,16,1,5,36,1,0,0,4,36,2,2,5,36,6,0,0,7,5,133,3,10,0,32,7,5,132,2,64,0,0,7,5,3,2,64,0,0,9,4,3,0,3,255,0,0,0,5,36,0,16,1,5,36,1,0,0,4,36,2,2,5,36,6,0,0,7,5,135,3,10,0,32,7,5,134,2,64,0,0,7,5,4,2,64,0,0,9,4,4,0,3,255,255,255,0,7,5,137,3,8,0,32,7,5,136,2,64,0,0,7,5,5,2,64,0,0};

static const u8 exact_hs[]={9,4,0,0,2,255,255,255,0,7,5,129,2,0,2,0,7,5,1,2,0,2,0,9,4,1,0,3,255,0,0,0,5,36,0,16,1,5,36,1,0,0,4,36,2,2,5,36,6,0,0,7,5,131,3,10,0,9,7,5,130,2,0,2,0,7,5,2,2,0,2,0,9,4,2,0,3,255,0,0,0,5,36,0,16,1,5,36,1,0,0,4,36,2,2,5,36,6,0,0,7,5,133,3,10,0,9,7,5,132,2,0,2,0,7,5,3,2,0,2,0,9,4,3,0,3,255,0,0,0,5,36,0,16,1,5,36,1,0,0,4,36,2,2,5,36,6,0,0,7,5,135,3,10,0,9,7,5,134,2,0,2,0,7,5,4,2,0,2,0,9,4,4,0,3,255,255,255,0,7,5,137,3,8,0,9,7,5,136,2,0,2,0,7,5,5,2,0,2,0};


struct model{struct usb_gadget gadget;struct gadget_ops ops;struct usb_ep eps[32];char names[32][16];unsigned count;};
static void init_model(struct model*m,bool reverse){
 memset(m,0,sizeof(*m));m->gadget.ops=&m->ops;m->gadget.dual=true;
 m->gadget.ep_list.next=m->gadget.ep_list.prev=&m->gadget.ep_list;
 for(unsigned i=0;i<30;i++){
  unsigned n=reverse?29-i:i;unsigned number=n/2+1;bool in=n%2;
  struct usb_ep*ep=&m->eps[i];snprintf(m->names[i],16,"ep%u%s",number,in?"in":"out");
  ep->name=m->names[i];ep->caps=(struct caps){.dir_in=in,.dir_out=!in,.type_bulk=true,.type_int=true,.type_iso=true};ep->maxpacket_limit=512;
  struct list_head*head=&m->gadget.ep_list;ep->ep_list.prev=head->prev;ep->ep_list.next=head;head->prev->next=&ep->ep_list;head->prev=&ep->ep_list;m->count++;
 }
 request_calls=request_frees=request_fail_at=releases=0;
}
static struct usb_ep *by_name(struct model*m,const char*name){for(unsigned i=0;i<m->count;i++)if(!strcmp(m->eps[i].name,name))return &m->eps[i];return NULL;}
static struct usb_endpoint_descriptor desc(u8 a,u8 t,u16 p){return (struct usb_endpoint_descriptor){.bLength=7,.bDescriptorType=5,.bEndpointAddress=a,.bmAttributes=t,.wMaxPacketSize=p,.bInterval=9};}
static void prepare(struct ffs_function*f,struct ffs_data*d,struct model*m,unsigned flags){
 memset(f,0,sizeof(*f));memset(d,0,sizeof(*d));f->ffs=d;f->gadget=&m->gadget;d->user_flags=flags;d->eps_count=14;
 f->eps=calloc(14,sizeof(*f->eps));CHECK(f->eps!=NULL);
 unsigned index=1;for(unsigned i=0;i<sizeof(exact_hs);i+=exact_hs[i])if(exact_hs[i+1]==5)d->eps_addrmap[index++]=exact_hs[i+2];
 CHECK(index==15);
}
static int walk(struct ffs_function*f,u8*bytes,unsigned len,unsigned speed){
 struct usb_descriptor_header *items[64]={0};
 if(speed==0)f->function.fs_descriptors=items;else f->function.hs_descriptors=items;
 int result=0;unsigned item=0;
 for(unsigned i=0;i<len;i+=bytes[i]){CHECK(bytes[i]>=2 && i+bytes[i]<=len);result=__ffs_func_bind_do_descs(FFS_DESCRIPTOR,(u8*)(uintptr_t)item++,(void*)(bytes+i),f);if(result<0)break;}
 /* Stack table lifetime must not escape; non-NULL sentinel identifies FS. */
 if(speed==0)f->function.fs_descriptors=(void*)1;else f->function.hs_descriptors=(void*)1;
 return result;
}
int main(void){
 const unsigned flag=FUNCTIONFS_EXPERIMENTAL_EXACT_ADDR;
 CHECK(cdc_flags(flag)==-ENOSYS);CHECK(combined_flags(flag|3)==0);
 CHECK(combined_flags(flag|FUNCTIONFS_VIRTUAL_ADDR)==-EINVAL);
 CHECK(combined_flags(flag|FUNCTIONFS_HAS_SS_DESC)==-EINVAL);
 CHECK(combined_flags(3|FUNCTIONFS_VIRTUAL_ADDR)==0);
 CHECK(combined_flags(flag|(1U<<28))==-ENOSYS);
 CHECK(combined_flags(flag|FUNCTIONFS_EXPERIMENTAL_CDC_FUNCS|3)==0);
 struct model m;struct usb_endpoint_descriptor d=desc(0x83,3,10),before=d;struct usb_ep*ep;
 /* Linux's endpoint struct is9B, but this valid wire allocation is exactly7B. */
 CHECK(sizeof(struct usb_endpoint_descriptor)==9);init_model(&m,false);
 u8 *raw7=malloc(7);CHECK(raw7!=NULL);memcpy(raw7,&d,7);
 CHECK(ffs_ep_matches_exact(&m.gadget,by_name(&m,"ep3in"),(void*)raw7));free(raw7);
 init_model(&m,false);ep=ffs_ep_autoconfig_exact(&m.gadget,&d);
 CHECK(ep==by_name(&m,"ep3in") && ep->address==0x83 && ep->claimed);CHECK(!memcmp(&d,&before,sizeof(d)));CHECK(!by_name(&m,"ep2in")->claimed);
 CHECK(ffs_ep_autoconfig_exact(&m.gadget,&d)==NULL);usb_ep_autoconfig_release(ep);
 struct {u8 address,type;u16 packet;} invalid[]={{0x80,3,10},{0x93,3,10},{0x83,0,10},{0x83,3,0},{0x83,3,513}};
 for(int i=0;i<ARRAY_SIZE(invalid);i++){d=desc(invalid[i].address,invalid[i].type,invalid[i].packet);CHECK(ffs_ep_autoconfig_exact(&m.gadget,&d)==NULL);CHECK(!by_name(&m,"ep3in")->claimed);}
 d=desc(0x83,3,10);d.bLength=9;CHECK(ffs_ep_autoconfig_exact(&m.gadget,&d)==NULL);d.bLength=7;
 ep=by_name(&m,"ep3in");ep->name="ep-c";CHECK(ffs_ep_autoconfig_exact(&m.gadget,&d)==NULL);ep->name="ep03in";CHECK(ffs_ep_autoconfig_exact(&m.gadget,&d)==NULL);ep->name="ep3in-bulk";CHECK(ffs_ep_autoconfig_exact(&m.gadget,&d)==NULL);ep->name="ep3in";
 ep->caps.dir_in=false;CHECK(ffs_ep_autoconfig_exact(&m.gadget,&d)==NULL);ep->caps.dir_in=true;
 ep->caps.type_int=false;ep->caps.type_bulk=false;CHECK(ffs_ep_autoconfig_exact(&m.gadget,&d)==NULL);ep->caps.type_bulk=true;CHECK(ffs_ep_autoconfig_exact(&m.gadget,&d)==ep);usb_ep_autoconfig_release(ep);ep->caps.type_int=true;
 by_name(&m,"ep2in")->name="ep3in";CHECK(ffs_ep_autoconfig_exact(&m.gadget,&d)==NULL);CHECK(!ep->claimed);
 /* Numerically sorted requests also preserve each address, irrespective of list order. */
 init_model(&m,true);
 for(unsigned number=1;number<=9;number++){d=desc(128|number,number%2?3:2,number%2?10:512);ep=ffs_ep_autoconfig_exact(&m.gadget,&d);CHECK(ep && ep->address==(128|number));}
 for(unsigned number=1;number<=5;number++){d=desc(number,2,512);ep=ffs_ep_autoconfig_exact(&m.gadget,&d);CHECK(ep && ep->address==number);}
 for(unsigned i=0;i<m.count;i++)if(m.eps[i].claimed)usb_ep_autoconfig_release(&m.eps[i]);
 for(unsigned reverse=0;reverse<2;reverse++){
  init_model(&m,reverse);struct ffs_function f;struct ffs_data data;prepare(&f,&data,&m,flag);
  u8 fs[sizeof(exact_fs)],hs[sizeof(exact_hs)];memcpy(fs,exact_fs,sizeof fs);memcpy(hs,exact_hs,sizeof hs);
  CHECK(walk(&f,fs,sizeof fs,0)==0);CHECK(walk(&f,hs,sizeof hs,1)==0);
  CHECK(!memcmp(fs,exact_fs,sizeof fs));CHECK(!memcmp(hs,exact_hs,sizeof hs));CHECK(request_calls==14);
  for(unsigned i=0;i<14;i++){CHECK(f.eps[i].ep->address==data.eps_addrmap[i+1]);CHECK(f.eps[i].ep->claimed);}
  ffs_exact_bind_rollback(&f);CHECK(request_frees==14 && releases==14 && f.eps==NULL);for(unsigned i=0;i<30;i++)CHECK(!m.eps[i].claimed);
  ffs_exact_bind_rollback(&f);CHECK(releases==14);
 }
 /* Existing default path retains first-fit rewrites; opt-in is not automatic. */
 init_model(&m,false);struct ffs_function f;struct ffs_data data;prepare(&f,&data,&m,0);u8 fs[sizeof(exact_fs)];memcpy(fs,exact_fs,sizeof fs);CHECK(walk(&f,fs,sizeof fs,0)==0);CHECK(memcmp(fs,exact_fs,sizeof fs)!=0);CHECK(f.eps[2].ep->address==0x82 && f.eps[3].ep->address==0x83);ffs_exact_bind_rollback(&f);
 /* HS-only is supported; no dereference of absent descs[0]. */
 init_model(&m,false);prepare(&f,&data,&m,flag);u8 hs[sizeof(exact_hs)];memcpy(hs,exact_hs,sizeof hs);CHECK(walk(&f,hs,sizeof hs,1)==0);CHECK(!memcmp(hs,exact_hs,sizeof hs));ffs_exact_bind_rollback(&f);
 /* A subsequent speed that requires too much capacity must unwind claims. */
 init_model(&m,false);by_name(&m,"ep2in")->maxpacket_limit=64;prepare(&f,&data,&m,flag);memcpy(fs,exact_fs,sizeof fs);memcpy(hs,exact_hs,sizeof hs);CHECK(walk(&f,fs,sizeof fs,0)==0);CHECK(walk(&f,hs,sizeof hs,1)==-ENOTSUPP);ffs_exact_bind_rollback(&f);CHECK(request_frees==14 && releases==14);
 /* Request allocation failure releases the current claim and previous claims. */
 init_model(&m,false);prepare(&f,&data,&m,flag);request_fail_at=4;memcpy(fs,exact_fs,sizeof fs);CHECK(walk(&f,fs,sizeof fs,0)==-ENOMEM);CHECK(!by_name(&m,"ep2in")->claimed);ffs_exact_bind_rollback(&f);CHECK(request_frees==3 && releases==4);
 /* Busy target preserves external ownership while rolling back own claims. */
 init_model(&m,false);ep=by_name(&m,"ep3in");ep->claimed=true;ep->driver_data=(void*)123;prepare(&f,&data,&m,flag);memcpy(fs,exact_fs,sizeof fs);CHECK(walk(&f,fs,sizeof fs,0)==-ENOTSUPP);ffs_exact_bind_rollback(&f);CHECK(ep->claimed && ep->driver_data==(void*)123);CHECK(request_frees==2 && releases==2);
 /* Missing target does not substitute another IN endpoint. */
 init_model(&m,false);by_name(&m,"ep3in")->name="unavailable";prepare(&f,&data,&m,flag);memcpy(fs,exact_fs,sizeof fs);CHECK(walk(&f,fs,sizeof fs,0)==-ENOTSUPP);ffs_exact_bind_rollback(&f);CHECK(!by_name(&m,"ep2in")->claimed);
 /* Fail each request allocation position; no old own claim/request survives. */
 for(unsigned fail=1;fail<=14;fail++){
  init_model(&m,false);prepare(&f,&data,&m,flag);request_fail_at=fail;memcpy(fs,exact_fs,sizeof fs);
  CHECK(walk(&f,fs,sizeof fs,0)==-ENOMEM);ffs_exact_bind_rollback(&f);
  CHECK(request_frees==fail-1 && releases==fail);for(unsigned i=0;i<m.count;i++)CHECK(!m.eps[i].claimed);
 }
 /* Actual normal-unbind allocation-cleanup statements release own exact claims. */
 init_model(&m,false);prepare(&f,&data,&m,flag);memcpy(fs,exact_fs,sizeof fs);CHECK(walk(&f,fs,sizeof fs,0)==0);normal_cleanup_allocations(&f);CHECK(request_frees==14 && releases==14 && !f.eps);
 normal_cleanup_allocations(&f);CHECK(request_frees==14 && releases==14);
 /* Default unbind cleanup does not acquire new exact-release behavior. */
 init_model(&m,false);prepare(&f,&data,&m,0);memcpy(fs,exact_fs,sizeof fs);CHECK(walk(&f,fs,sizeof fs,0)==0);normal_cleanup_allocations(&f);CHECK(request_frees==14 && releases==0);
 printf("{\"result\":\"PASS\",\"assertions\":%u,\"hardware\":false,\"full_kernel_build\":false}\n",checks);return 0;
}
