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
 */
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
typedef uint8_t u8;
#define __must_check
#define pr_vdebug(...) do {} while (0)
#define pr_debug(...) do {} while (0)
#define USB_DT_DEVICE 1
#define USB_DT_CONFIG 2
#define USB_DT_STRING 3
#define USB_DT_INTERFACE 4
#define USB_DT_ENDPOINT 5
#define USB_DT_DEVICE_QUALIFIER 6
#define USB_DT_OTHER_SPEED_CONFIG 7
#define USB_DT_INTERFACE_POWER 8
#define USB_DT_OTG 9
#define USB_DT_DEBUG 10
#define USB_DT_INTERFACE_ASSOCIATION 11
#define USB_DT_SECURITY 12
#define USB_DT_CS_RADIO_CONTROL 35
#define USB_DT_CS_INTERFACE 36
#define USB_DT_SS_ENDPOINT_COMP 48
#define USB_DT_ENDPOINT_SIZE 7
#define USB_DT_ENDPOINT_AUDIO_SIZE 9
#define USB_TYPE_CLASS 32
#define USB_INTERFACE_CLASS_HID 3
#define USB_INTERFACE_CLASS_CCID 11
#define USB_CLASS_APP_SPEC 254
#define USB_SUBCLASS_DFU 1
#define USB_CLASS_COMM 2
#define USB_CLASS_VENDOR_SPEC 255
#define USB_CDC_SUBCLASS_ACM 2
#define USB_CDC_HEADER_TYPE 0
#define USB_CDC_CALL_MANAGEMENT_TYPE 1
#define USB_CDC_ACM_TYPE 2
#define USB_CDC_UNION_TYPE 6
#define USB_ENDPOINT_NUMBER_MASK 15
#define FFS_MAX_EPS_COUNT 31
#define FUNCTIONFS_EXPERIMENTAL_CDC_FUNCS (1U << 30)
#define FUNCTIONFS_HAS_FS_DESC 1
#define FUNCTIONFS_HAS_HS_DESC 2
#define FUNCTIONFS_HAS_SS_DESC 4
#define FUNCTIONFS_HAS_MS_OS_DESC 8
#define FUNCTIONFS_VIRTUAL_ADDR 16
#define FUNCTIONFS_EVENTFD 32
#define FUNCTIONFS_ALL_CTRL_RECIP 64
#define FUNCTIONFS_CONFIG0_SETUP 128
struct usb_descriptor_header { u8 bLength, bDescriptorType; };
struct usb_interface_descriptor { u8 bLength,bDescriptorType,bInterfaceNumber,bAlternateSetting,bNumEndpoints,bInterfaceClass,bInterfaceSubClass,bInterfaceProtocol,iInterface; };
struct usb_endpoint_descriptor { u8 bLength,bDescriptorType,bEndpointAddress,bmAttributes,wMaxPacketSize[2],bInterval; };
struct usb_interface_assoc_descriptor { u8 bLength,bDescriptorType,bFirstInterface,bInterfaceCount,bFunctionClass,bFunctionSubClass,bFunctionProtocol,iFunction; };
struct hid_descriptor { u8 bytes[9]; };
struct ccid_descriptor { u8 bytes[54]; };
struct usb_dfu_functional_descriptor { u8 bytes[9]; };
struct usb_otg_descriptor { u8 bytes[3]; };
struct usb_ss_ep_comp_descriptor { u8 bytes[6]; };
struct string_entry { u8 id; };
struct string_table { struct string_entry *strings; };
struct ffs_data { unsigned interfaces_count, eps_count, strings_count; u8 eps_addrmap[31]; struct string_table **stringtabs; };
struct ffs_ep { void *ep; struct usb_endpoint_descriptor *descs[2]; };
struct ffs_function { void *conf; int function; struct ffs_data *ffs; short *interfaces_nums; struct ffs_ep *eps; };
static int next_id, allocation_error;
static int usb_interface_id(void *conf, void *func) { (void)conf; (void)func; return allocation_error ? -ENOSPC : next_id++; }
static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); exit(1); } } while (0)

enum ffs_entity_type {
	FFS_DESCRIPTOR, FFS_INTERFACE, FFS_STRING, FFS_ENDPOINT,
	FFS_INTERFACE_REF
};

typedef int (*ffs_entity_callback)(enum ffs_entity_type,u8*,struct usb_descriptor_header*,void*);

struct ffs_desc_helper {
	struct ffs_data *ffs;
	unsigned interfaces_count;
	unsigned eps_count;
	bool interface_declared[256];
	bool interface_referenced[256];
};

static int stock_flags(unsigned flags) { return (flags & ~(FUNCTIONFS_HAS_FS_DESC |
			      FUNCTIONFS_HAS_HS_DESC |
			      FUNCTIONFS_HAS_SS_DESC |
			      FUNCTIONFS_HAS_MS_OS_DESC |
			      FUNCTIONFS_VIRTUAL_ADDR |
			      FUNCTIONFS_EVENTFD |
			      FUNCTIONFS_ALL_CTRL_RECIP |
			      FUNCTIONFS_CONFIG0_SETUP)) ? -ENOSYS : 0; }

static int patched_flags(unsigned flags) { return (flags & ~(FUNCTIONFS_HAS_FS_DESC |
			      FUNCTIONFS_HAS_HS_DESC |
			      FUNCTIONFS_HAS_SS_DESC |
			      FUNCTIONFS_HAS_MS_OS_DESC |
			      FUNCTIONFS_VIRTUAL_ADDR |
			      FUNCTIONFS_EVENTFD |
			      FUNCTIONFS_ALL_CTRL_RECIP |
			      FUNCTIONFS_CONFIG0_SETUP |
			      FUNCTIONFS_EXPERIMENTAL_CDC_FUNCS)) ? -ENOSYS : 0; }

static int __must_check stock_ffs_do_single_desc(char *data, unsigned len,
					   ffs_entity_callback entity,
					   void *priv, int *current_class, int *current_subclass)
{
	struct usb_descriptor_header *_ds = (void *)data;
	u8 length;
	int ret;

	/* At least two bytes are required: length and type */
	if (len < 2) {
		pr_vdebug("descriptor too short\n");
		return -EINVAL;
	}

	/* If we have at least as many bytes as the descriptor takes? */
	length = _ds->bLength;
	if (len < length) {
		pr_vdebug("descriptor longer then available data\n");
		return -EINVAL;
	}

#define __entity_check_INTERFACE(val)  1
#define __entity_check_STRING(val)     (val)
#define __entity_check_ENDPOINT(val)   ((val) & USB_ENDPOINT_NUMBER_MASK)
#define __entity(type, val) do {					\
		pr_vdebug("entity " #type "(%02x)\n", (val));		\
		if (!__entity_check_ ##type(val)) {			\
			pr_vdebug("invalid entity's value\n");		\
			return -EINVAL;					\
		}							\
		ret = entity(FFS_ ##type, &val, _ds, priv);		\
		if (ret < 0) {						\
			pr_debug("entity " #type "(%02x); ret = %d\n",	\
				 (val), ret);				\
			return ret;					\
		}							\
	} while (0)

	/* Parse descriptor depending on type. */
	switch (_ds->bDescriptorType) {
	case USB_DT_DEVICE:
	case USB_DT_CONFIG:
	case USB_DT_STRING:
	case USB_DT_DEVICE_QUALIFIER:
		/* function can't have any of those */
		pr_vdebug("descriptor reserved for gadget: %d\n",
		      _ds->bDescriptorType);
		return -EINVAL;

	case USB_DT_INTERFACE: {
		struct usb_interface_descriptor *ds = (void *)_ds;
		pr_vdebug("interface descriptor\n");
		if (length != sizeof *ds)
			goto inv_length;

		__entity(INTERFACE, ds->bInterfaceNumber);
		if (ds->iInterface)
			__entity(STRING, ds->iInterface);
		*current_class = ds->bInterfaceClass;
		*current_subclass = ds->bInterfaceSubClass;
	}
		break;

	case USB_DT_ENDPOINT: {
		struct usb_endpoint_descriptor *ds = (void *)_ds;
		pr_vdebug("endpoint descriptor\n");
		if (length != USB_DT_ENDPOINT_SIZE &&
		    length != USB_DT_ENDPOINT_AUDIO_SIZE)
			goto inv_length;
		__entity(ENDPOINT, ds->bEndpointAddress);
	}
		break;

	case USB_TYPE_CLASS | 0x01:
		if (*current_class == USB_INTERFACE_CLASS_HID) {
			pr_vdebug("hid descriptor\n");
			if (length != sizeof(struct hid_descriptor))
				goto inv_length;
			break;
		} else if (*current_class == USB_INTERFACE_CLASS_CCID) {
			pr_vdebug("ccid descriptor\n");
			if (length != sizeof(struct ccid_descriptor))
				goto inv_length;
			break;
		} else if (*current_class == USB_CLASS_APP_SPEC &&
			   *current_subclass == USB_SUBCLASS_DFU) {
			pr_vdebug("dfu functional descriptor\n");
			if (length != sizeof(struct usb_dfu_functional_descriptor))
				goto inv_length;
			break;
		} else {
			pr_vdebug("unknown descriptor: %d for class %d\n",
			      _ds->bDescriptorType, *current_class);
			return -EINVAL;
		}

	case USB_DT_OTG:
		if (length != sizeof(struct usb_otg_descriptor))
			goto inv_length;
		break;

	case USB_DT_INTERFACE_ASSOCIATION: {
		struct usb_interface_assoc_descriptor *ds = (void *)_ds;
		pr_vdebug("interface association descriptor\n");
		if (length != sizeof *ds)
			goto inv_length;
		if (ds->iFunction)
			__entity(STRING, ds->iFunction);
	}
		break;

	case USB_DT_SS_ENDPOINT_COMP:
		pr_vdebug("EP SS companion descriptor\n");
		if (length != sizeof(struct usb_ss_ep_comp_descriptor))
			goto inv_length;
		break;

	case USB_DT_OTHER_SPEED_CONFIG:
	case USB_DT_INTERFACE_POWER:
	case USB_DT_DEBUG:
	case USB_DT_SECURITY:
	case USB_DT_CS_RADIO_CONTROL:
		/* TODO */
		pr_vdebug("unimplemented descriptor: %d\n", _ds->bDescriptorType);
		return -EINVAL;

	default:
		/* We should never be here */
		pr_vdebug("unknown descriptor: %d\n", _ds->bDescriptorType);
		return -EINVAL;

inv_length:
		pr_vdebug("invalid length: %d (descriptor %d)\n",
			  _ds->bLength, _ds->bDescriptorType);
		return -EINVAL;
	}

#undef __entity
#undef __entity_check_DESCRIPTOR
#undef __entity_check_INTERFACE
#undef __entity_check_STRING
#undef __entity_check_ENDPOINT

	return length;
}

static int __must_check ffs_do_single_desc(char *data, unsigned len,
					   ffs_entity_callback entity,
					   void *priv, int *current_class, int *current_subclass,
					   unsigned flags)
{
	struct usb_descriptor_header *_ds = (void *)data;
	u8 length;
	int ret;

	/* At least two bytes are required: length and type */
	if (len < 2) {
		pr_vdebug("descriptor too short\n");
		return -EINVAL;
	}

	/* If we have at least as many bytes as the descriptor takes? */
	length = _ds->bLength;
	if (len < length) {
		pr_vdebug("descriptor longer then available data\n");
		return -EINVAL;
	}

#define __entity_check_INTERFACE(val)  1
#define __entity_check_INTERFACE_REF(val) 1
#define __entity_check_STRING(val)     (val)
#define __entity_check_ENDPOINT(val)   ((val) & USB_ENDPOINT_NUMBER_MASK)
#define __entity(type, val) do {					\
		pr_vdebug("entity " #type "(%02x)\n", (val));		\
		if (!__entity_check_ ##type(val)) {			\
			pr_vdebug("invalid entity's value\n");		\
			return -EINVAL;					\
		}							\
		ret = entity(FFS_ ##type, &val, _ds, priv);		\
		if (ret < 0) {						\
			pr_debug("entity " #type "(%02x); ret = %d\n",	\
				 (val), ret);				\
			return ret;					\
		}							\
	} while (0)

	/* Parse descriptor depending on type. */
	switch (_ds->bDescriptorType) {
	case USB_DT_DEVICE:
	case USB_DT_CONFIG:
	case USB_DT_STRING:
	case USB_DT_DEVICE_QUALIFIER:
		/* function can't have any of those */
		pr_vdebug("descriptor reserved for gadget: %d\n",
		      _ds->bDescriptorType);
		return -EINVAL;

	case USB_DT_INTERFACE: {
		struct usb_interface_descriptor *ds = (void *)_ds;
		pr_vdebug("interface descriptor\n");
		if (length != sizeof *ds)
			goto inv_length;

		__entity(INTERFACE, ds->bInterfaceNumber);
		if (ds->iInterface)
			__entity(STRING, ds->iInterface);
		*current_class = ds->bInterfaceClass;
		*current_subclass = ds->bInterfaceSubClass;
	}
		break;

	case USB_DT_ENDPOINT: {
		struct usb_endpoint_descriptor *ds = (void *)_ds;
		pr_vdebug("endpoint descriptor\n");
		if (length != USB_DT_ENDPOINT_SIZE &&
		    length != USB_DT_ENDPOINT_AUDIO_SIZE)
			goto inv_length;
		__entity(ENDPOINT, ds->bEndpointAddress);
	}
		break;

	case USB_DT_CS_INTERFACE: {
		u8 *d = (void *)_ds;
		unsigned i;

		/* Private opt-in: never reinterpret vendor descriptors by default. */
		if (!(flags & FUNCTIONFS_EXPERIMENTAL_CDC_FUNCS))
			return -EINVAL;
		if (!((*current_class == USB_CLASS_COMM &&
		       *current_subclass == USB_CDC_SUBCLASS_ACM) ||
		      (*current_class == USB_CLASS_VENDOR_SPEC &&
		       *current_subclass == 0)))
			return -EINVAL;
		if (length < 3)
			goto inv_length;

		switch (d[2]) {
		case USB_CDC_HEADER_TYPE:
			if (length != 5)
				goto inv_length;
			break;
		case USB_CDC_CALL_MANAGEMENT_TYPE:
			if (length != 5)
				goto inv_length;
			__entity(INTERFACE_REF, d[4]);
			break;
		case USB_CDC_ACM_TYPE:
			if (length != 4)
				goto inv_length;
			break;
		case USB_CDC_UNION_TYPE:
			if (length < 5)
				goto inv_length;
			for (i = 3; i < length; ++i)
				__entity(INTERFACE_REF, d[i]);
			break;
		default:
			return -EINVAL;
		}
		break;
	}

	case USB_TYPE_CLASS | 0x01:
		if (*current_class == USB_INTERFACE_CLASS_HID) {
			pr_vdebug("hid descriptor\n");
			if (length != sizeof(struct hid_descriptor))
				goto inv_length;
			break;
		} else if (*current_class == USB_INTERFACE_CLASS_CCID) {
			pr_vdebug("ccid descriptor\n");
			if (length != sizeof(struct ccid_descriptor))
				goto inv_length;
			break;
		} else if (*current_class == USB_CLASS_APP_SPEC &&
			   *current_subclass == USB_SUBCLASS_DFU) {
			pr_vdebug("dfu functional descriptor\n");
			if (length != sizeof(struct usb_dfu_functional_descriptor))
				goto inv_length;
			break;
		} else {
			pr_vdebug("unknown descriptor: %d for class %d\n",
			      _ds->bDescriptorType, *current_class);
			return -EINVAL;
		}

	case USB_DT_OTG:
		if (length != sizeof(struct usb_otg_descriptor))
			goto inv_length;
		break;

	case USB_DT_INTERFACE_ASSOCIATION: {
		struct usb_interface_assoc_descriptor *ds = (void *)_ds;
		pr_vdebug("interface association descriptor\n");
		if (length != sizeof *ds)
			goto inv_length;
		if (ds->iFunction)
			__entity(STRING, ds->iFunction);
	}
		break;

	case USB_DT_SS_ENDPOINT_COMP:
		pr_vdebug("EP SS companion descriptor\n");
		if (length != sizeof(struct usb_ss_ep_comp_descriptor))
			goto inv_length;
		break;

	case USB_DT_OTHER_SPEED_CONFIG:
	case USB_DT_INTERFACE_POWER:
	case USB_DT_DEBUG:
	case USB_DT_SECURITY:
	case USB_DT_CS_RADIO_CONTROL:
		/* TODO */
		pr_vdebug("unimplemented descriptor: %d\n", _ds->bDescriptorType);
		return -EINVAL;

	default:
		/* We should never be here */
		pr_vdebug("unknown descriptor: %d\n", _ds->bDescriptorType);
		return -EINVAL;

inv_length:
		pr_vdebug("invalid length: %d (descriptor %d)\n",
			  _ds->bLength, _ds->bDescriptorType);
		return -EINVAL;
	}

#undef __entity
#undef __entity_check_DESCRIPTOR
#undef __entity_check_INTERFACE
#undef __entity_check_INTERFACE_REF
#undef __entity_check_STRING
#undef __entity_check_ENDPOINT

	return length;
}

static int __must_check ffs_do_descs(unsigned count, char *data, unsigned len,
				     ffs_entity_callback entity, void *priv,
				     unsigned flags)
{
	const unsigned _len = len;
	unsigned long num = 0;
	int current_class = -1;
	int current_subclass = -1;

	for (;;) {
		int ret;

		if (num == count)
			data = NULL;

		/* Record "descriptor" entity */
		ret = entity(FFS_DESCRIPTOR, (u8 *)num, (void *)data, priv);
		if (ret < 0) {
			pr_debug("entity DESCRIPTOR(%02lx); ret = %d\n",
				 num, ret);
			return ret;
		}

		if (!data)
			return _len - len;

		ret = ffs_do_single_desc(data, len, entity, priv,
			&current_class, &current_subclass, flags);
		if (ret < 0) {
			pr_debug("%s returns %d\n", __func__, ret);
			return ret;
		}

		len -= ret;
		data += ret;
		++num;
	}
}

static int __ffs_data_do_entity(enum ffs_entity_type type,
				u8 *valuep, struct usb_descriptor_header *desc,
				void *priv)
{
	struct ffs_desc_helper *helper = priv;
	struct usb_endpoint_descriptor *d;
	unsigned i;

	switch (type) {
	case FFS_DESCRIPTOR:
		/* End of this speed: refs cannot invent an interface. */
		if (!desc)
			for (i = 0; i < 256; ++i)
				if (helper->interface_referenced[i] &&
				    !helper->interface_declared[i])
					return -EINVAL;
		break;

	case FFS_INTERFACE_REF:
		helper->interface_referenced[*valuep] = true;
		break;

	case FFS_INTERFACE:
		helper->interface_declared[*valuep] = true;
		/*
		 * Interfaces are indexed from zero so if we
		 * encountered interface "n" then there are at least
		 * "n+1" interfaces.
		 */
		if (*valuep >= helper->interfaces_count)
			helper->interfaces_count = *valuep + 1;
		break;

	case FFS_STRING:
		/*
		 * Strings are indexed from 1 (0 is reserved
		 * for languages list)
		 */
		if (*valuep > helper->ffs->strings_count)
			helper->ffs->strings_count = *valuep;
		break;

	case FFS_ENDPOINT:
		d = (void *)desc;
		helper->eps_count++;
		if (helper->eps_count >= FFS_MAX_EPS_COUNT)
			return -EINVAL;
		/* Check if descriptors for any speed were already parsed */
		if (!helper->ffs->eps_count && !helper->ffs->interfaces_count)
			helper->ffs->eps_addrmap[helper->eps_count] =
				d->bEndpointAddress;
		else if (helper->ffs->eps_addrmap[helper->eps_count] !=
				d->bEndpointAddress)
			return -EINVAL;
		break;
	}

	return 0;
}

static int __ffs_func_bind_do_nums(enum ffs_entity_type type, u8 *valuep,
				   struct usb_descriptor_header *desc,
				   void *priv)
{
	struct ffs_function *func = priv;
	unsigned idx;
	u8 newValue;

	switch (type) {
	default:
	case FFS_DESCRIPTOR:
		/* Handled in previous pass by __ffs_func_bind_do_descs() */
		return 0;

	case FFS_INTERFACE_REF:
	case FFS_INTERFACE:
		idx = *valuep;
		if (idx >= func->ffs->interfaces_count)
			return -EINVAL;
		if (type == FFS_INTERFACE_REF && func->interfaces_nums[idx] < 0)
			return -EINVAL;
		if (func->interfaces_nums[idx] < 0) {
			int id = usb_interface_id(func->conf, &func->function);
			if (id < 0)
				return id;
			func->interfaces_nums[idx] = id;
		}
		newValue = func->interfaces_nums[idx];
		break;

	case FFS_STRING:
		/* String' IDs are allocated when fsf_data is bound to cdev */
		newValue = func->ffs->stringtabs[0]->strings[*valuep - 1].id;
		break;

	case FFS_ENDPOINT:
		/*
		 * USB_DT_ENDPOINT are handled in
		 * __ffs_func_bind_do_descs().
		 */
		if (desc->bDescriptorType == USB_DT_ENDPOINT)
			return 0;

		idx = (*valuep & USB_ENDPOINT_NUMBER_MASK) - 1;
		if (!func->eps[idx].ep)
			return -EINVAL;

		{
			struct usb_endpoint_descriptor **descs;
			descs = func->eps[idx].descs;
			newValue = descs[descs[0] ? 0 : 1]->bEndpointAddress;
		}
		break;
	}

	pr_vdebug("%02x -> %02x\n", *valuep, newValue);
	*valuep = newValue;
	return 0;
}

static int __ffs_func_bind_do_interface_ids(enum ffs_entity_type type, u8 *valuep,
					 struct usb_descriptor_header *desc,
					 void *priv)
{
	u8 value;

	if (type != FFS_INTERFACE)
		return 0;
	value = *valuep;
	return __ffs_func_bind_do_nums(type, &value, desc, priv);
}

static const u8 exact_fs[] = {9,4,0,0,2,255,255,255,0,7,5,129,2,64,0,0,7,5,1,2,64,0,0,9,4,1,0,3,255,0,0,0,5,36,0,16,1,5,36,1,0,0,4,36,2,2,5,36,6,0,0,7,5,131,3,10,0,32,7,5,130,2,64,0,0,7,5,2,2,64,0,0,9,4,2,0,3,255,0,0,0,5,36,0,16,1,5,36,1,0,0,4,36,2,2,5,36,6,0,0,7,5,133,3,10,0,32,7,5,132,2,64,0,0,7,5,3,2,64,0,0,9,4,3,0,3,255,0,0,0,5,36,0,16,1,5,36,1,0,0,4,36,2,2,5,36,6,0,0,7,5,135,3,10,0,32,7,5,134,2,64,0,0,7,5,4,2,64,0,0,9,4,4,0,3,255,255,255,0,7,5,137,3,8,0,32,7,5,136,2,64,0,0,7,5,5,2,64,0,0};

static const u8 exact_hs[] = {9,4,0,0,2,255,255,255,0,7,5,129,2,0,2,0,7,5,1,2,0,2,0,9,4,1,0,3,255,0,0,0,5,36,0,16,1,5,36,1,0,0,4,36,2,2,5,36,6,0,0,7,5,131,3,10,0,9,7,5,130,2,0,2,0,7,5,2,2,0,2,0,9,4,2,0,3,255,0,0,0,5,36,0,16,1,5,36,1,0,0,4,36,2,2,5,36,6,0,0,7,5,133,3,10,0,9,7,5,132,2,0,2,0,7,5,3,2,0,2,0,9,4,3,0,3,255,0,0,0,5,36,0,16,1,5,36,1,0,0,4,36,2,2,5,36,6,0,0,7,5,135,3,10,0,9,7,5,134,2,0,2,0,7,5,4,2,0,2,0,9,4,4,0,3,255,255,255,0,7,5,137,3,8,0,9,7,5,136,2,0,2,0,7,5,5,2,0,2,0};


static int noop(enum ffs_entity_type type,u8 *value,struct usb_descriptor_header *desc,void *priv) {
    (void)type;(void)value;(void)desc;(void)priv;return 0;
}
static int reject_entity(enum ffs_entity_type type,u8 *value,struct usb_descriptor_header *desc,void *priv) {
    (void)type;(void)value;(void)desc;(void)priv;return -EACCES;
}
static int parse(u8 *data,unsigned length,unsigned count,struct ffs_desc_helper *helper,unsigned flags) {
    memset(helper->interface_declared,0,sizeof(helper->interface_declared));
    memset(helper->interface_referenced,0,sizeof(helper->interface_referenced));
    helper->interfaces_count=0;helper->eps_count=0;
    return ffs_do_descs(count,(char*)data,length,__ffs_data_do_entity,helper,flags);
}
static int remap(u8 *data,unsigned length,unsigned count,unsigned n,int first) {
    struct ffs_data ffs={.interfaces_count=n};
    short ids[256]; for(unsigned i=0;i<256;i++) ids[i]=-1;
    struct ffs_function func={.ffs=&ffs,.interfaces_nums=ids};
    next_id=first;
    int result=ffs_do_descs(count,(char*)data,length,__ffs_func_bind_do_interface_ids,&func,FUNCTIONFS_EXPERIMENTAL_CDC_FUNCS);
    if(result<0)return result;
    return ffs_do_descs(count,(char*)data,length,__ffs_func_bind_do_nums,&func,FUNCTIONFS_EXPERIMENTAL_CDC_FUNCS);
}
int main(void) {
    const unsigned flag=FUNCTIONFS_EXPERIMENTAL_CDC_FUNCS;
    CHECK(stock_flags(3)==0);
    CHECK(stock_flags(3|flag)==-ENOSYS);
    CHECK(patched_flags(3|flag)==0);
    CHECK(patched_flags(3|flag|(1U<<29))==-ENOSYS);
    u8 cdc[][6]={{5,36,0,16,1,0},{5,36,1,0,0,0},{4,36,2,2,0,0},{5,36,6,0,0,0}};
    for(unsigned i=0;i<4;i++) {
        int cls=255,sub=0;
        CHECK(stock_ffs_do_single_desc((char*)cdc[i],cdc[i][0],noop,NULL,&cls,&sub)==-EINVAL);
        CHECK(ffs_do_single_desc((char*)cdc[i],cdc[i][0],noop,NULL,&cls,&sub,0)==-EINVAL);
        CHECK(ffs_do_single_desc((char*)cdc[i],cdc[i][0],noop,NULL,&cls,&sub,flag)==cdc[i][0]);
        for(unsigned length=0;length<cdc[i][0];length++)
            CHECK(ffs_do_single_desc((char*)cdc[i],length,noop,NULL,&cls,&sub,flag)==-EINVAL);
        u8 malformed[6];memcpy(malformed,cdc[i],6);malformed[0]=cdc[i][0]-1;
        CHECK(ffs_do_single_desc((char*)malformed,6,noop,NULL,&cls,&sub,flag)==-EINVAL);
        if(i!=3) {malformed[0]=cdc[i][0]+1;CHECK(ffs_do_single_desc((char*)malformed,6,noop,NULL,&cls,&sub,flag)==-EINVAL);}
    }
    int cls=-1,sub=-1;
    CHECK(ffs_do_single_desc((char*)cdc[0],5,noop,NULL,&cls,&sub,flag)==-EINVAL);
    cls=3;sub=0;CHECK(ffs_do_single_desc((char*)cdc[0],5,noop,NULL,&cls,&sub,flag)==-EINVAL);
    cls=2;sub=2;CHECK(ffs_do_single_desc((char*)cdc[0],5,noop,NULL,&cls,&sub,flag)==5);
    cls=255;sub=0;u8 unknown[]={3,36,99};
    CHECK(ffs_do_single_desc((char*)unknown,3,noop,NULL,&cls,&sub,flag)==-EINVAL);
    CHECK(ffs_do_single_desc((char*)cdc[1],5,reject_entity,NULL,&cls,&sub,flag)==-EACCES);

    struct ffs_data ffs={0};struct ffs_desc_helper helper={.ffs=&ffs};
    for(unsigned speed=0;speed<2;speed++) {
        u8 copy[200];memcpy(copy,speed?exact_hs:exact_fs,200);
        CHECK(parse(copy,200,31,&helper,0)==-EINVAL);
        CHECK(parse(copy,200,31,&helper,flag)==200);
        CHECK(helper.interfaces_count==5 && helper.eps_count==14);
        CHECK(memcmp(copy,speed?exact_hs:exact_fs,200)==0);
        CHECK(remap(copy,200,31,5,0)==200);
        CHECK(memcmp(copy,speed?exact_hs:exact_fs,200)==0);
    }
    u8 forward[]={9,4,0,0,0,255,0,0,0, 5,36,1,0,1, 9,4,1,0,0,255,0,0,0};
    CHECK(parse(forward,sizeof(forward),3,&helper,flag)==sizeof(forward));
    CHECK(helper.interfaces_count==2);
    CHECK(remap(forward,sizeof(forward),3,2,7)==sizeof(forward));
    CHECK(forward[2]==7 && forward[13]==8 && forward[16]==8);
    u8 invalid[]={9,4,0,0,0,255,0,0,0, 5,36,1,0,2};
    CHECK(parse(invalid,sizeof(invalid),2,&helper,flag)==-EINVAL);
    CHECK(helper.interfaces_count==1); /* reference 2 did not invent interfaces */
    /* A declaration from the preceding speed cannot validate this stream. */
    helper.interface_declared[2]=true;
    CHECK(parse(invalid,sizeof(invalid),2,&helper,flag)==-EINVAL);

    u8 multi[]={9,4,0,0,0,255,0,0,0, 6,36,6,0,1,2,
                9,4,1,0,0,255,0,0,0, 9,4,2,0,0,255,0,0,0};
    CHECK(parse(multi,sizeof(multi),4,&helper,flag)==sizeof(multi));
    u8 before[sizeof(multi)];memcpy(before,multi,sizeof(multi));
    allocation_error=1;CHECK(remap(multi,sizeof(multi),4,3,7)==-ENOSPC);
    CHECK(memcmp(multi,before,sizeof(multi))==0);allocation_error=0;
    CHECK(remap(multi,sizeof(multi),4,3,7)==sizeof(multi));
    CHECK(multi[12]==7 && multi[13]==8 && multi[14]==9);
    struct ffs_data small={.interfaces_count=1};short ids[]={-1};
    struct ffs_function func={.ffs=&small,.interfaces_nums=ids};u8 value=2;
    CHECK(__ffs_func_bind_do_nums(FFS_INTERFACE_REF,&value,NULL,&func)==-EINVAL);
    value=0;CHECK(__ffs_func_bind_do_nums(FFS_INTERFACE_REF,&value,NULL,&func)==-EINVAL);
    CHECK(__ffs_func_bind_do_interface_ids(FFS_INTERFACE_REF,&value,NULL,&func)==0);
    printf("{\"status\":\"PASS\",\"checks\":%u,\"hardware\":false,\"full_kernel_build\":false}\n",checks);
    return 0;
}
