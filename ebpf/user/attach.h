/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FF_ATTACH_H
#define FF_ATTACH_H
#include "fakeflow.h"
#include <bpf/libbpf.h>
struct ff_attachment { unsigned index, point, priority, handle, id; };
int ff_attach(unsigned index,enum bpf_tc_attach_point point,int fd,unsigned priority,struct ff_attachment *record);
void ff_detach(const struct ff_attachment *record);
int ff_link(const char *name,unsigned mode,unsigned *index,unsigned *mtu);
int ff_command(const char *const argv[]);
int ff_dummy(char *name,size_t cap);
int ff_tun(char *name,size_t cap);
int ff_priority_available(const char *name,const char *direction);
#endif
