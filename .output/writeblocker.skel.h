/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED! */
#ifndef __WRITEBLOCKER_BPF_SKEL_H__
#define __WRITEBLOCKER_BPF_SKEL_H__

#include <stdlib.h>
#include <bpf/libbpf.h>

struct writeblocker_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *rb;
		struct bpf_map *rodata;
	} maps;
	struct {
		struct bpf_program *fake_write;
	} progs;
	struct {
		struct bpf_link *fake_write;
	} links;
	struct writeblocker_bpf__rodata {
		int target_pid;
	} *rodata;
};

static void
writeblocker_bpf__destroy(struct writeblocker_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
writeblocker_bpf__create_skeleton(struct writeblocker_bpf *obj);

static inline struct writeblocker_bpf *
writeblocker_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct writeblocker_bpf *obj;

	obj = (struct writeblocker_bpf *)calloc(1, sizeof(*obj));
	if (!obj)
		return NULL;
	if (writeblocker_bpf__create_skeleton(obj))
		goto err;
	if (bpf_object__open_skeleton(obj->skeleton, opts))
		goto err;

	return obj;
err:
	writeblocker_bpf__destroy(obj);
	return NULL;
}

static inline struct writeblocker_bpf *
writeblocker_bpf__open(void)
{
	return writeblocker_bpf__open_opts(NULL);
}

static inline int
writeblocker_bpf__load(struct writeblocker_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct writeblocker_bpf *
writeblocker_bpf__open_and_load(void)
{
	struct writeblocker_bpf *obj;

	obj = writeblocker_bpf__open();
	if (!obj)
		return NULL;
	if (writeblocker_bpf__load(obj)) {
		writeblocker_bpf__destroy(obj);
		return NULL;
	}
	return obj;
}

static inline int
writeblocker_bpf__attach(struct writeblocker_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
writeblocker_bpf__detach(struct writeblocker_bpf *obj)
{
	return bpf_object__detach_skeleton(obj->skeleton);
}

static inline int
writeblocker_bpf__create_skeleton(struct writeblocker_bpf *obj)
{
	struct bpf_object_skeleton *s;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)
		return -1;
	obj->skeleton = s;

	s->sz = sizeof(*s);
	s->name = "writeblocker_bpf";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 2;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps)
		goto err;

	s->maps[0].name = "rb";
	s->maps[0].map = &obj->maps.rb;

	s->maps[1].name = "writeblo.rodata";
	s->maps[1].map = &obj->maps.rodata;
	s->maps[1].mmaped = (void **)&obj->rodata;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs)
		goto err;

	s->progs[0].name = "fake_write";
	s->progs[0].prog = &obj->progs.fake_write;
	s->progs[0].link = &obj->links.fake_write;

	s->data_sz = 4344;
	s->data = (void *)"\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x38\x0d\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x0f\0\
\x0e\0\xb7\x08\0\0\0\0\0\0\x79\x17\0\0\0\0\0\0\x85\0\0\0\x0e\0\0\0\x18\x01\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x61\x11\0\0\0\0\0\0\x77\0\0\0\x20\0\0\0\x5d\x01\x34\0\
\0\0\0\0\x79\x76\x60\0\0\0\0\0\x79\x77\x70\0\0\0\0\0\xbf\x71\0\0\0\0\0\0\x67\
\x01\0\0\x20\0\0\0\x77\x01\0\0\x20\0\0\0\xb7\x02\0\0\x03\0\0\0\x2d\x12\x2d\0\0\
\0\0\0\xb7\x01\0\0\x0a\0\0\0\x6b\x1a\xf8\xff\0\0\0\0\x18\x01\0\0\x63\x6f\x75\
\x6e\0\0\0\0\x74\x3d\x25\x64\x7b\x1a\xf0\xff\0\0\0\0\x18\x01\0\0\x20\x66\x64\
\x3d\0\0\0\0\x25\x64\x3b\x20\x7b\x1a\xe8\xff\0\0\0\0\x18\x01\0\0\x20\x70\x69\
\x64\0\0\0\0\x3d\x25\x64\x3b\x7b\x1a\xe0\xff\0\0\0\0\x18\x01\0\0\x72\x69\x74\
\x65\0\0\0\0\x20\x66\x6f\x72\x7b\x1a\xd8\xff\0\0\0\0\x18\x01\0\0\x46\x61\x6b\
\x69\0\0\0\0\x6e\x67\x20\x77\x7b\x1a\xd0\xff\0\0\0\0\x18\x01\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x61\x13\0\0\0\0\0\0\xbf\xa1\0\0\0\0\0\0\x07\x01\0\0\xd0\xff\xff\xff\
\xb7\x02\0\0\x2a\0\0\0\xbf\x74\0\0\0\0\0\0\xbf\x65\0\0\0\0\0\0\x85\0\0\0\x06\0\
\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\0\x18\0\0\0\xb7\x03\0\0\0\0\
\0\0\x85\0\0\0\x83\0\0\0\xbf\x09\0\0\0\0\0\0\xbf\x68\0\0\0\0\0\0\x15\x09\x0b\0\
\0\0\0\0\x63\x79\0\0\0\0\0\0\xb7\x01\0\0\x01\0\0\0\x73\x19\x14\0\0\0\0\0\xbf\
\x91\0\0\0\0\0\0\x07\x01\0\0\x04\0\0\0\xb7\x02\0\0\x10\0\0\0\x85\0\0\0\x10\0\0\
\0\xbf\x91\0\0\0\0\0\0\xb7\x02\0\0\0\0\0\0\x85\0\0\0\x84\0\0\0\xbf\x68\0\0\0\0\
\0\0\xbf\x80\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x44\x75\x61\x6c\x20\x42\x53\x44\x2f\
\x47\x50\x4c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x46\x61\
\x6b\x69\x6e\x67\x20\x77\x72\x69\x74\x65\x20\x66\x6f\x72\x20\x70\x69\x64\x3d\
\x25\x64\x3b\x20\x66\x64\x3d\x25\x64\x3b\x20\x63\x6f\x75\x6e\x74\x3d\x25\x64\
\x0a\0\x9f\xeb\x01\0\x18\0\0\0\0\0\0\0\x98\x02\0\0\x98\x02\0\0\x32\x03\0\0\0\0\
\0\0\0\0\0\x02\x03\0\0\0\x01\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\x01\0\0\0\0\0\0\
\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x1b\0\0\0\x05\0\0\0\0\0\0\x01\x04\0\0\0\x20\
\0\0\0\0\0\0\0\0\0\0\x02\x06\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\
\0\0\0\x04\0\0\0\0\0\x02\0\0\x04\x10\0\0\0\x19\0\0\0\x01\0\0\0\0\0\0\0\x1e\0\0\
\0\x05\0\0\0\x40\0\0\0\x2a\0\0\0\0\0\0\x0e\x07\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\
\x02\x0a\0\0\0\x2d\0\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\0\0\0\0\0\x01\0\0\x0d\x02\
\0\0\0\x44\0\0\0\x09\0\0\0\x48\0\0\0\x01\0\0\x0c\x0b\0\0\0\x1b\x01\0\0\x15\0\0\
\x04\xa8\0\0\0\x23\x01\0\0\x0e\0\0\0\0\0\0\0\x27\x01\0\0\x0e\0\0\0\x40\0\0\0\
\x2b\x01\0\0\x0e\0\0\0\x80\0\0\0\x2f\x01\0\0\x0e\0\0\0\xc0\0\0\0\x33\x01\0\0\
\x0e\0\0\0\0\x01\0\0\x36\x01\0\0\x0e\0\0\0\x40\x01\0\0\x39\x01\0\0\x0e\0\0\0\
\x80\x01\0\0\x3d\x01\0\0\x0e\0\0\0\xc0\x01\0\0\x41\x01\0\0\x0e\0\0\0\0\x02\0\0\
\x44\x01\0\0\x0e\0\0\0\x40\x02\0\0\x47\x01\0\0\x0e\0\0\0\x80\x02\0\0\x4a\x01\0\
\0\x0e\0\0\0\xc0\x02\0\0\x4d\x01\0\0\x0e\0\0\0\0\x03\0\0\x50\x01\0\0\x0e\0\0\0\
\x40\x03\0\0\x53\x01\0\0\x0e\0\0\0\x80\x03\0\0\x56\x01\0\0\x0e\0\0\0\xc0\x03\0\
\0\x5e\x01\0\0\x0e\0\0\0\0\x04\0\0\x61\x01\0\0\x0e\0\0\0\x40\x04\0\0\x64\x01\0\
\0\x0e\0\0\0\x80\x04\0\0\x6a\x01\0\0\x0e\0\0\0\xc0\x04\0\0\x6d\x01\0\0\x0e\0\0\
\0\0\x05\0\0\x70\x01\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\0\x04\x03\0\0\0\0\0\x01\
\x01\0\0\0\x08\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x0f\0\0\0\x04\0\0\0\x0d\0\0\0\
\x09\x03\0\0\0\0\0\x0e\x10\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x0a\x13\0\0\0\0\0\0\0\
\0\0\0\x09\x02\0\0\0\x11\x03\0\0\0\0\0\x0e\x12\0\0\0\x01\0\0\0\x1c\x03\0\0\x01\
\0\0\x0f\0\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\x22\x03\0\0\x01\0\0\x0f\0\0\0\0\
\x14\0\0\0\0\0\0\0\x04\0\0\0\x2a\x03\0\0\x01\0\0\x0f\0\0\0\0\x11\0\0\0\0\0\0\0\
\x0d\0\0\0\0\x69\x6e\x74\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\
\x54\x59\x50\x45\x5f\x5f\0\x74\x79\x70\x65\0\x6d\x61\x78\x5f\x65\x6e\x74\x72\
\x69\x65\x73\0\x72\x62\0\x6c\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\x20\x75\x6e\x73\
\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x63\x74\x78\0\x66\x61\x6b\x65\x5f\x77\
\x72\x69\x74\x65\0\x66\x6d\x6f\x64\x5f\x72\x65\x74\x2f\x5f\x5f\x78\x36\x34\x5f\
\x73\x79\x73\x5f\x77\x72\x69\x74\x65\0\x2f\x68\x6f\x6d\x65\x2f\x62\x65\x6e\x6a\
\x69\x2f\x44\x65\x73\x6b\x74\x6f\x70\x2f\x62\x61\x64\x2d\x62\x70\x66\x2f\x73\
\x72\x63\x2f\x77\x72\x69\x74\x65\x62\x6c\x6f\x63\x6b\x65\x72\x2e\x62\x70\x66\
\x2e\x63\0\x69\x6e\x74\x20\x42\x50\x46\x5f\x50\x52\x4f\x47\x28\x66\x61\x6b\x65\
\x5f\x77\x72\x69\x74\x65\x2c\x20\x73\x74\x72\x75\x63\x74\x20\x70\x74\x5f\x72\
\x65\x67\x73\x20\x2a\x72\x65\x67\x73\x29\0\x20\x20\x20\x20\x69\x6e\x74\x20\x70\
\x69\x64\x20\x3d\x20\x62\x70\x66\x5f\x67\x65\x74\x5f\x63\x75\x72\x72\x65\x6e\
\x74\x5f\x70\x69\x64\x5f\x74\x67\x69\x64\x28\x29\x20\x3e\x3e\x20\x33\x32\x3b\0\
\x20\x20\x20\x20\x69\x66\x20\x28\x70\x69\x64\x20\x21\x3d\x20\x74\x61\x72\x67\
\x65\x74\x5f\x70\x69\x64\x29\x20\x7b\0\x70\x74\x5f\x72\x65\x67\x73\0\x72\x31\
\x35\0\x72\x31\x34\0\x72\x31\x33\0\x72\x31\x32\0\x62\x70\0\x62\x78\0\x72\x31\
\x31\0\x72\x31\x30\0\x72\x39\0\x72\x38\0\x61\x78\0\x63\x78\0\x64\x78\0\x73\x69\
\0\x64\x69\0\x6f\x72\x69\x67\x5f\x61\x78\0\x69\x70\0\x63\x73\0\x66\x6c\x61\x67\
\x73\0\x73\x70\0\x73\x73\0\x6c\x6f\x6e\x67\x20\x75\x6e\x73\x69\x67\x6e\x65\x64\
\x20\x69\x6e\x74\0\x30\x3a\x31\x32\0\x20\x20\x20\x20\x75\x33\x32\x20\x63\x6f\
\x75\x6e\x74\x20\x3d\x20\x50\x54\x5f\x52\x45\x47\x53\x5f\x50\x41\x52\x4d\x33\
\x28\x72\x65\x67\x73\x29\x3b\0\x30\x3a\x31\x34\0\x20\x20\x20\x20\x75\x33\x32\
\x20\x66\x64\x20\x3d\x20\x50\x54\x5f\x52\x45\x47\x53\x5f\x50\x41\x52\x4d\x31\
\x28\x72\x65\x67\x73\x29\x3b\0\x20\x20\x20\x20\x69\x66\x20\x28\x66\x64\x20\x3c\
\x3d\x20\x32\x29\x20\x7b\0\x20\x20\x20\x20\x62\x70\x66\x5f\x70\x72\x69\x6e\x74\
\x6b\x28\x22\x46\x61\x6b\x69\x6e\x67\x20\x77\x72\x69\x74\x65\x20\x66\x6f\x72\
\x20\x70\x69\x64\x3d\x25\x64\x3b\x20\x66\x64\x3d\x25\x64\x3b\x20\x63\x6f\x75\
\x6e\x74\x3d\x25\x64\x5c\x6e\x22\x2c\x20\x74\x61\x72\x67\x65\x74\x5f\x70\x69\
\x64\x2c\x20\x66\x64\x2c\x20\x63\x6f\x75\x6e\x74\x29\x3b\0\x20\x20\x20\x20\x65\
\x20\x3d\x20\x62\x70\x66\x5f\x72\x69\x6e\x67\x62\x75\x66\x5f\x72\x65\x73\x65\
\x72\x76\x65\x28\x26\x72\x62\x2c\x20\x73\x69\x7a\x65\x6f\x66\x28\x2a\x65\x29\
\x2c\x20\x30\x29\x3b\0\x20\x20\x20\x20\x69\x66\x20\x28\x65\x29\x20\x7b\0\x20\
\x20\x20\x20\x20\x20\x20\x20\x65\x2d\x3e\x70\x69\x64\x20\x3d\x20\x66\x64\x3b\0\
\x20\x20\x20\x20\x20\x20\x20\x20\x65\x2d\x3e\x73\x75\x63\x63\x65\x73\x73\x20\
\x3d\x20\x74\x72\x75\x65\x3b\0\x20\x20\x20\x20\x20\x20\x20\x20\x62\x70\x66\x5f\
\x67\x65\x74\x5f\x63\x75\x72\x72\x65\x6e\x74\x5f\x63\x6f\x6d\x6d\x28\x26\x65\
\x2d\x3e\x63\x6f\x6d\x6d\x2c\x20\x73\x69\x7a\x65\x6f\x66\x28\x65\x2d\x3e\x63\
\x6f\x6d\x6d\x29\x29\x3b\0\x20\x20\x20\x20\x20\x20\x20\x20\x62\x70\x66\x5f\x72\
\x69\x6e\x67\x62\x75\x66\x5f\x73\x75\x62\x6d\x69\x74\x28\x65\x2c\x20\x30\x29\
\x3b\0\x63\x68\x61\x72\0\x4c\x49\x43\x45\x4e\x53\x45\0\x74\x61\x72\x67\x65\x74\
\x5f\x70\x69\x64\0\x2e\x6d\x61\x70\x73\0\x2e\x72\x6f\x64\x61\x74\x61\0\x6c\x69\
\x63\x65\x6e\x73\x65\0\x9f\xeb\x01\0\x20\0\0\0\0\0\0\0\x14\0\0\0\x14\0\0\0\x4c\
\x01\0\0\x60\x01\0\0\x2c\0\0\0\x08\0\0\0\x53\0\0\0\x01\0\0\0\0\0\0\0\x0c\0\0\0\
\x10\0\0\0\x53\0\0\0\x14\0\0\0\0\0\0\0\x6c\0\0\0\x9f\0\0\0\0\x50\0\0\x08\0\0\0\
\x6c\0\0\0\x9f\0\0\0\x05\x50\0\0\x10\0\0\0\x6c\0\0\0\xce\0\0\0\x0f\x58\0\0\x18\
\0\0\0\x6c\0\0\0\xfe\0\0\0\x10\x5c\0\0\x30\0\0\0\x6c\0\0\0\xce\0\0\0\x2a\x58\0\
\0\x38\0\0\0\x6c\0\0\0\xfe\0\0\0\x09\x5c\0\0\x40\0\0\0\x6c\0\0\0\x87\x01\0\0\
\x11\x78\0\0\x48\0\0\0\x6c\0\0\0\xb1\x01\0\0\x0e\x74\0\0\x70\0\0\0\x6c\0\0\0\
\xd3\x01\0\0\x09\x7c\0\0\x80\0\0\0\x6c\0\0\0\xe6\x01\0\0\x05\x94\0\0\x48\x01\0\
\0\x6c\0\0\0\x3b\x02\0\0\x09\x98\0\0\x78\x01\0\0\x6c\0\0\0\0\0\0\0\0\0\0\0\x80\
\x01\0\0\x6c\0\0\0\x6c\x02\0\0\x09\x9c\0\0\x88\x01\0\0\x6c\0\0\0\x79\x02\0\0\
\x10\xa8\0\0\x98\x01\0\0\x6c\0\0\0\x8e\x02\0\0\x14\xa0\0\0\xa0\x01\0\0\x6c\0\0\
\0\xa9\x02\0\0\x22\xac\0\0\xb0\x01\0\0\x6c\0\0\0\xa9\x02\0\0\x09\xac\0\0\xc0\
\x01\0\0\x6c\0\0\0\xe2\x02\0\0\x09\xb0\0\0\xd8\x01\0\0\x6c\0\0\0\0\0\0\0\0\0\0\
\0\xe0\x01\0\0\x6c\0\0\0\x9f\0\0\0\x05\x50\0\0\x10\0\0\0\x53\0\0\0\x02\0\0\0\
\x40\0\0\0\x0d\0\0\0\x82\x01\0\0\0\0\0\0\x48\0\0\0\x0d\0\0\0\xac\x01\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x8f\0\0\0\0\0\x02\0\xe0\x01\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x87\0\0\0\x11\0\x03\0\0\0\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\x45\0\0\0\x12\0\x02\
\0\0\0\0\0\0\0\0\0\xf0\x01\0\0\0\0\0\0\x63\0\0\0\x11\0\x05\0\0\0\0\0\0\0\0\0\
\x10\0\0\0\0\0\0\0\x58\0\0\0\x11\0\x04\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\x18\
\0\0\0\0\0\0\0\x01\0\0\0\x06\0\0\0\0\x01\0\0\0\0\0\0\x01\0\0\0\x06\0\0\0\x48\
\x01\0\0\0\0\0\0\x01\0\0\0\x05\0\0\0\x78\x02\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\x90\
\x02\0\0\0\0\0\0\x0a\0\0\0\x06\0\0\0\xa8\x02\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\x2c\
\0\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\x50\0\0\0\
\0\0\0\0\0\0\0\0\x02\0\0\0\x60\0\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\x70\0\0\0\0\0\0\
\0\0\0\0\0\x02\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\x90\0\0\0\0\0\0\0\0\0\
\0\0\x02\0\0\0\xa0\0\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\xb0\0\0\0\0\0\0\0\0\0\0\0\
\x02\0\0\0\xc0\0\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\xd0\0\0\0\0\0\0\0\0\0\0\0\x02\0\
\0\0\xe0\0\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\xf0\0\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\0\
\x01\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\x10\x01\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\x20\
\x01\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\x30\x01\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\x40\
\x01\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\x50\x01\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\x60\
\x01\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\x70\x01\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\x8c\
\x01\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\x9c\x01\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\x46\
\x45\x48\x47\0\x2e\x74\x65\x78\x74\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\x2e\x65\
\x78\x74\0\x2e\x6d\x61\x70\x73\0\x2e\x6c\x6c\x76\x6d\x5f\x61\x64\x64\x72\x73\
\x69\x67\0\x2e\x72\x65\x6c\x66\x6d\x6f\x64\x5f\x72\x65\x74\x2f\x5f\x5f\x78\x36\
\x34\x5f\x73\x79\x73\x5f\x77\x72\x69\x74\x65\0\x66\x61\x6b\x65\x5f\x77\x72\x69\
\x74\x65\0\x6c\x69\x63\x65\x6e\x73\x65\0\x74\x61\x72\x67\x65\x74\x5f\x70\x69\
\x64\0\x72\x62\0\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\x74\x61\x62\0\
\x2e\x72\x6f\x64\x61\x74\x61\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\0\x4c\x49\x43\
\x45\x4e\x53\x45\0\x4c\x42\x42\x30\x5f\x34\0\x2e\x72\x6f\x64\x61\x74\x61\x2e\
\x73\x74\x72\x31\x2e\x31\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x2c\0\
\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\xf0\x01\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x50\0\0\0\x01\0\0\0\
\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x30\x02\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x76\0\0\0\x01\0\0\0\x02\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x40\x02\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x14\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x48\x02\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x96\0\0\0\x01\0\0\0\x32\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x58\x02\
\0\0\0\0\0\0\x2a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\
\0\0\x82\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x82\x02\0\0\0\0\0\0\
\xe2\x05\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0b\0\0\
\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x64\x08\0\0\0\0\0\0\xac\x01\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x6e\0\0\0\x02\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x10\x0a\0\0\0\0\0\0\xa8\0\0\0\0\0\0\0\x0e\0\0\0\
\x03\0\0\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0\x28\0\0\0\x09\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\xb8\x0a\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\x09\0\0\0\x02\0\0\0\
\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x7e\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\xe8\x0a\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\x09\0\0\0\x07\0\0\0\x08\0\0\0\
\0\0\0\0\x10\0\0\0\0\0\0\0\x07\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x18\x0b\0\0\0\0\0\0\x70\x01\0\0\0\0\0\0\x09\0\0\0\x08\0\0\0\x08\0\0\0\0\0\0\0\
\x10\0\0\0\0\0\0\0\x1a\0\0\0\x03\x4c\xff\x6f\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\
\x88\x0c\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x66\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x8c\x0c\0\0\0\0\
\0\0\xa5\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return -1;
}

#endif /* __WRITEBLOCKER_BPF_SKEL_H__ */