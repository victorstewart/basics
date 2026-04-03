// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cstring>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

#include <includes.h>
#include <types/types.containers.h>

/*
struct bpf_prog_info {
	__u32 type;
	__u32 id;
	__u8  tag[BPF_TAG_SIZE];
	__u32 jited_prog_len;
	__u32 xlated_prog_len;
	__aligned_u64 jited_prog_insns;
	__aligned_u64 xlated_prog_insns;
	__u64 load_time;	//ns since boottime
	__u32 created_by_uid;
	__u32 nr_map_ids;
	__aligned_u64 map_ids; // pointer
	char name[BPF_OBJ_NAME_LEN];
	__u32 ifindex;
	__u32 gpl_compatible:1;
	__u32 :31; // alignment pad
	__u64 netns_dev;
	__u64 netns_ino;
	__u32 nr_jited_ksyms;
	__u32 nr_jited_func_lens;
	__aligned_u64 jited_ksyms;
	__aligned_u64 jited_func_lens;
	__u32 btf_id;
	__u32 func_info_rec_size;
	__aligned_u64 func_info;
	__u32 nr_func_info;
	__u32 nr_line_info;
	__aligned_u64 line_info;
	__aligned_u64 jited_line_info;
	__u32 nr_jited_line_info;
	__u32 line_info_rec_size;
	__u32 jited_line_info_rec_size;
	__u32 nr_prog_tags;
	__aligned_u64 prog_tags;
	__u64 run_time_ns;
	__u64 run_cnt;
	__u64 recursion_misses;
	__u32 verified_insns;
	__u32 attach_btf_obj_id;
	__u32 attach_btf_id;
} __attribute__((aligned(8)));

struct bpf_map_info {
	__u32 type;
	__u32 id;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	char  name[BPF_OBJ_NAME_LEN];
	__u32 ifindex;
	__u32 btf_vmlinux_value_type_id;
	__u64 netns_dev;
	__u64 netns_ino;
	__u32 btf_id;
	__u32 btf_key_type_id;
	__u32 btf_value_type_id;
	__u32 btf_vmlinux_id;
	__u64 map_extra;
} __attribute__((aligned(8)));

*/

class BPFProgram {
private:

	int attachidx = -1;
	enum bpf_attach_type attachtype = static_cast<enum bpf_attach_type>(0);
	bool progFDOwnedByObject = false;

	struct PreattachedMapFD
	{
		char name[BPF_OBJ_NAME_LEN];
		int fd;
	};

	std::vector<PreattachedMapFD> preattachedMapFDs;

	void closePreattachedMapFDs(void)
	{
		for (PreattachedMapFD& preattachedMap : preattachedMapFDs)
		{
			if (preattachedMap.fd >= 0)
			{
				::close(preattachedMap.fd);
				preattachedMap.fd = -1;
			}
		}

		preattachedMapFDs.clear();
	}

public:

	BPFProgram() = default;
	BPFProgram(const BPFProgram&) = delete;
	BPFProgram& operator=(const BPFProgram&) = delete;
	BPFProgram(BPFProgram&&) = delete;
	BPFProgram& operator=(BPFProgram&&) = delete;

	~BPFProgram()
	{
		close();
	}

	static void removeAllZombies(void)
	{
		uint32_t next_id = 0;

	   while (bpf_prog_get_next_id(next_id, &next_id) == 0) 
	   {
	      int prog_fd = bpf_prog_get_fd_by_id(next_id);

			struct bpf_prog_info prog_info;
			uint32_t len = sizeof(struct bpf_prog_info);
			memset(&prog_info, 0, len);

			int result = bpf_prog_get_info_by_fd(prog_fd, &prog_info, &len);
			(void)result;
			
			// and we can't extract the attach type, i don't think?, so also need to hardcode that
			enum bpf_attach_type attach_type;

			if (auto ingress_stub = "observer_tcx_in"_ctv; memcmp(prog_info.name, ingress_stub.data(), ingress_stub.size()) == 0)
			{
				attach_type = BPF_TCX_INGRESS;
			}
			else if (auto egress_stub = "observer_tcx_eg"_ctv; memcmp(prog_info.name, egress_stub.data(), egress_stub.size()) == 0)
			{
				attach_type = BPF_TCX_EGRESS;
			}
			else
			{
				::close(prog_fd);
				continue;
			}

			// prog_info.ifindex is 0 so hardcoded it to eno1
			int ifidx = 3; // eno1

			int detach_result = bpf_prog_detach_opts(prog_fd, ifidx, attach_type, nullptr);
			(void)detach_result;

			::close(prog_fd);
	   }
	}

	struct bpf_object *obj = nullptr;
	struct bpf_program *prog = nullptr;
	int prog_fd = -1;

	bool loadPreattached(enum bpf_attach_type progtype, uint32_t prog_id, StringType auto&& progpath)
	{
		close();

		prog_fd = bpf_prog_get_fd_by_id(prog_id);

		if (prog_fd < 0) 
		{
			return false;
		}

		struct bpf_prog_info prog_info = {};
		uint32_t info_len = sizeof(prog_info);

		if (bpf_prog_get_info_by_fd(prog_fd, &prog_info, &info_len) != 0)
		{
			close();
			return false;
		}

		if (prog_info.nr_map_ids > 0)
		{
			std::vector<__u32> mapIDs;
			mapIDs.resize(prog_info.nr_map_ids);

			prog_info.map_ids = reinterpret_cast<__u64>(mapIDs.data());
			info_len = sizeof(prog_info);
			if (bpf_prog_get_info_by_fd(prog_fd, &prog_info, &info_len) == 0)
			{
				for (__u32 mapID : mapIDs)
				{
					int mapFD = bpf_map_get_fd_by_id(mapID);
					if (mapFD < 0)
					{
						continue;
					}

					struct bpf_map_info mapInfo = {};
					__u32 mapInfoLen = sizeof(mapInfo);
					if (bpf_map_get_info_by_fd(mapFD, &mapInfo, &mapInfoLen) != 0)
					{
						::close(mapFD);
						continue;
					}

					PreattachedMapFD mapEntry = {};
					memcpy(mapEntry.name, mapInfo.name, sizeof(mapEntry.name));
					mapEntry.fd = mapFD;
					preattachedMapFDs.push_back(mapEntry);
				}
			}
		}

	    	attachidx = prog_info.ifindex;
	    	attachtype = progtype;
	    	
		obj = bpf_object__open(progpath.c_str());

		if (libbpf_get_error(obj))
		{
			obj = nullptr;
			close();
			return false;
		}

		prog = bpf_object__find_program_by_name(obj, prog_info.name);

		if (!prog)
		{
			close();
			return false;
		}

		return true;
	}

	template <typename MapOfMapsSeeder>
	bool load(StringType auto&& progpath, StringType auto&& progname, MapOfMapsSeeder&& seeder)
	{
		close();

		obj = bpf_object__open(progpath.c_str());
	 
	   if (libbpf_get_error(obj))
	   {
	      obj = nullptr;
	      return false;
	   }

	   Vector<int> inner_map_fds;
		seeder(obj, inner_map_fds);
		auto closeInnerMapFDs = [&] (void) -> void {
			for (int fd : inner_map_fds)
			{
				if (fd >= 0)
				{
					::close(fd);
				}
			}
		};

	   // Load the program into the kernel
	   if (bpf_object__load(obj)) 
	   {
	      closeInnerMapFDs();
	      close();
	      return false;
	   }

	   closeInnerMapFDs();

	   // Find the program by name (as set in the SEC macro in the eBPF program)
	   prog = bpf_object__find_program_by_name(obj, progname.c_str());

	   if (!prog) 
	   {
	      close();
	      return false;
	   }

	   prog_fd = bpf_program__fd(prog);
	   if (prog_fd < 0)
	   {
	      close();
	      return false;
	   }
	   progFDOwnedByObject = true;

	   return true;
	}

	template <StringType T, StringType X>
	bool load(T&& progpath, X&& progname)
	{
		return load(std::forward<T>(progpath), std::forward<X>(progname), [&] (struct bpf_object *obj, Vector<int>& inner_map_fds) -> void {});
	}

	template <StringType T, StringType X>
	bool loadAttach(enum bpf_attach_type progtype, int ifidx, T&& progpath, X&& progname)
	{
		return loadAttach(progtype, ifidx, std::forward<T>(progpath), std::forward<X>(progname), [&] (struct bpf_object *obj, Vector<int>& inner_map_fds) -> void {});
	}

	template <StringType T, StringType X, typename MapSeeder>
	bool loadAttach(enum bpf_attach_type progtype, int ifidx, T&& progpath, X&& progname, MapSeeder&& seeder)
	{
		if (load(std::forward<T>(progpath), std::forward<X>(progname), std::forward<MapSeeder>(seeder)))
		{
			attachidx = ifidx;
			attachtype = progtype;

			// https://github.com/torvalds/linux/blob/b401b621758e46812da61fa58a67c3fd8d91de0d/include/uapi/linux/bpf.h#L1000

			int result = bpf_prog_attach_opts(prog_fd, ifidx, progtype, nullptr);

		   if (result == 0)
		   {
		   	return true;
		   }

		   close();
		   return false;
		}

		return false;
	}

	void detach(void)
	{
		if (attachidx > -1)
		{
			int result = bpf_prog_detach_opts(prog_fd, attachidx, attachtype, nullptr);
			(void)result;
			attachidx = -1;
		}
	}

	template <typename Lambda>
	void openMap(StringType auto&& map_name, Lambda&& lambda)
	{
		const char *requestedName = map_name.c_str();
		if (requestedName != nullptr && preattachedMapFDs.empty() == false)
		{
			size_t requestedLen = strlen(requestedName);

			for (const PreattachedMapFD& preattachedMap : preattachedMapFDs)
			{
				if (preattachedMap.fd < 0)
				{
					continue;
				}

				size_t existingLen = strnlen(preattachedMap.name, sizeof(preattachedMap.name));
				bool exactMatch = (requestedLen == existingLen && memcmp(requestedName, preattachedMap.name, requestedLen) == 0);
				bool requestedIsPrefix = (requestedLen >= existingLen && memcmp(requestedName, preattachedMap.name, existingLen) == 0);
				bool existingIsPrefix = (existingLen >= requestedLen && memcmp(preattachedMap.name, requestedName, requestedLen) == 0);

				// BPF map names are capped to BPF_OBJ_NAME_LEN, so accept both exact and
				// truncated-prefix matches when resolving preattached map descriptors.
				if (exactMatch || requestedIsPrefix || existingIsPrefix)
				{
					lambda(preattachedMap.fd);
					return;
				}
			}
		}

		int fd = bpf_object__find_map_fd_by_name(obj, map_name.c_str());
		lambda(fd);
		// close(fd); // -9 when we open close then reopen. stupid thing.
	}

	void setElement(int map_fd, void *key, void *value)
	{
		bpf_map_update_elem(map_fd, key, value, BPF_ANY);
	}

	void deleteElement(int map_fd, void *key)
	{
	   bpf_map_delete_elem(map_fd, key);
	}

	void deleteArrayElement(int map_fd, uint32_t index)
	{
	   bpf_map_delete_elem(map_fd, &index);
	}

	void deleteArrayElement(StringType auto&& array_name, uint32_t index)
	{
		openMap(array_name, [&] (int array_fd) -> void {

			deleteArrayElement(array_fd, index);
		});
	}

	template <typename T>
	void setArrayElement(int array_fd, uint32_t index, T& element)
	{
		setElement(array_fd, &index, &element);
	}

	template <typename T>
	void setArrayElement(StringType auto&& array_name, uint32_t index, T& element)
	{
		openMap(array_name, [&] (int array_fd) -> void {

			setArrayElement(array_fd, index, element);
		});
	}

	template <typename T>
	T getElement(StringType auto&& map_name, void *key)
	{
		T element;

		openMap(map_name, [&] (int map_fd) -> void {

			getElement(map_fd, key, element);
		});

		return element;
	}

	template <typename T>
	T getElement(int fd, void *key)
	{
		T element;
		bpf_map_lookup_elem(fd, key, &element);
		return element;
	}

	template <typename T>
	T getArrayElement(int fd, uint32_t index)
	{
		return getElement<T>(fd, &index);
	}

	template <typename T>
	void getElement(int fd, void *key, T& element)
	{
		bpf_map_lookup_elem(fd, key, &element);
	}

	template <typename T>
	void getArrayElement(StringType auto&& map_name, uint32_t index, T& element)
	{
		openMap(map_name, [&] (int map_fd) -> void {

			getElement(map_fd, &index, element);
		});
	}

	template <typename T>
	void getElement(StringType auto&& map_name, void *key, T& element)
	{
		openMap(map_name, [&] (int map_fd) -> void {

			getElement(map_fd, key, element);
		});
	}

	void close(void)
	{
		detach();
		closePreattachedMapFDs();

		if (obj != nullptr)
		{
			bpf_object__close(obj);
			obj = nullptr;
		}

		prog = nullptr;
		if (progFDOwnedByObject == false && prog_fd != -1)
		{
			::close(prog_fd);
		}

		prog_fd = -1;
		progFDOwnedByObject = false;
		attachidx = -1;
	}
};
