// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cstdarg>
#include <cstring>
#include <fcntl.h>
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
	bool loadedFromPreattached = false;
	struct bpf_link *link = nullptr;
	__u32 expectedPreattachedMapCount = 0;
	std::vector<char> kernelLog;

	struct PreattachedMapFD
	{
		char name[BPF_OBJ_NAME_LEN];
		enum bpf_map_type type;
		__u32 keySize;
		__u32 valueSize;
		__u32 maxEntries;
		__u32 mapFlags;
		__u32 btfKeyTypeID;
		__u32 btfValueTypeID;
		__u32 btfVMLinuxValueTypeID;
		int fd;
	};

	std::vector<PreattachedMapFD> preattachedMapFDs;

	// Linux BPF object names are BPF_OBJ_NAME_LEN bytes including NUL:
	// callers may use at most 15 visible bytes.
	static constexpr size_t maxObjectNameBytes = BPF_OBJ_NAME_LEN - 1;

	static bool objectNameFitsKernelLimit(const char *name)
	{
		return name != nullptr && strnlen(name, BPF_OBJ_NAME_LEN) <= maxObjectNameBytes;
	}

	static void logInvalidObjectName(const char *kind, const char *name)
	{
		basics_log("BPFProgram rejected overlong %s name=%s max_bytes=%zu\n",
			kind,
			(name ? name : "<null>"),
			maxObjectNameBytes);
	}

	static void logBPFError(const char *op, int fd, int result)
	{
		basics_log("BPFProgram::%s failed fd=%d result=%d errno=%d\n",
			(op ? op : "bpf"),
			fd,
			result,
			errno);
	}

	static bool validMapFD(int fd, const char *op)
	{
		if (fd >= 0)
		{
			return true;
		}

		basics_log("BPFProgram::%s invalid map_fd=%d\n", (op ? op : "bpf-map"), fd);
		return false;
	}

	struct bpf_object *openObject(const char *path)
	{
		kernelLog.assign(1 << 20, 0);
		struct bpf_object_open_opts opts = {};
		opts.sz = sizeof(opts);
		opts.kernel_log_buf = kernelLog.data();
		opts.kernel_log_size = kernelLog.size();
		return bpf_object__open_file(path, &opts);
	}

	void logKernelLoadFailure(const char *stage, const char *path, int result)
	{
		basics_log("BPFProgram::%s failed path=%s result=%d errno=%d\n",
			stage,
			(path ? path : "<null>"),
			result,
			errno);
		if (!kernelLog.empty() && kernelLog[0] != '\0')
		{
			basics_log("BPFProgram verifier log path=%s\n%s\n", (path ? path : "<null>"), kernelLog.data());
		}
	}

	bool validateObjectNames(const char *path)
	{
		bool ok = true;
		struct bpf_map *map = nullptr;
		bpf_object__for_each_map(map, obj)
		{
			if (objectNameFitsKernelLimit(bpf_map__name(map)) == false)
			{
				logInvalidObjectName("object map", bpf_map__name(map));
				ok = false;
			}
		}

		struct bpf_program *program = nullptr;
		bpf_object__for_each_program(program, obj)
		{
			if (objectNameFitsKernelLimit(bpf_program__name(program)) == false)
			{
				logInvalidObjectName("object program", bpf_program__name(program));
				ok = false;
			}
		}

		if (ok == false)
		{
			basics_log("BPFProgram rejected object with overlong BPF object names path=%s max_bytes=%zu\n",
				(path ? path : "<null>"),
				maxObjectNameBytes);
		}
		return ok;
	}

	static bool objectNameMatches(const char *requestedName, const char *candidateName)
	{
		if (requestedName == nullptr || candidateName == nullptr)
		{
			return false;
		}

		size_t requestedLen = strnlen(requestedName, BPF_OBJ_NAME_LEN);
		size_t candidateLen = strnlen(candidateName, BPF_OBJ_NAME_LEN);
		bool exactMatch = (requestedLen == candidateLen && memcmp(requestedName, candidateName, requestedLen) == 0);
		bool requestedIsPrefix = (requestedLen >= candidateLen && memcmp(requestedName, candidateName, candidateLen) == 0);
		bool candidateIsPrefix = (candidateLen >= requestedLen && memcmp(candidateName, requestedName, requestedLen) == 0);

		// Kernel-side BPF object names are capped to BPF_OBJ_NAME_LEN, so accept
		// both exact and truncated-prefix matches when reopening a preattached
		// program or map from its persisted kernel identity.
		return exactMatch || requestedIsPrefix || candidateIsPrefix;
	}

	static struct bpf_program *findProgramByKernelName(struct bpf_object *object, const char *requestedName)
	{
		if (object == nullptr || requestedName == nullptr)
		{
			return nullptr;
		}

		struct bpf_program *candidate = nullptr;
		bpf_object__for_each_program(candidate, object)
		{
			const char *candidateName = bpf_program__name(candidate);
			if (objectNameMatches(requestedName, candidateName))
			{
				return candidate;
			}
		}

		return nullptr;
	}

	static struct bpf_map *findMapByKernelName(struct bpf_object *object, const char *requestedName)
	{
		if (object == nullptr || requestedName == nullptr)
		{
			return nullptr;
		}

		if (struct bpf_map *match = bpf_object__find_map_by_name(object, requestedName))
		{
			return match;
		}

		struct bpf_map *candidate = nullptr;
		bpf_object__for_each_map(candidate, object)
		{
			if (objectNameMatches(requestedName, bpf_map__name(candidate)))
			{
				return candidate;
			}
		}

		return nullptr;
	}

	static void appendPreattachedTracef(const char *format, ...)
	{
		int fd = ::open("/switchboard.attach.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
		if (fd < 0)
		{
			return;
		}

		char line[768] = {};
		va_list args;
		va_start(args, format);
		(void)vsnprintf(line, sizeof(line), format, args);
		va_end(args);

		(void)::write(fd, line, strlen(line));
		(void)::write(fd, "\n", 1);
		(void)::close(fd);
	}

	static bool metadataMatchesRequestedMap(const PreattachedMapFD& preattachedMap, const struct bpf_map *requestedMap)
	{
		if (requestedMap == nullptr)
		{
			return false;
		}

		if (preattachedMap.type != bpf_map__type(requestedMap)
			|| preattachedMap.keySize != bpf_map__key_size(requestedMap)
			|| preattachedMap.valueSize != bpf_map__value_size(requestedMap)
			|| preattachedMap.maxEntries != bpf_map__max_entries(requestedMap)
			|| preattachedMap.mapFlags != bpf_map__map_flags(requestedMap))
		{
			return false;
		}

		__u32 requestedBTFKeyTypeID = bpf_map__btf_key_type_id(requestedMap);
		__u32 requestedBTFValueTypeID = bpf_map__btf_value_type_id(requestedMap);
		if (requestedBTFKeyTypeID != 0 && preattachedMap.btfKeyTypeID != 0 && preattachedMap.btfKeyTypeID != requestedBTFKeyTypeID)
		{
			return false;
		}
		if (requestedBTFValueTypeID != 0 && preattachedMap.btfValueTypeID != 0 && preattachedMap.btfValueTypeID != requestedBTFValueTypeID)
		{
			return false;
		}

		return true;
	}

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

	bool refreshPreattachedMapFDs(__u32 *recoveredMapCount = nullptr)
	{
		closePreattachedMapFDs();

		if (prog_fd < 0)
		{
			return false;
		}

		struct bpf_prog_info progInfo = {};
		__u32 progInfoLen = sizeof(progInfo);
		if (bpf_prog_get_info_by_fd(prog_fd, &progInfo, &progInfoLen) != 0)
		{
			basics_log("BPFProgram::refreshPreattachedMapFDs bpf_prog_get_info_by_fd failed prog_fd=%d errno=%d\n",
				prog_fd,
				errno);
			return false;
		}

		appendPreattachedTracef("BPFProgram refresh prog_fd=%d prog_name=%s nr_map_ids=%u ifindex=%u",
			prog_fd,
			progInfo.name,
			unsigned(progInfo.nr_map_ids),
			unsigned(progInfo.ifindex));

		if (recoveredMapCount != nullptr)
		{
			*recoveredMapCount = progInfo.nr_map_ids;
		}

		if (progInfo.nr_map_ids == 0)
		{
			return true;
		}

		std::vector<__u32> mapIDs;
		mapIDs.resize(progInfo.nr_map_ids);

		struct bpf_prog_info mapInfoRequest = {};
		mapInfoRequest.nr_map_ids = static_cast<__u32>(mapIDs.size());
		mapInfoRequest.map_ids = reinterpret_cast<__u64>(mapIDs.data());
		progInfoLen = sizeof(mapInfoRequest);
		if (bpf_prog_get_info_by_fd(prog_fd, &mapInfoRequest, &progInfoLen) != 0)
		{
			basics_log("BPFProgram::refreshPreattachedMapFDs map-id query failed prog_fd=%d expected=%u errno=%d\n",
				prog_fd,
				unsigned(mapIDs.size()),
				errno);
			closePreattachedMapFDs();
			return false;
		}

		if (mapInfoRequest.nr_map_ids != mapIDs.size())
		{
			basics_log("BPFProgram::refreshPreattachedMapFDs map-id count drifted prog_fd=%d requested=%u actual=%u\n",
				prog_fd,
				unsigned(mapIDs.size()),
				unsigned(mapInfoRequest.nr_map_ids));
			closePreattachedMapFDs();
			return false;
		}

		for (__u32 mapID : mapIDs)
		{
			int mapFD = bpf_map_get_fd_by_id(mapID);
			if (mapFD < 0)
			{
				basics_log("BPFProgram::refreshPreattachedMapFDs bpf_map_get_fd_by_id failed prog_fd=%d map_id=%u errno=%d\n",
					prog_fd,
					mapID,
					errno);
				closePreattachedMapFDs();
				return false;
			}

			struct bpf_map_info mapInfo = {};
			__u32 mapInfoLen = sizeof(mapInfo);
			if (bpf_map_get_info_by_fd(mapFD, &mapInfo, &mapInfoLen) != 0)
			{
				basics_log("BPFProgram::refreshPreattachedMapFDs bpf_map_get_info_by_fd failed prog_fd=%d map_id=%u fd=%d errno=%d\n",
					prog_fd,
					mapID,
					mapFD,
					errno);
				::close(mapFD);
				closePreattachedMapFDs();
				return false;
			}

			PreattachedMapFD mapEntry = {};
			memcpy(mapEntry.name, mapInfo.name, sizeof(mapEntry.name));
			mapEntry.type = static_cast<enum bpf_map_type>(mapInfo.type);
			mapEntry.keySize = mapInfo.key_size;
			mapEntry.valueSize = mapInfo.value_size;
			mapEntry.maxEntries = mapInfo.max_entries;
			mapEntry.mapFlags = mapInfo.map_flags;
			mapEntry.btfKeyTypeID = mapInfo.btf_key_type_id;
			mapEntry.btfValueTypeID = mapInfo.btf_value_type_id;
			mapEntry.btfVMLinuxValueTypeID = mapInfo.btf_vmlinux_value_type_id;
			mapEntry.fd = mapFD;
			preattachedMapFDs.push_back(mapEntry);
			appendPreattachedTracef("BPFProgram recovered map prog_fd=%d map_id=%u name=%s type=%u key=%u value=%u max=%u flags=0x%x btf_key=%u btf_value=%u",
				prog_fd,
				unsigned(mapInfo.id),
				mapInfo.name,
				unsigned(mapInfo.type),
				unsigned(mapInfo.key_size),
				unsigned(mapInfo.value_size),
				unsigned(mapInfo.max_entries),
				unsigned(mapInfo.map_flags),
				unsigned(mapInfo.btf_key_type_id),
				unsigned(mapInfo.btf_value_type_id));
		}

		if (preattachedMapFDs.size() != mapIDs.size())
		{
			basics_log("BPFProgram::refreshPreattachedMapFDs recovered incomplete map set prog_fd=%d expected=%u actual=%u\n",
				prog_fd,
				unsigned(mapIDs.size()),
				unsigned(preattachedMapFDs.size()));
			closePreattachedMapFDs();
			return false;
		}

		return true;
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

	   int nextResult = 0;
	   errno = 0;
	   while ((nextResult = bpf_prog_get_next_id(next_id, &next_id)) == 0)
	   {
	      int prog_fd = bpf_prog_get_fd_by_id(next_id);
			if (prog_fd < 0)
			{
				basics_log("BPFProgram::removeAllZombies bpf_prog_get_fd_by_id failed prog_id=%u errno=%d\n",
					next_id,
					errno);
				continue;
			}

			struct bpf_prog_info prog_info;
			uint32_t len = sizeof(struct bpf_prog_info);
			memset(&prog_info, 0, len);

			int result = bpf_prog_get_info_by_fd(prog_fd, &prog_info, &len);
			if (result != 0)
			{
				basics_log("BPFProgram::removeAllZombies bpf_prog_get_info_by_fd failed prog_id=%u fd=%d errno=%d\n",
					next_id,
					prog_fd,
					errno);
				::close(prog_fd);
				continue;
			}
			
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
			if (detach_result != 0)
			{
				basics_log("BPFProgram::removeAllZombies detach failed prog_id=%u fd=%d ifidx=%d attach_type=%d result=%d errno=%d\n",
					next_id,
					prog_fd,
					ifidx,
					int(attach_type),
					detach_result,
					errno);
			}

			::close(prog_fd);
	   }
	   if (nextResult != 0 && errno != ENOENT)
	   {
	      basics_log("BPFProgram::removeAllZombies bpf_prog_get_next_id failed errno=%d\n", errno);
	   }
	}

	struct bpf_object *obj = nullptr;
	struct bpf_program *prog = nullptr;
	int prog_fd = -1;

	bool loadPreattached(enum bpf_attach_type progtype, int attachedIfidx, uint32_t prog_id, StringType auto&& progpath)
	{
		close();

		prog_fd = bpf_prog_get_fd_by_id(prog_id);

		if (prog_fd < 0) 
		{
			basics_log("BPFProgram::loadPreattached bpf_prog_get_fd_by_id failed prog_id=%u errno=%d\n",
				prog_id,
				errno);
			return false;
		}

		struct bpf_prog_info prog_info = {};
		uint32_t info_len = sizeof(prog_info);

		if (bpf_prog_get_info_by_fd(prog_fd, &prog_info, &info_len) != 0)
		{
			basics_log("BPFProgram::loadPreattached bpf_prog_get_info_by_fd failed prog_id=%u fd=%d errno=%d\n",
				prog_id,
				prog_fd,
				errno);
			close();
			return false;
		}

		appendPreattachedTracef("BPFProgram loadPreattached prog_id=%u prog_fd=%d name=%s nr_map_ids=%u ifindex=%u path=%s",
			prog_id,
			prog_fd,
			prog_info.name,
			unsigned(prog_info.nr_map_ids),
			unsigned(prog_info.ifindex),
			progpath.c_str());

		if (refreshPreattachedMapFDs(&expectedPreattachedMapCount) == false)
		{
			basics_log("BPFProgram::loadPreattached failed to recover map FDs prog_id=%u fd=%d errno=%d\n",
				prog_id,
				prog_fd,
				errno);
			close();
			return false;
		}

	    	attachidx = (prog_info.ifindex > 0 ? int(prog_info.ifindex) : attachedIfidx);
	    	attachtype = progtype;
	    	loadedFromPreattached = true;
	    	
		obj = openObject(progpath.c_str());

		if (libbpf_get_error(obj))
		{
			int error = -libbpf_get_error(obj);
			logKernelLoadFailure("loadPreattached open", progpath.c_str(), error);
			obj = nullptr;
			close();
			return false;
		}
		if (validateObjectNames(progpath.c_str()) == false)
		{
			close();
			return false;
		}

		prog = findProgramByKernelName(obj, prog_info.name);

		if (!prog)
		{
			basics_log("BPFProgram::loadPreattached unable to resolve program prog_id=%u kernel_name=%s path=%s\n",
				prog_id,
				prog_info.name,
				progpath.c_str());
			struct bpf_program *candidate = nullptr;
			bpf_object__for_each_program(candidate, obj)
			{
				const char *candidateName = bpf_program__name(candidate);
				if (candidateName)
				{
					basics_log("BPFProgram::loadPreattached candidate program name=%s\n", candidateName);
				}
			}
			close();
			return false;
		}

		return true;
	}

	template <typename MapOfMapsSeeder>
	bool load(StringType auto&& progpath, StringType auto&& progname, MapOfMapsSeeder&& seeder)
	{
		close();

		if (objectNameFitsKernelLimit(progname.c_str()) == false)
		{
			logInvalidObjectName("program", progname.c_str());
			return false;
		}

		obj = openObject(progpath.c_str());
	 
	   if (libbpf_get_error(obj))
	   {
	      int error = -libbpf_get_error(obj);
	      logKernelLoadFailure("load open", progpath.c_str(), error);
	      obj = nullptr;
	      return false;
	   }
	   if (validateObjectNames(progpath.c_str()) == false)
	   {
	      close();
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
	   int loadResult = bpf_object__load(obj);
	   if (loadResult != 0)
	   {
	      logKernelLoadFailure("load verifier", progpath.c_str(), loadResult);
	      closeInnerMapFDs();
	      close();
	      return false;
	   }

	   closeInnerMapFDs();

	   // Find the program by name (as set in the SEC macro in the eBPF program)
	   prog = findProgramByKernelName(obj, progname.c_str());

	   if (!prog) 
	   {
	      basics_log("BPFProgram::load missing program name=%s path=%s\n", progname.c_str(), progpath.c_str());
	      struct bpf_program *candidate = nullptr;
	      bpf_object__for_each_program(candidate, obj)
	      {
	         const char *candidateName = bpf_program__name(candidate);
	         if (candidateName)
	         {
	            basics_log("BPFProgram::load candidate program name=%s\n", candidateName);
	         }
	      }
	      close();
	      return false;
	   }

	   prog_fd = bpf_program__fd(prog);
	   if (prog_fd < 0)
	   {
	      logBPFError("bpf_program__fd", prog_fd, prog_fd);
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
			if (progtype == BPF_TCX_INGRESS || progtype == BPF_TCX_EGRESS)
			{
				struct bpf_tcx_opts opts = {};
				opts.sz = sizeof(opts);
				link = bpf_program__attach_tcx(prog, ifidx, &opts);
				int error = int(libbpf_get_error(link));
				if (error == 0)
				{
					return true;
				}

				link = nullptr;
				errno = -error;
				basics_log("BPFProgram::loadAttach TCX link failed fd=%d ifidx=%d attach_type=%d error=%d errno=%d path=%s program=%s\n",
					prog_fd,
					ifidx,
					int(progtype),
					error,
					errno,
					progpath.c_str(),
					progname.c_str());
				close();
				return false;
			}

			// https://github.com/torvalds/linux/blob/b401b621758e46812da61fa58a67c3fd8d91de0d/include/uapi/linux/bpf.h#L1000

			int result = bpf_prog_attach_opts(prog_fd, ifidx, progtype, nullptr);

		   if (result == 0)
		   {
		   	return true;
		   }

		   basics_log("BPFProgram::loadAttach attach failed fd=%d ifidx=%d attach_type=%d result=%d errno=%d path=%s program=%s\n",
				prog_fd,
				ifidx,
				int(progtype),
				result,
				errno,
				progpath.c_str(),
				progname.c_str());
		   close();
		   return false;
		}

		return false;
	}

	void detach(void)
	{
		if (link != nullptr)
		{
			int result = bpf_link__destroy(link);
			if (result != 0)
			{
				basics_log("BPFProgram::detach link failed fd=%d ifidx=%d attach_type=%d result=%d errno=%d\n",
					prog_fd,
					attachidx,
					int(attachtype),
					result,
					errno);
			}
			link = nullptr;
			attachidx = -1;
			return;
		}

		if (attachidx > -1)
		{
			int result = bpf_prog_detach_opts(prog_fd, attachidx, attachtype, nullptr);
			if (result != 0)
			{
				basics_log("BPFProgram::detach failed fd=%d ifidx=%d attach_type=%d result=%d errno=%d\n",
					prog_fd,
					attachidx,
					int(attachtype),
					result,
					errno);
			}
			attachidx = -1;
		}
	}

	template <typename Lambda>
	void openMap(StringType auto&& map_name, Lambda&& lambda)
	{
		const char *requestedName = map_name.c_str();
		if (objectNameFitsKernelLimit(requestedName) == false)
		{
			logInvalidObjectName("map", requestedName);
			lambda(-1);
			return;
		}

		auto tryOpenPreattachedMap = [&] (bool allowRefresh) -> int {
			if (loadedFromPreattached == false)
			{
				return -1;
			}

			auto tryResolveFromCurrentState = [&] (void) -> int {
				appendPreattachedTracef("BPFProgram openMap request=%s prog_fd=%d expected=%u recovered=%u allowRefresh=%d",
					(requestedName ? requestedName : "<null>"),
					prog_fd,
					unsigned(expectedPreattachedMapCount),
					unsigned(preattachedMapFDs.size()),
					int(allowRefresh));

				if (requestedName == nullptr || preattachedMapFDs.empty())
				{
					return -1;
				}

				const struct bpf_map *requestedMap = findMapByKernelName(obj, requestedName);

				if (requestedMap != nullptr)
				{
					const PreattachedMapFD *metadataMatch = nullptr;
					uint32_t metadataMatchCount = 0;

					for (const PreattachedMapFD& preattachedMap : preattachedMapFDs)
					{
						if (preattachedMap.fd < 0 || metadataMatchesRequestedMap(preattachedMap, requestedMap) == false)
						{
							continue;
						}

						metadataMatch = &preattachedMap;
						metadataMatchCount += 1;
					}

					if (metadataMatchCount > 1)
					{
						metadataMatch = nullptr;
						metadataMatchCount = 0;

						for (const PreattachedMapFD& preattachedMap : preattachedMapFDs)
						{
							if (preattachedMap.fd < 0
								|| metadataMatchesRequestedMap(preattachedMap, requestedMap) == false
								|| objectNameMatches(requestedName, preattachedMap.name) == false)
							{
								continue;
							}

							metadataMatch = &preattachedMap;
							metadataMatchCount += 1;
						}
					}

					if (metadataMatchCount == 1 && metadataMatch != nullptr)
					{
						appendPreattachedTracef("BPFProgram openMap metadata match request=%s fd=%d name=%s",
							requestedName,
							metadataMatch->fd,
							metadataMatch->name);
						return metadataMatch->fd;
					}
				}

				for (const PreattachedMapFD& preattachedMap : preattachedMapFDs)
				{
					if (preattachedMap.fd >= 0 && objectNameMatches(requestedName, preattachedMap.name))
					{
						appendPreattachedTracef("BPFProgram openMap name match request=%s fd=%d name=%s",
							requestedName,
							preattachedMap.fd,
							preattachedMap.name);
						return preattachedMap.fd;
					}
				}

				return -1;
			};

			int fd = tryResolveFromCurrentState();
			if (fd >= 0 || allowRefresh == false)
			{
				return fd;
			}

			__u32 refreshedMapCount = expectedPreattachedMapCount;
			if (refreshPreattachedMapFDs(&refreshedMapCount))
			{
				expectedPreattachedMapCount = refreshedMapCount;
				return tryResolveFromCurrentState();
			}

			return -1;
		};

		if (loadedFromPreattached)
		{
			int preattachedFD = tryOpenPreattachedMap(true);
			if (preattachedFD >= 0 || prog_fd >= 0)
			{
				if (preattachedFD < 0)
				{
					basics_log("BPFProgram::openMap missing reopened map name=%s prog_fd=%d expected_preattached_maps=%u recovered=%u\n",
						(requestedName ? requestedName : "<null>"),
						prog_fd,
						unsigned(expectedPreattachedMapCount),
						unsigned(preattachedMapFDs.size()));
				}
				lambda(preattachedFD);
				return;
			}
		}

		struct bpf_map *map = findMapByKernelName(obj, requestedName);
		int fd = (map != nullptr) ? bpf_map__fd(map) : -1;
		if (map == nullptr)
		{
			basics_log("BPFProgram::openMap missing map name=%s prog_fd=%d\n",
				(requestedName ? requestedName : "<null>"),
				prog_fd);
		}
		else if (fd < 0)
		{
			logBPFError("bpf_map__fd", fd, fd);
		}
		lambda(fd);
		// close(fd); // -9 when we open close then reopen. stupid thing.
	}

	void setElement(int map_fd, void *key, void *value)
	{
		if (validMapFD(map_fd, "setElement") == false)
		{
			return;
		}

		int result = bpf_map_update_elem(map_fd, key, value, BPF_ANY);
		if (result != 0)
		{
			logBPFError("bpf_map_update_elem", map_fd, result);
		}
	}

	void deleteElement(int map_fd, void *key)
	{
		if (validMapFD(map_fd, "deleteElement") == false)
		{
			return;
		}

		int result = bpf_map_delete_elem(map_fd, key);
		if (result != 0)
		{
			logBPFError("bpf_map_delete_elem", map_fd, result);
		}
	}

	void deleteArrayElement(int map_fd, uint32_t index)
	{
	   deleteElement(map_fd, &index);
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
		T element = {};

		openMap(map_name, [&] (int map_fd) -> void {

			getElement(map_fd, key, element);
		});

		return element;
	}

	template <typename T>
	T getElement(int fd, void *key)
	{
		T element = {};
		getElement(fd, key, element);
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
		element = {};
		if (validMapFD(fd, "getElement") == false)
		{
			return;
		}

		int result = bpf_map_lookup_elem(fd, key, &element);
		if (result != 0)
		{
			logBPFError("bpf_map_lookup_elem", fd, result);
		}
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
		loadedFromPreattached = false;
		expectedPreattachedMapCount = 0;
		attachidx = -1;
	}
};
