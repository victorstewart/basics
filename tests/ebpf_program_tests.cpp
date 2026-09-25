// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <algorithm>
#include <chrono>
#include <cerrno>
#include <cstdarg>
#include <filesystem>
#include <fstream>
#include <fcntl.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <string_view>
#include <unordered_set>
#include <sys/wait.h>
#include <unistd.h>

#include "ebpf/program.h"

// These networking headers are not yet self-contained, so include the
// prerequisites explicitly in the order the current public surface expects.
#include "base/flat_hash_map.hpp"
#include "base/bytell_hash_map.hpp"
#include "types/types.containers.h"
#include "services/bitsery.h"
#include "macros/bytes.h"
#include "networking/time.h"
#include "networking/ip.h"
#include "networking/socket.h"
#include "networking/msg.h"
#include "networking/pool.h"
#include "networking/eth.h"
#include "networking/netlink.h"

namespace PreattachedTraceIntercept {

static std::string redirectedPath;
static std::unordered_set<int> diagnosticFDs;
static uint64_t opens = 0;
static uint64_t writes = 0;
static uint64_t closes = 0;

static void resetCounts()
{
  opens = 0;
  writes = 0;
  closes = 0;
}

static bool redirects(const char *path)
{
  return redirectedPath.empty() == false && path != nullptr &&
         strcmp(path, "/switchboard.attach.log") == 0;
}

} // namespace PreattachedTraceIntercept

extern "C" int __real_open(const char *path, int flags, ...);
extern "C" ssize_t __real_write(int fd, const void *buffer, size_t count);
extern "C" int __real_close(int fd);

extern "C" int __wrap_open(const char *path, int flags, ...)
{
  if ((flags & O_CREAT) == 0 && (flags & O_TMPFILE) != O_TMPFILE)
  {
    return __real_open(path, flags);
  }

  va_list arguments;
  va_start(arguments, flags);
  const mode_t mode = static_cast<mode_t>(va_arg(arguments, int));
  va_end(arguments);

  if (PreattachedTraceIntercept::redirects(path) == false)
  {
    return __real_open(path, flags, mode);
  }
  int fd = __real_open(PreattachedTraceIntercept::redirectedPath.c_str(), flags, mode);
  if (fd >= 0)
  {
    PreattachedTraceIntercept::diagnosticFDs.insert(fd);
    PreattachedTraceIntercept::opens += 1;
  }
  return fd;
}

extern "C" ssize_t __wrap_write(int fd, const void *buffer, size_t count)
{
  if (PreattachedTraceIntercept::diagnosticFDs.contains(fd))
  {
    PreattachedTraceIntercept::writes += 1;
  }
  return __real_write(fd, buffer, count);
}

extern "C" int __wrap_close(int fd)
{
  if (PreattachedTraceIntercept::diagnosticFDs.erase(fd) != 0)
  {
    PreattachedTraceIntercept::closes += 1;
  }
  return __real_close(fd);
}

namespace {

constexpr const char *kProgramName = "xdp_pass";
constexpr const char *kTCXProgramName = "tcx_pass";
constexpr const char *kMapName = "counters";
constexpr const char *kOverlapMap4Name = "owned_routable_prefixes4";
constexpr const char *kOverlapMap6Name = "owned_routable_prefixes6";

class ScopedTempDirectory {
private:

  std::filesystem::path path_;

public:

  ScopedTempDirectory()
  {
    char tempTemplate[] = "/tmp/basics-ebpf-XXXXXX";
    char *created = mkdtemp(tempTemplate);
    if (created != nullptr)
    {
      path_ = created;
    }
  }

  ~ScopedTempDirectory()
  {
    if (path_.empty() == false)
    {
      std::error_code error;
      std::filesystem::remove_all(path_, error);
    }
  }

  bool valid() const
  {
    return path_.empty() == false;
  }

  std::string child(std::string_view name) const
  {
    return (path_ / name).string();
  }
};

class EBPFTestContext {
private:

  TestSuite suite_;
  int skipped_ = 0;

public:

  TestSuite& suite()
  {
    return suite_;
  }

  void skip(std::string_view reason)
  {
    ++skipped_;
    std::cout << "skip ebpf program tests: " << reason << '\n';
  }

  int finish()
  {
    if (skipped_ > 0)
    {
      std::cout << skipped_ << " ebpf test segment(s) skipped.\n";
    }

    return suite_.finish("ebpf program tests");
  }
};

struct CompiledProgramFixture {
  ScopedTempDirectory tempDirectory;
  std::string sourcePath;
  std::string objectPath;
};

static void initializeNetDevice(NetDevice& device)
{
  device.ifidx = 0;
  memset(device.mac, 0, sizeof(device.mac));
}

static int runCommand(const std::vector<std::string>& arguments)
{
  pid_t child = fork();
  if (child < 0)
  {
    return -1;
  }

  if (child == 0)
  {
    std::vector<char *> argv;
    argv.reserve(arguments.size() + 1);

    for (const std::string& argument : arguments)
    {
      argv.push_back(const_cast<char *>(argument.c_str()));
    }

    argv.push_back(nullptr);
    execvp(argv[0], argv.data());
    _exit(127);
  }

  int status = 0;
  if (waitpid(child, &status, 0) < 0)
  {
    return -1;
  }

  if (WIFEXITED(status) == false)
  {
    return -1;
  }

  return WEXITSTATUS(status);
}

static bool compileFixtureProgram(CompiledProgramFixture& fixture)
{
  if (fixture.tempDirectory.valid() == false)
  {
    return false;
  }

  fixture.sourcePath = fixture.tempDirectory.child("xdp_pass.c");
  fixture.objectPath = fixture.tempDirectory.child("xdp_pass.o");

  std::ofstream source(fixture.sourcePath);
  if (source.is_open() == false)
  {
    return false;
  }

  source
    << "#include <linux/bpf.h>\n"
    << "#include <bpf/bpf_helpers.h>\n"
    << "\n"
    << "struct {\n"
    << "  __uint(type, BPF_MAP_TYPE_HASH);\n"
    << "  __uint(max_entries, 4);\n"
    << "  __type(key, __u32);\n"
    << "  __type(value, __u64);\n"
    << "} " << kMapName << " SEC(\".maps\");\n"
    << "\n"
    << "SEC(\"xdp\")\n"
    << "int " << kProgramName << "(struct xdp_md *ctx)\n"
    << "{\n"
    << "  __u32 key = 0;\n"
    << "  __u64 *counter = bpf_map_lookup_elem(&" << kMapName << ", &key);\n"
    << "  if (counter) { *counter += 1; }\n"
    << "  return XDP_PASS;\n"
    << "}\n"
    << "\n"
    << "char LICENSE[] SEC(\"license\") = \"GPL\";\n";

  source.close();
  if (source.good() == false)
  {
    return false;
  }

  int exitCode = runCommand({
    "clang",
    "-O2",
    "-g",
    "-target",
    "bpf",
    "-c",
    fixture.sourcePath,
    "-o",
    fixture.objectPath,
  });

  return exitCode == 0;
}

static bool compileTruncatedMapFixtureProgram(CompiledProgramFixture& fixture)
{
  if (fixture.tempDirectory.valid() == false)
  {
    return false;
  }

  fixture.sourcePath = fixture.tempDirectory.child("xdp_truncated_maps.c");
  fixture.objectPath = fixture.tempDirectory.child("xdp_truncated_maps.o");

  std::ofstream source(fixture.sourcePath);
  if (source.is_open() == false)
  {
    return false;
  }

  source
    << "#include <linux/bpf.h>\n"
    << "#include <bpf/bpf_helpers.h>\n"
    << "\n"
    << "struct key4 {\n"
    << "  __u32 prefixlen;\n"
    << "  __u32 addr;\n"
    << "};\n"
    << "\n"
    << "struct key6 {\n"
    << "  __u32 prefixlen;\n"
    << "  __u32 addr[4];\n"
    << "};\n"
    << "\n"
    << "struct {\n"
    << "  __uint(type, BPF_MAP_TYPE_HASH);\n"
    << "  __uint(max_entries, 4);\n"
    << "  __type(key, struct key4);\n"
    << "  __type(value, __u8);\n"
    << "} " << kOverlapMap4Name << " SEC(\".maps\");\n"
    << "\n"
    << "struct {\n"
    << "  __uint(type, BPF_MAP_TYPE_HASH);\n"
    << "  __uint(max_entries, 4);\n"
    << "  __type(key, struct key6);\n"
    << "  __type(value, __u8);\n"
    << "} " << kOverlapMap6Name << " SEC(\".maps\");\n"
    << "\n"
    << "SEC(\"xdp\")\n"
    << "int " << kProgramName << "(struct xdp_md *ctx)\n"
    << "{\n"
    << "  return XDP_PASS;\n"
    << "}\n"
    << "\n"
    << "char LICENSE[] SEC(\"license\") = \"GPL\";\n";

  source.close();
  if (source.good() == false)
  {
    return false;
  }

  int exitCode = runCommand({
    "clang",
    "-O2",
    "-g",
    "-target",
    "bpf",
    "-c",
    fixture.sourcePath,
    "-o",
    fixture.objectPath,
  });

  return exitCode == 0;
}

static bool compileTCXFixtureProgram(CompiledProgramFixture& fixture)
{
  if (fixture.tempDirectory.valid() == false)
  {
    return false;
  }

  fixture.sourcePath = fixture.tempDirectory.child("tcx_pass.c");
  fixture.objectPath = fixture.tempDirectory.child("tcx_pass.o");

  std::ofstream source(fixture.sourcePath);
  if (source.is_open() == false)
  {
    return false;
  }

  source
    << "#include <linux/bpf.h>\n"
    << "#include <bpf/bpf_helpers.h>\n"
    << "\n"
    << "SEC(\"tcx/egress\")\n"
    << "int " << kTCXProgramName << "(struct __sk_buff *skb)\n"
    << "{\n"
    << "  return TCX_NEXT;\n"
    << "}\n"
    << "\n"
    << "char LICENSE[] SEC(\"license\") = \"GPL\";\n";

  source.close();
  if (source.good() == false)
  {
    return false;
  }

  return runCommand({
    "clang",
    "-O2",
    "-g",
    "-target",
    "bpf",
    "-c",
    fixture.sourcePath,
    "-o",
    fixture.objectPath,
  }) == 0;
}

static size_t countProgramsNamed(std::string_view programName)
{
  size_t count = 0;
  uint32_t nextID = 0;

  while (bpf_prog_get_next_id(nextID, &nextID) == 0)
  {
    int fd = bpf_prog_get_fd_by_id(nextID);
    if (fd < 0)
    {
      continue;
    }

    struct bpf_prog_info info = {};
    __u32 infoLength = sizeof(info);
    if (bpf_prog_get_info_by_fd(fd, &info, &infoLength) == 0)
    {
      size_t loadedNameLength = strnlen(info.name, sizeof(info.name));
      if (loadedNameLength == programName.size() && memcmp(info.name, programName.data(), loadedNameLength) == 0)
      {
        ++count;
      }
    }

    ::close(fd);
  }

  return count;
}

static bool haveRuntimeLoadSupport(void)
{
  return geteuid() == 0;
}

static bool objectNameMatches(std::string_view requestedName, const char *candidateName)
{
  if (candidateName == nullptr)
  {
    return false;
  }

  size_t candidateLength = strnlen(candidateName, BPF_OBJ_NAME_LEN);
  bool exactMatch = (requestedName.size() == candidateLength && memcmp(requestedName.data(), candidateName, requestedName.size()) == 0);
  bool requestedIsPrefix = (requestedName.size() >= candidateLength && memcmp(requestedName.data(), candidateName, candidateLength) == 0);
  bool candidateIsPrefix = (candidateLength >= requestedName.size() && memcmp(candidateName, requestedName.data(), requestedName.size()) == 0);
  return exactMatch || requestedIsPrefix || candidateIsPrefix;
}

static __u32 findAttachedMapIDByNameAndKeySize(int progFD, std::string_view name, __u32 expectedKeySize)
{
  struct bpf_prog_info progInfo = {};
  __u32 infoLength = sizeof(progInfo);
  if (bpf_prog_get_info_by_fd(progFD, &progInfo, &infoLength) != 0 || progInfo.nr_map_ids == 0)
  {
    return 0;
  }

  std::vector<__u32> mapIDs(progInfo.nr_map_ids);
  struct bpf_prog_info mapInfoRequest = {};
  mapInfoRequest.nr_map_ids = static_cast<__u32>(mapIDs.size());
  mapInfoRequest.map_ids = reinterpret_cast<__u64>(mapIDs.data());
  infoLength = sizeof(mapInfoRequest);
  if (bpf_prog_get_info_by_fd(progFD, &mapInfoRequest, &infoLength) != 0)
  {
    return 0;
  }

  for (__u32 mapID : mapIDs)
  {
    int mapFD = bpf_map_get_fd_by_id(mapID);
    if (mapFD < 0)
    {
      continue;
    }

    struct bpf_map_info mapInfo = {};
    __u32 mapInfoLength = sizeof(mapInfo);
    bool matches = false;
    if (bpf_map_get_info_by_fd(mapFD, &mapInfo, &mapInfoLength) == 0)
    {
      matches = objectNameMatches(name, mapInfo.name) && mapInfo.key_size == expectedKeySize;
    }

    ::close(mapFD);

    if (matches)
    {
      return mapID;
    }
  }

  return 0;
}

static void exerciseMapOperations(TestSuite& suite, BPFProgram& program)
{
  bool sawMap = false;
  String mapName(kMapName);

  program.openMap(mapName, [&] (int mapFD) -> void {
    sawMap = true;
    EXPECT_TRUE(suite, mapFD >= 0);
    if (mapFD < 0)
    {
      return;
    }

    uint32_t key = 7;
    uint64_t expectedValue = 12345;
    program.setElement(mapFD, &key, &expectedValue);

    uint64_t actualValue = 0;
    program.getElement(mapFD, &key, actualValue);
    EXPECT_EQ(suite, actualValue, expectedValue);

    program.deleteElement(mapFD, &key);
    errno = 0;
    int lookupResult = bpf_map_lookup_elem(mapFD, &key, &actualValue);
    EXPECT_EQ(suite, lookupResult, -ENOENT);
  });

  EXPECT_TRUE(suite, sawMap);
}

static void testLoadAndCleanup(EBPFTestContext& context, const CompiledProgramFixture& fixture)
{
  if (haveRuntimeLoadSupport() == false)
  {
    context.skip("eBPF load smoke requires root or CAP_BPF on this host");
    return;
  }

  size_t baselineProgramCount = countProgramsNamed(kProgramName);
  String programName(kProgramName);

  {
    BPFProgram program;

    EXPECT_FALSE(context.suite(), program.load(fixture.objectPath, "missing_program"_ctv));
    EXPECT_TRUE(context.suite(), program.obj == nullptr);
    EXPECT_TRUE(context.suite(), program.prog == nullptr);
    EXPECT_EQ(context.suite(), program.prog_fd, -1);
    EXPECT_EQ(context.suite(), countProgramsNamed(kProgramName), baselineProgramCount);

    EXPECT_TRUE(context.suite(), program.load(fixture.objectPath, programName));
    if (program.prog_fd < 0)
    {
      return;
    }

    EXPECT_TRUE(context.suite(), program.obj != nullptr);
    EXPECT_TRUE(context.suite(), program.prog != nullptr);
    EXPECT_EQ(context.suite(), countProgramsNamed(kProgramName), baselineProgramCount + 1);

    exerciseMapOperations(context.suite(), program);

    program.close();
    EXPECT_TRUE(context.suite(), program.obj == nullptr);
    EXPECT_TRUE(context.suite(), program.prog == nullptr);
    EXPECT_EQ(context.suite(), program.prog_fd, -1);
    EXPECT_EQ(context.suite(), countProgramsNamed(kProgramName), baselineProgramCount);

    EXPECT_TRUE(context.suite(), program.load(fixture.objectPath, programName));
    EXPECT_TRUE(context.suite(), program.prog_fd >= 0);
    EXPECT_EQ(context.suite(), countProgramsNamed(kProgramName), baselineProgramCount + 1);
  }

  EXPECT_EQ(context.suite(), countProgramsNamed(kProgramName), baselineProgramCount);
}

static void testLoopbackXDPAttach(EBPFTestContext& context, const CompiledProgramFixture& fixture)
{
  if (haveRuntimeLoadSupport() == false)
  {
    context.skip("loopback XDP attach requires root or CAP_BPF on this host");
    return;
  }

  NetDevice loopback;
  initializeNetDevice(loopback);
  loopback.name = "lo"_ctv;
  loopback.getInfo();
  if (loopback.ifidx == 0)
  {
    context.skip("loopback interface lookup failed");
    return;
  }

  __u32 existingProgramID = 0;
  if (bpf_xdp_query_id(loopback.ifidx, XDP_FLAGS_SKB_MODE, &existingProgramID) != 0)
  {
    context.skip("loopback XDP query is unavailable on this host");
    return;
  }

  if (existingProgramID != 0)
  {
    context.skip("loopback already has an XDP program attached");
    return;
  }

  size_t baselineProgramCount = countProgramsNamed(kProgramName);
  String programName(kProgramName);
  BPFProgram *program = loopback.attachXDP(fixture.objectPath, programName, XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE);
  if (program == nullptr)
  {
    context.skip("loopback XDP attach failed on this host");
    return;
  }

  __u32 attachedProgramID = 0;
  EXPECT_EQ(context.suite(), bpf_xdp_query_id(loopback.ifidx, XDP_FLAGS_SKB_MODE, &attachedProgramID), 0);
  EXPECT_TRUE(context.suite(), attachedProgramID != 0);
  EXPECT_EQ(context.suite(), countProgramsNamed(kProgramName), baselineProgramCount + 1);

  exerciseMapOperations(context.suite(), *program);

  loopback.detachXDP();
  attachedProgramID = 0;
  EXPECT_EQ(context.suite(), bpf_xdp_query_id(loopback.ifidx, XDP_FLAGS_SKB_MODE, &attachedProgramID), 0);
  EXPECT_EQ(context.suite(), attachedProgramID, 0U);
  EXPECT_EQ(context.suite(), countProgramsNamed(kProgramName), baselineProgramCount);
}

static void testTCXLinkAttach(EBPFTestContext& context, const CompiledProgramFixture& fixture)
{
  if (haveRuntimeLoadSupport() == false)
  {
    context.skip("TCX attach requires root or CAP_BPF on this host");
    return;
  }

  std::string deviceName = "btcx" + std::to_string(getpid());
  std::string peerName = "btcp" + std::to_string(getpid());
  deviceName.resize(std::min(deviceName.size(), size_t(IFNAMSIZ - 1)));
  peerName.resize(std::min(peerName.size(), size_t(IFNAMSIZ - 1)));
  if (runCommand({"ip", "link", "add", deviceName, "type", "veth", "peer", "name", peerName}) != 0)
  {
    context.skip("TCX test veth creation is unavailable on this host");
    return;
  }

  auto removeVeth = [&] (void) -> void {
    (void)runCommand({"ip", "link", "del", deviceName});
  };

  NetDevice device;
  initializeNetDevice(device);
  device.name.assign(deviceName.c_str(), deviceName.size());
  device.getInfo();
  if (device.ifidx == 0)
  {
    removeVeth();
    context.skip("TCX test veth lookup failed");
    return;
  }

  size_t baselineProgramCount = countProgramsNamed(kTCXProgramName);
  BPFProgram *program = device.attachBPF(BPF_TCX_EGRESS, fixture.objectPath, String(kTCXProgramName));
  EXPECT_TRUE(context.suite(), program != nullptr);
  if (program != nullptr)
  {
    __u32 programID = 0;
    struct bpf_prog_query_opts opts = {};
    opts.sz = sizeof(opts);
    opts.prog_ids = &programID;
    opts.prog_cnt = 1;
    EXPECT_EQ(context.suite(), bpf_prog_query_opts(device.ifidx, BPF_TCX_EGRESS, &opts), 0);
    EXPECT_TRUE(context.suite(), programID != 0);
    EXPECT_EQ(context.suite(), countProgramsNamed(kTCXProgramName), baselineProgramCount + 1);

    device.detachBPF(BPF_TCX_EGRESS);
    programID = 0;
    opts.prog_cnt = 1;
    EXPECT_EQ(context.suite(), bpf_prog_query_opts(device.ifidx, BPF_TCX_EGRESS, &opts), 0);
    EXPECT_EQ(context.suite(), programID, 0U);
    EXPECT_EQ(context.suite(), countProgramsNamed(kTCXProgramName), baselineProgramCount);
  }

  removeVeth();
}

static void testPreattachedMapReopenDisambiguatesTruncatedNames(EBPFTestContext& context, const CompiledProgramFixture& fixture)
{
  if (haveRuntimeLoadSupport() == false)
  {
    context.skip("preattached XDP reopen requires root or CAP_BPF on this host");
    return;
  }

  NetDevice loopback;
  initializeNetDevice(loopback);
  loopback.name = "lo"_ctv;
  loopback.getInfo();
  if (loopback.ifidx == 0)
  {
    context.skip("loopback interface lookup failed");
    return;
  }

  __u32 existingProgramID = 0;
  if (bpf_xdp_query_id(loopback.ifidx, XDP_FLAGS_SKB_MODE, &existingProgramID) != 0)
  {
    context.skip("loopback XDP query is unavailable on this host");
    return;
  }

  if (existingProgramID != 0)
  {
    context.skip("loopback already has an XDP program attached");
    return;
  }

  BPFProgram *attached = loopback.attachXDP(fixture.objectPath, String(kProgramName), XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE);
  if (attached == nullptr)
  {
    context.skip("loopback XDP attach failed on this host");
    return;
  }

  NetDevice reopenedDevice;
  initializeNetDevice(reopenedDevice);
  reopenedDevice.name = "lo"_ctv;
  reopenedDevice.getInfo();
  BPFProgram *reopened = reopenedDevice.loadPreattachedProgram(BPF_XDP, fixture.objectPath);
  if (reopened == nullptr)
  {
    loopback.detachXDP();
    context.skip("loopback preattached XDP reopen failed on this host");
    return;
  }

  auto expectKeySizeForMap = [&] (const char *name, __u32 expectedKeySize) -> void {
    bool sawMap = false;
    reopened->openMap(String(name), [&] (int mapFD) -> void {
      sawMap = true;
      EXPECT_TRUE(context.suite(), mapFD >= 0);
      if (mapFD < 0)
      {
        return;
      }

      struct bpf_map_info info = {};
      __u32 infoLength = sizeof(info);
      EXPECT_EQ(context.suite(), bpf_map_get_info_by_fd(mapFD, &info, &infoLength), 0);
      EXPECT_EQ(context.suite(), info.key_size, expectedKeySize);
      EXPECT_EQ(context.suite(), info.id, findAttachedMapIDByNameAndKeySize(attached->prog_fd, name, expectedKeySize));

      if (expectedKeySize == 8)
      {
        struct
        {
          __u32 prefixlen;
          __u32 addr;
        } key4 = {
          .prefixlen = 32,
          .addr = 0x01020304,
        };
        __u8 expectedValue = 1;
        EXPECT_EQ(context.suite(), bpf_map_update_elem(mapFD, &key4, &expectedValue, BPF_ANY), 0);
        __u8 actualValue = 0;
        EXPECT_EQ(context.suite(), bpf_map_lookup_elem(mapFD, &key4, &actualValue), 0);
        EXPECT_EQ(context.suite(), actualValue, expectedValue);
      }
      else if (expectedKeySize == 20)
      {
        struct
        {
          __u32 prefixlen;
          __u32 addr[4];
        } key6 = {
          .prefixlen = 128,
          .addr = {0x01020304, 0x05060708, 0x11121314, 0x15161718},
        };
        __u8 expectedValue = 1;
        EXPECT_EQ(context.suite(), bpf_map_update_elem(mapFD, &key6, &expectedValue, BPF_ANY), 0);
        __u8 actualValue = 0;
        EXPECT_EQ(context.suite(), bpf_map_lookup_elem(mapFD, &key6, &actualValue), 0);
        EXPECT_EQ(context.suite(), actualValue, expectedValue);
      }
    });
    EXPECT_TRUE(context.suite(), sawMap);
  };

  expectKeySizeForMap(kOverlapMap4Name, 8);
  expectKeySizeForMap(kOverlapMap6Name, 20);

  reopenedDevice.detachXDP();
  loopback.detachXDP();
}

static void testPreattachedMapLoggingIsReleaseGated(EBPFTestContext& context, const CompiledProgramFixture& fixture)
{
  if (haveRuntimeLoadSupport() == false)
  {
    context.skip("preattached trace test requires root or CAP_BPF on this host");
    return;
  }

  ScopedTempDirectory traceDirectory = {};
  if (traceDirectory.valid() == false)
  {
    context.skip("preattached trace test temporary directory is unavailable");
    return;
  }

  // The linker wrappers redirect only this diagnostic literal. They are armed
  // before the actual attach/reopen so a debug build never writes the
  // production trace path either.
  PreattachedTraceIntercept::redirectedPath = traceDirectory.child("switchboard.attach.log");
  PreattachedTraceIntercept::diagnosticFDs.clear();
  PreattachedTraceIntercept::resetCounts();

  NetDevice loopback = {};
  initializeNetDevice(loopback);
  loopback.name = "lo"_ctv;
  loopback.getInfo();
  if (loopback.ifidx == 0)
  {
    PreattachedTraceIntercept::redirectedPath.clear();
    context.skip("loopback interface lookup failed");
    return;
  }

  __u32 existingProgramID = 0;
  if (bpf_xdp_query_id(loopback.ifidx, XDP_FLAGS_SKB_MODE, &existingProgramID) != 0 || existingProgramID != 0)
  {
    PreattachedTraceIntercept::redirectedPath.clear();
    context.skip("loopback is unavailable for isolated preattached trace coverage");
    return;
  }

  BPFProgram *attached = loopback.attachXDP(fixture.objectPath,
                                              String(kProgramName),
                                              XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE);
  if (attached == nullptr)
  {
    PreattachedTraceIntercept::redirectedPath.clear();
    context.skip("loopback XDP attach failed for preattached trace coverage");
    return;
  }

  uint32_t key = 17;
  uint64_t expectedValue = 0xB0F17ULL;
  bool seeded = false;
  attached->openMap(String(kMapName), [&](int mapFD) {
    seeded = mapFD >= 0 && bpf_map_update_elem(mapFD, &key, &expectedValue, BPF_ANY) == 0;
  });
  if (seeded == false)
  {
    loopback.detachXDP();
    PreattachedTraceIntercept::redirectedPath.clear();
    context.skip("attached map could not be seeded for preattached trace coverage");
    return;
  }

  NetDevice reopenedDevice = {};
  initializeNetDevice(reopenedDevice);
  reopenedDevice.name = "lo"_ctv;
  reopenedDevice.getInfo();
  BPFProgram *reopened = reopenedDevice.loadPreattachedProgram(BPF_XDP, fixture.objectPath);
  if (reopened == nullptr)
  {
    loopback.detachXDP();
    PreattachedTraceIntercept::redirectedPath.clear();
    context.skip("loopback preattached reopen failed for trace coverage");
    return;
  }

  // Exclude attach/reopen progress from the measurement. Each sample now
  // performs only successful preattached openMap resolutions and readback.
  PreattachedTraceIntercept::resetCounts();
  constexpr uint32_t samples = 30;
  constexpr uint32_t opensPerSample = 128;
  std::vector<uint64_t> elapsedUs = {};
  elapsedUs.reserve(samples);
  std::vector<uint64_t> cpuUs = {};
  cpuUs.reserve(samples);
  bool allResolved = true;
  for (uint32_t sample = 0; sample < samples; ++sample)
  {
    timespec cpuStarted = {};
    EXPECT_EQ(context.suite(), clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpuStarted), 0);
    const auto started = std::chrono::steady_clock::now();
    for (uint32_t open = 0; open < opensPerSample; ++open)
    {
      bool resolved = false;
      reopened->openMap(String(kMapName), [&](int mapFD) {
        struct bpf_map_info info = {};
        __u32 infoLength = sizeof(info);
        uint64_t actualValue = 0;
        resolved = mapFD >= 0 &&
                   bpf_map_get_info_by_fd(mapFD, &info, &infoLength) == 0 &&
                   objectNameMatches(kMapName, info.name) &&
                   bpf_map_lookup_elem(mapFD, &key, &actualValue) == 0 &&
                   actualValue == expectedValue;
      });
      allResolved = allResolved && resolved;
    }
    const auto finished = std::chrono::steady_clock::now();
    timespec cpuFinished = {};
    EXPECT_EQ(context.suite(), clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpuFinished), 0);
    elapsedUs.push_back(uint64_t(std::chrono::duration_cast<std::chrono::microseconds>(finished - started).count()));
    cpuUs.push_back(uint64_t((cpuFinished.tv_sec - cpuStarted.tv_sec) * 1000000000LL +
                            cpuFinished.tv_nsec - cpuStarted.tv_nsec) / 1000);
  }

  EXPECT_TRUE(context.suite(), allResolved);
#if BASICS_DEBUG
  const uint64_t expectedTraceRecords = uint64_t(samples) * opensPerSample * 2;
  EXPECT_EQ(context.suite(), PreattachedTraceIntercept::opens, expectedTraceRecords);
  EXPECT_EQ(context.suite(), PreattachedTraceIntercept::writes, expectedTraceRecords * 2);
  EXPECT_EQ(context.suite(), PreattachedTraceIntercept::closes, expectedTraceRecords);
#else
  EXPECT_EQ(context.suite(), PreattachedTraceIntercept::opens, 0U);
  EXPECT_EQ(context.suite(), PreattachedTraceIntercept::writes, 0U);
  EXPECT_EQ(context.suite(), PreattachedTraceIntercept::closes, 0U);
#endif

  std::cout << "PREATTACHED_TRACE_SAMPLE_US";
  for (uint64_t sample : elapsedUs)
  {
    std::cout << ' ' << sample;
  }
  std::cout << '\n';
  std::cout << "PREATTACHED_TRACE_CPU_SAMPLE_US";
  for (uint64_t sample : cpuUs)
  {
    std::cout << ' ' << sample;
  }
  std::cout << '\n';
  std::vector<uint64_t> sortedElapsedUs = elapsedUs;
  std::sort(sortedElapsedUs.begin(), sortedElapsedUs.end());
  std::sort(cpuUs.begin(), cpuUs.end());
  std::cout << "PREATTACHED_TRACE_P95_US "
            << sortedElapsedUs[(sortedElapsedUs.size() * 95 + 99) / 100 - 1] << '\n';
  std::cout << "PREATTACHED_TRACE_CPU_P95_US "
            << cpuUs[(cpuUs.size() * 95 + 99) / 100 - 1] << '\n';
  std::cout << "PREATTACHED_TRACE_COUNTS open=" << PreattachedTraceIntercept::opens
            << " write=" << PreattachedTraceIntercept::writes
            << " close=" << PreattachedTraceIntercept::closes << '\n';

  reopenedDevice.detachXDP();
  loopback.detachXDP();
  __u32 remainingProgramID = 0;
  EXPECT_EQ(context.suite(), bpf_xdp_query_id(loopback.ifidx, XDP_FLAGS_SKB_MODE, &remainingProgramID), 0);
  EXPECT_EQ(context.suite(), remainingProgramID, 0U);
  EXPECT_TRUE(context.suite(), PreattachedTraceIntercept::diagnosticFDs.empty());
  PreattachedTraceIntercept::diagnosticFDs.clear();
  PreattachedTraceIntercept::redirectedPath.clear();
}

} // namespace

int main()
{
  EBPFTestContext context;

  CompiledProgramFixture fixture;
  if (compileFixtureProgram(fixture) == false)
  {
    context.skip("clang with the BPF backend is unavailable");
    return context.finish();
  }

  const char *only = getenv("BASICS_TEST_ONLY");
  if (only != nullptr && strcmp(only, "preattached-logging") == 0)
  {
    testPreattachedMapLoggingIsReleaseGated(context, fixture);
    return context.finish();
  }

  testLoadAndCleanup(context, fixture);
  testLoopbackXDPAttach(context, fixture);

  CompiledProgramFixture tcxFixture;
  if (compileTCXFixtureProgram(tcxFixture) == false)
  {
    context.skip("clang with TCX BPF support is unavailable");
    return context.finish();
  }
  testTCXLinkAttach(context, tcxFixture);

  CompiledProgramFixture truncatedMapFixture;
  if (compileTruncatedMapFixtureProgram(truncatedMapFixture) == false)
  {
    context.skip("clang with the BPF backend is unavailable for truncated-map reopen coverage");
    return context.finish();
  }

  testPreattachedMapReopenDisambiguatesTruncatedNames(context, truncatedMapFixture);
  testPreattachedMapLoggingIsReleaseGated(context, fixture);
  return context.finish();
}
