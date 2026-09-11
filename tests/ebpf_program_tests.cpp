// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <linux/if_link.h>
#include <net/if.h>
#include <string_view>
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

namespace {

constexpr const char *kProgramName = "xdp_pass";
constexpr const char *kTCXProgramName = "tcx_pass";
constexpr const char *kMapName = "counters";
constexpr const char *kOverlapMap4Name = "wh_egress4";
constexpr const char *kOverlapMap6Name = "wh_egress";

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

static bool compilePreattachedPrefixMapFixtureProgram(CompiledProgramFixture& fixture)
{
  if (fixture.tempDirectory.valid() == false)
  {
    return false;
  }

  fixture.sourcePath = fixture.tempDirectory.child("xdp_prefix_maps.c");
  fixture.objectPath = fixture.tempDirectory.child("xdp_prefix_maps.o");
  std::ofstream source(fixture.sourcePath);
  if (source.is_open() == false)
  {
    return false;
  }

  source
    << "#include <linux/bpf.h>\n"
    << "#include <bpf/bpf_helpers.h>\n"
    << "struct key4 { __u32 prefixlen; __u32 addr; };\n"
    << "struct key10 { __u8 bytes[10]; };\n"
    << "struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4); __type(key, struct key10); __type(value, __u8[32]); } " << kOverlapMap6Name << " SEC(\".maps\");\n"
    << "struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4); __type(key, struct key4); __type(value, __u8[32]); } " << kOverlapMap4Name << " SEC(\".maps\");\n"
    << "SEC(\"xdp\") int " << kProgramName << "(struct xdp_md *ctx) {\n"
    << "  struct key10 key10 = {};\n"
    << "  struct key4 key4 = {};\n"
    << "  __u8 *value10 = bpf_map_lookup_elem(&" << kOverlapMap6Name << ", &key10);\n"
    << "  __u8 *value4 = bpf_map_lookup_elem(&" << kOverlapMap4Name << ", &key4);\n"
    << "  return (value10 || value4) ? XDP_PASS : XDP_PASS;\n"
    << "}\n"
    << "char LICENSE[] SEC(\"license\") = \"GPL\";\n";
  source.close();
  if (source.good() == false)
  {
    return false;
  }
  return runCommand({"clang", "-O2", "-g", "-target", "bpf", "-c", fixture.sourcePath, "-o", fixture.objectPath}) == 0;
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
  return requestedName.size() == candidateLength && memcmp(requestedName.data(), candidateName, requestedName.size()) == 0;
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

static void testPreattachedMapReopenKeepsPrefixNamesDistinct(EBPFTestContext& context, const CompiledProgramFixture& fixture)
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
    context.skip("loopback XDP query is unavailable");
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

  // Force the public retained-FD name fallback; restore the owned object before cleanup.
  struct bpf_object *savedObject = reopened->obj;
  reopened->obj = nullptr;
  auto expectMapShape = [&] (const char *name, __u32 keySize, __u32 valueSize) -> void {
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
      EXPECT_EQ(context.suite(), info.key_size, keySize);
      EXPECT_EQ(context.suite(), info.value_size, valueSize);
      EXPECT_EQ(context.suite(), info.id, findAttachedMapIDByNameAndKeySize(attached->prog_fd, name, keySize));
      if (info.key_size != keySize || info.value_size != valueSize)
      {
        return;
      }
      __u8 expected[32] = {};
      __u8 actual[32] = {};
      expected[0] = static_cast<__u8>(keySize);
      expected[31] = 0xa5;
      if (keySize == 8)
      {
        struct { __u32 prefixlen; __u32 addr; } key = {.prefixlen = 32, .addr = 0x01020304};
        EXPECT_EQ(context.suite(), bpf_map_update_elem(mapFD, &key, expected, BPF_ANY), 0);
        EXPECT_EQ(context.suite(), bpf_map_lookup_elem(mapFD, &key, actual), 0);
      }
      else
      {
        struct { __u8 bytes[10]; } key = {.bytes = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}};
        EXPECT_EQ(context.suite(), bpf_map_update_elem(mapFD, &key, expected, BPF_ANY), 0);
        EXPECT_EQ(context.suite(), bpf_map_lookup_elem(mapFD, &key, actual), 0);
      }
      EXPECT_EQ(context.suite(), memcmp(actual, expected, sizeof(expected)), 0);
    });
    EXPECT_TRUE(context.suite(), sawMap);
  };
  expectMapShape(kOverlapMap4Name, 8, 32);
  expectMapShape(kOverlapMap6Name, 10, 32);
  reopened->obj = savedObject;
  reopenedDevice.detachXDP();
  loopback.detachXDP();
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

  testLoadAndCleanup(context, fixture);
  testLoopbackXDPAttach(context, fixture);

  CompiledProgramFixture tcxFixture;
  if (compileTCXFixtureProgram(tcxFixture) == false)
  {
    context.skip("clang with TCX BPF support is unavailable");
    return context.finish();
  }
  testTCXLinkAttach(context, tcxFixture);

  CompiledProgramFixture prefixMapFixture;
  if (compilePreattachedPrefixMapFixtureProgram(prefixMapFixture) == false)
  {
    context.skip("clang with the BPF backend is unavailable for prefix-map reopen coverage");
    return context.finish();
  }

  testPreattachedMapReopenKeepsPrefixNamesDistinct(context, prefixMapFixture);
  return context.finish();
}
