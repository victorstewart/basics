// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <linux/openat2.h>
#include <net/if.h>
#include <sched.h>
#include <sys/wait.h>
#include <unistd.h>

#include "macros/bytes.h"

// These networking headers are not yet self-contained, so include the
// prerequisites explicitly in the order the current public surface expects.
#include "base/flat_hash_map.hpp"
#include "base/bytell_hash_map.hpp"
#include "types/types.containers.h"
#include "services/bitsery.h"
#include "networking/time.h"
#include "networking/ip.h"
#include "networking/socket.h"
#include "networking/msg.h"
#include "networking/pool.h"
#include "networking/eth.h"
#include "networking/netlink.h"
#include "networking/veth.h"

#include "services/filesystem.h"

namespace {

constexpr std::string_view kFilesystemSuite = "filesystem";
constexpr std::string_view kNetlinkReadonlySuite = "netlink_readonly";
constexpr std::string_view kVethNamespaceSuite = "veth_namespace";
constexpr const char *kHostIPv4Address = "10.123.45.1";
constexpr const char *kPeerIPv4Address = "10.123.45.2";

class LinuxIntegrationContext {
private:

  TestSuite suite_;
  int skipped_ = 0;
  bool runAll_ = false;
  std::vector<std::string> selectedSuites_;

  static bool isKnownSuite(std::string_view suite)
  {
    return suite == kFilesystemSuite || suite == kNetlinkReadonlySuite || suite == kVethNamespaceSuite || suite == "all";
  }

public:

  explicit LinuxIntegrationContext(int argc, char **argv)
  {
    for (int index = 1; index < argc; ++index)
    {
      std::string_view argument(argv[index]);

      if (argument == "--list-suites")
      {
        std::cout << kFilesystemSuite << '\n'
                  << kNetlinkReadonlySuite << '\n'
                  << kVethNamespaceSuite << '\n';
        std::exit(0);
      }

      std::string suiteName;
      if (argument == "--suite")
      {
        if (index + 1 >= argc)
        {
          std::cerr << "--suite requires a value\n";
          std::exit(2);
        }

        suiteName = argv[++index];
      }
      else if (argument.starts_with("--suite="))
      {
        suiteName = std::string(argument.substr(sizeof("--suite=") - 1));
      }
      else
      {
        std::cerr << "unknown argument: " << argument << '\n';
        std::exit(2);
      }

      if (isKnownSuite(suiteName) == false)
      {
        std::cerr << "unknown suite: " << suiteName << '\n';
        std::exit(2);
      }

      if (suiteName == "all")
      {
        runAll_ = true;
      }
      else
      {
        selectedSuites_.push_back(suiteName);
      }
    }
  }

  TestSuite& suite()
  {
    return suite_;
  }

  bool shouldRun(std::string_view suiteName) const
  {
    if (runAll_)
    {
      return true;
    }

    if (selectedSuites_.empty())
    {
      return suiteName == kFilesystemSuite || suiteName == kNetlinkReadonlySuite || suiteName == kVethNamespaceSuite;
    }

    return std::find(selectedSuites_.begin(), selectedSuites_.end(), suiteName) != selectedSuites_.end();
  }

  void skip(std::string_view suiteName, std::string_view reason)
  {
    ++skipped_;
    std::cout << "skip " << suiteName << ": " << reason << '\n';
  }

  int finish()
  {
    if (skipped_ > 0)
    {
      std::cout << skipped_ << " linux integration suite(s) skipped.\n";
    }

    return suite_.finish("linux integration tests");
  }
};

class TempDirectory {
private:

  std::array<char, 64> path_ {};
  bool valid_ = false;

public:

  TempDirectory()
  {
    std::snprintf(path_.data(), path_.size(), "/tmp/basics-linux-XXXXXX");
    valid_ = (mkdtemp(path_.data()) != nullptr);
  }

  ~TempDirectory()
  {
    if (valid_)
    {
      Filesystem::eraseDirectory(String(path_.data()));
    }
  }

  bool valid() const
  {
    return valid_;
  }

  const char *path() const
  {
    return path_.data();
  }
};

static void initializeNetDevice(NetDevice& device)
{
  device.ifidx = 0;
  memset(device.mac, 0, sizeof(device.mac));
}

static std::string makePath(const char *root, std::string_view child)
{
  std::string path(root);
  path.push_back('/');
  path.append(child);
  return path;
}

static void testFilesystemSuite(LinuxIntegrationContext& context)
{
  if (context.shouldRun(kFilesystemSuite) == false)
  {
    return;
  }

  TempDirectory tempDirectory;
  EXPECT_TRUE(context.suite(), tempDirectory.valid());
  if (tempDirectory.valid() == false)
  {
    return;
  }

  errno = 0;
  int rootFd = Filesystem::openDirectoryAt(-1, String(tempDirectory.path()));
  if (rootFd < 0 && errno == ENOSYS)
  {
    context.skip(kFilesystemSuite, "openat2 is unavailable on this kernel");
    return;
  }

  EXPECT_TRUE(context.suite(), rootFd >= 0);
  if (rootFd < 0)
  {
    return;
  }

  int subdirFd = Filesystem::createOpenDirectoryAt(rootFd, "subdir"_ctv);
  EXPECT_TRUE(context.suite(), subdirFd >= 0);
  if (subdirFd < 0)
  {
    close(rootFd);
    return;
  }

  EXPECT_EQ(context.suite(), Filesystem::openWriteAtClose(subdirFd, "payload.txt"_ctv, "payload-data"_ctv), int("payload-data"_ctv.size()));

  String payload;
  Filesystem::openReadAtClose(subdirFd, "payload.txt"_ctv, payload);
  EXPECT_STRING_EQ(context.suite(), payload, "payload-data"_ctv);

  std::string oldPath = makePath(tempDirectory.path(), "subdir/payload.txt");
  std::string newPath = makePath(tempDirectory.path(), "subdir/renamed.txt");
  EXPECT_EQ(context.suite(), Filesystem::renameFile(String(oldPath.c_str()), String(newPath.c_str())), 0);

  String renamed;
  Filesystem::openReadAtClose(subdirFd, "renamed.txt"_ctv, renamed);
  EXPECT_STRING_EQ(context.suite(), renamed, "payload-data"_ctv);

  EXPECT_EQ(context.suite(), Filesystem::openWriteAtClose(rootFd, "outside.txt"_ctv, "outside"_ctv), int("outside"_ctv.size()));
  EXPECT_EQ(context.suite(), symlinkat("../outside.txt", subdirFd, "escape"), 0);

  errno = 0;
  int escapedFd = Filesystem::openFileAt(subdirFd, "escape"_ctv, O_RDONLY | O_CLOEXEC, 0, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS);
  EXPECT_TRUE(context.suite(), escapedFd < 0);
  if (escapedFd >= 0)
  {
    close(escapedFd);
  }

  close(subdirFd);
  close(rootFd);
}

static void testNetlinkReadonlySuite(LinuxIntegrationContext& context)
{
  if (context.shouldRun(kNetlinkReadonlySuite) == false)
  {
    return;
  }

  NetDevice loopback;
  initializeNetDevice(loopback);
  loopback.socket.configure();
  loopback.name = "lo"_ctv;
  loopback.getInfo();

  EXPECT_TRUE(context.suite(), loopback.ifidx > 0);

  NetlinkStream routes;
  routes.socket.configure();
  routes.generateRequest([&](NetlinkMessage *request) -> void {
    routes.socket.getRoutes(request, 1);
  });

  EXPECT_TRUE(context.suite(), routes.flushChecked());

  int routeMessages = 0;
  while (routes.nPendingResponses > 0)
  {
    EXPECT_TRUE(context.suite(), routes.readResponseChecked([&](uint16_t nlmsgType, uint32_t, void *nlmsgData, uint32_t) -> void {
      if (nlmsgType == RTM_NEWROUTE && nlmsgData != nullptr)
      {
        ++routeMessages;
      }
    }));
  }

  EXPECT_TRUE(context.suite(), routeMessages > 0);
}

static void closePipePair(int pipes[2])
{
  if (pipes[0] >= 0)
  {
    close(pipes[0]);
    pipes[0] = -1;
  }

  if (pipes[1] >= 0)
  {
    close(pipes[1]);
    pipes[1] = -1;
  }
}

static void closeFd(int& fd)
{
  if (fd >= 0)
  {
    close(fd);
    fd = -1;
  }
}

template <typename T>
static bool writeExact(int fd, const T& value)
{
  const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&value);
  size_t remaining = sizeof(T);

  while (remaining > 0)
  {
    ssize_t written = write(fd, bytes, remaining);
    if (written <= 0)
    {
      return false;
    }

    bytes += written;
    remaining -= size_t(written);
  }

  return true;
}

template <typename T>
static bool readExact(int fd, T& value)
{
  uint8_t *bytes = reinterpret_cast<uint8_t *>(&value);
  size_t remaining = sizeof(T);

  while (remaining > 0)
  {
    ssize_t count = read(fd, bytes, remaining);
    if (count <= 0)
    {
      return false;
    }

    bytes += count;
    remaining -= size_t(count);
  }

  return true;
}

static uint32_t ipv4Address(const char *address)
{
  uint32_t value = 0;
  inet_pton(AF_INET, address, &value);
  return value;
}

struct NamespacePeerReport {
  char status = 'F';
  int32_t ifidx = 0;
  uint32_t private4 = 0;
  uint32_t gateway4 = 0;
};

static void testVethNamespaceSuite(LinuxIntegrationContext& context)
{
  if (context.shouldRun(kVethNamespaceSuite) == false)
  {
    return;
  }

  int parentToChild[2] = {-1, -1};
  int childToParent[2] = {-1, -1};
  int hostNetnsFd = -1;
  int childNetnsFd = -1;

  if (pipe(parentToChild) != 0 || pipe(childToParent) != 0)
  {
    EXPECT_TRUE(context.suite(), false);
    closePipePair(parentToChild);
    closePipePair(childToParent);
    return;
  }

  String baseName;
  baseName.snprintf<"bn{itoa}"_ctv>(uint64_t(getpid()));

  String hostName;
  hostName.snprintf<"{}_veth0"_ctv>(baseName);

  String peerName;
  peerName.snprintf<"{}_veth1"_ctv>(baseName);

  pid_t child = fork();
  EXPECT_TRUE(context.suite(), child >= 0);
  if (child < 0)
  {
    closePipePair(parentToChild);
    closePipePair(childToParent);
    return;
  }

  if (child == 0)
  {
    close(parentToChild[1]);
    close(childToParent[0]);

    char status = 'F';
    if (unshare(CLONE_NEWNET) != 0)
    {
      status = (errno == EPERM || errno == EINVAL || errno == ENOSYS) ? 'S' : 'F';
      write(childToParent[1], &status, 1);
      _exit(status == 'S' ? 0 : 1);
    }

    status = 'R';
    write(childToParent[1], &status, 1);

    char command = 0;
    if (read(parentToChild[0], &command, 1) != 1)
    {
      _exit(2);
    }

    if (command != 'G')
    {
      _exit(0);
    }

    EthDevice peer;
    initializeNetDevice(peer);
    peer.socket.configure();
    peer.setDevice(peerName);

    NamespacePeerReport report;
    report.ifidx = peer.ifidx;

    if (peer.ifidx <= 0)
    {
      status = 'F';
      report.status = status;
      writeExact(childToParent[1], report);
      _exit(3);
    }

    peer.generateRequest([&](NetlinkMessage *request) -> void {
      peer.socket.bringUpInterface(request, 0, peer.ifidx);
    });
    if (peer.flushDiscardChecked() == false)
    {
      report.status = 'F';
      writeExact(childToParent[1], report);
      _exit(4);
    }

    peer.generateRequest([&](NetlinkMessage *request) -> void {
      peer.socket.addIPtoInterface(request, 0, String(kPeerIPv4Address), 24, false, peer.ifidx);
    });
    if (peer.flushDiscardChecked() == false)
    {
      report.status = 'F';
      writeExact(childToParent[1], report);
      _exit(5);
    }

    peer.generateRequest([&](NetlinkMessage *request) -> void {
      peer.socket.addRoute(request, 0, peer.ifidx, IPPrefix(), IPAddress(kHostIPv4Address, false), IPAddress());
    });
    if (peer.flushDiscardChecked() == false)
    {
      report.status = 'F';
      writeExact(childToParent[1], report);
      _exit(6);
    }

    report.private4 = peer.getPrivate4();
    report.gateway4 = peer.getPrivate4Gateway(report.private4);

    const uint32_t expectedPeerIPv4 = ipv4Address(kPeerIPv4Address);
    const uint32_t expectedGatewayIPv4 = ipv4Address(kHostIPv4Address);
    report.status = (report.ifidx > 0 && report.private4 == expectedPeerIPv4 && report.gateway4 == expectedGatewayIPv4) ? 'P' : 'F';
    writeExact(childToParent[1], report);
    _exit(report.status == 'P' ? 0 : 7);
  }

  close(parentToChild[0]);
  close(childToParent[1]);

  char childStatus = 0;
  if (read(childToParent[0], &childStatus, 1) != 1)
  {
    EXPECT_TRUE(context.suite(), false);
    closePipePair(parentToChild);
    closePipePair(childToParent);
    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);
    return;
  }

  if (childStatus == 'S')
  {
    context.skip(kVethNamespaceSuite, "CLONE_NEWNET is unavailable or not permitted on this host");
    closePipePair(parentToChild);
    closePipePair(childToParent);
    waitpid(child, nullptr, 0);
    return;
  }

  EXPECT_EQ(context.suite(), childStatus, 'R');
  if (childStatus != 'R')
  {
    closePipePair(parentToChild);
    closePipePair(childToParent);
    waitpid(child, nullptr, 0);
    return;
  }

  VethPair pair;
  initializeNetDevice(pair.host);
  initializeNetDevice(pair.peer);
  pair.socket.configure();
  pair.host.name = hostName;
  pair.peer.name = peerName;

  pair.generateRequest([&](NetlinkMessage *request) -> void {
    pair.socket.createVethPair(request, 0, pair.host.name, pair.peer.name, child);
  });

  if (pair.flushDiscardChecked() == false)
  {
    context.skip(kVethNamespaceSuite, "creating the veth pair failed; CAP_NET_ADMIN is likely unavailable");
    char quit = 'Q';
    write(parentToChild[1], &quit, 1);
    closePipePair(parentToChild);
    closePipePair(childToParent);
    waitpid(child, nullptr, 0);
    return;
  }

  pair.getInfo();
  EXPECT_TRUE(context.suite(), pair.host.ifidx > 0);

  pair.host.socket.configure();
  pair.host.generateRequest([&](NetlinkMessage *request) -> void {
    pair.host.socket.bringUpInterface(request, 0, pair.host.ifidx);
  });
  EXPECT_TRUE(context.suite(), pair.host.flushDiscardChecked());

  pair.host.generateRequest([&](NetlinkMessage *request) -> void {
    pair.host.socket.addIPtoInterface(request, 0, String(kHostIPv4Address), 24, false, pair.host.ifidx);
  });
  EXPECT_TRUE(context.suite(), pair.host.flushDiscardChecked());

  hostNetnsFd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
  EXPECT_TRUE(context.suite(), hostNetnsFd >= 0);
  if (hostNetnsFd >= 0)
  {
    char childNamespacePath[64] = {0};
    std::snprintf(childNamespacePath, sizeof(childNamespacePath), "/proc/%d/ns/net", child);
    childNetnsFd = open(childNamespacePath, O_RDONLY | O_CLOEXEC);
    EXPECT_TRUE(context.suite(), childNetnsFd >= 0);
  }

  if (hostNetnsFd >= 0 && childNetnsFd >= 0)
  {
    NetDevice peerFromHost;
    initializeNetDevice(peerFromHost);
    peerFromHost.name = peerName;
    peerFromHost.moveSocketToNamespace(childNetnsFd, hostNetnsFd);
    peerFromHost.getInfo();
    EXPECT_TRUE(context.suite(), peerFromHost.ifidx > 0);
  }

  char go = 'G';
  EXPECT_EQ(context.suite(), write(parentToChild[1], &go, 1), ssize_t(1));

  NamespacePeerReport peerReport;
  EXPECT_TRUE(context.suite(), readExact(childToParent[0], peerReport));
  EXPECT_EQ(context.suite(), peerReport.status, 'P');
  EXPECT_TRUE(context.suite(), peerReport.ifidx > 0);
  EXPECT_EQ(context.suite(), peerReport.private4, ipv4Address(kPeerIPv4Address));
  EXPECT_EQ(context.suite(), peerReport.gateway4, ipv4Address(kHostIPv4Address));

  int childExitStatus = 0;
  EXPECT_EQ(context.suite(), waitpid(child, &childExitStatus, 0), child);
  EXPECT_TRUE(context.suite(), WIFEXITED(childExitStatus));
  EXPECT_EQ(context.suite(), WEXITSTATUS(childExitStatus), 0);

  pair.destroyPair();
  EXPECT_EQ(context.suite(), pair.host.ifidx, uint32_t(0));
  EXPECT_EQ(context.suite(), pair.peer.ifidx, uint32_t(0));

  NetDevice destroyedHost;
  initializeNetDevice(destroyedHost);
  destroyedHost.name = hostName;
  destroyedHost.getInfo();
  EXPECT_EQ(context.suite(), destroyedHost.ifidx, uint32_t(0));

  closeFd(hostNetnsFd);
  closeFd(childNetnsFd);
  closePipePair(parentToChild);
  closePipePair(childToParent);
}

} // namespace

int main(int argc, char **argv)
{
  LinuxIntegrationContext context(argc, argv);

  testFilesystemSuite(context);
  testNetlinkReadonlySuite(context);
  testVethNamespaceSuite(context);

  return context.finish();
}
