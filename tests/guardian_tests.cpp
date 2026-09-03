// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include "tests/test_support.h"

#include <cerrno>
#include <cstdio>
#include <csignal>
#include <fcntl.h>
#include <pthread.h>
#include <sys/wait.h>
#include <unistd.h>

#include "networking/guardian.h"

namespace {

static void hangIfCalled()
{
  while (true)
  {
    pause();
  }
}

static bool waitForChild(pid_t child, int& status)
{
  for (int attempt = 0; attempt < 200; ++attempt)
  {
    pid_t result = waitpid(child, &status, WNOHANG);
    if (result == child)
    {
      return true;
    }
    if (result < 0 && errno != EINTR)
    {
      break;
    }
    usleep(10'000);
  }

  kill(child, SIGKILL);
  waitpid(child, &status, 0);
  return false;
}

static void *bootGuardian(void *)
{
  Guardian::boot();
  return nullptr;
}

static void testFatalSignalExitsWithoutForkOrUnsafeShutdown(TestSuite& suite, int signalNumber)
{
  char reportPath[] = "/tmp/basics-guardian-XXXXXX";
  int reportFD = mkstemp(reportPath);
  EXPECT_TRUE(suite, reportFD >= 0);
  if (reportFD < 0)
  {
    return;
  }
  close(reportFD);

  int stderrPipe[2] = {-1, -1};
  EXPECT_EQ(suite, pipe(stderrPipe), 0);
  if (stderrPipe[0] < 0 || stderrPipe[1] < 0)
  {
    unlink(reportPath);
    return;
  }

  Guardian::crashReportPath.assign(reportPath);
  pid_t child = fork();
  EXPECT_TRUE(suite, child >= 0);
  if (child == 0)
  {
    close(stderrPipe[0]);
    if (dup2(stderrPipe[1], STDERR_FILENO) < 0)
    {
      _exit(98);
    }
    close(stderrPipe[1]);
    pthread_atfork(hangIfCalled, nullptr, nullptr);
    Guardian::shutdownSequence = hangIfCalled;
    Guardian::boot();
    raise(signalNumber);
    _exit(99);
  }

  close(stderrPipe[1]);

  int status = 0;
  bool exited = child > 0 && waitForChild(child, status);

  EXPECT_TRUE(suite, exited);
  EXPECT_TRUE(suite, exited && WIFEXITED(status));
  EXPECT_TRUE(suite, exited && WEXITSTATUS(status) == EXIT_FAILURE);

  char report[128] = {};
  reportFD = open(reportPath, O_RDONLY);
  ssize_t reportSize = reportFD >= 0 ? read(reportFD, report, sizeof(report)) : -1;
  if (reportFD >= 0)
  {
    close(reportFD);
  }

  std::string_view reportView(report, reportSize > 0 ? size_t(reportSize) : 0);
  char expectedPrefix[64] = {};
  std::snprintf(
      expectedPrefix,
      sizeof(expectedPrefix),
      "Caught fatal signal %d code ",
      signalNumber);
  EXPECT_TRUE(suite, reportSize > 0);
  EXPECT_TRUE(suite, reportView.starts_with(expectedPrefix));
  EXPECT_TRUE(suite, reportView.find(" address 0x") != std::string_view::npos);
  EXPECT_TRUE(suite, reportView.find(" pc 0x") != std::string_view::npos);
  EXPECT_TRUE(suite, reportView.ends_with("\n"));

  char stderrReport[128] = {};
  ssize_t stderrReportSize = read(stderrPipe[0], stderrReport, sizeof(stderrReport));
  close(stderrPipe[0]);
  EXPECT_EQ(suite, stderrReportSize, reportSize);
  EXPECT_TRUE(
      suite,
      stderrReportSize == reportSize &&
          std::string_view(stderrReport, size_t(stderrReportSize)) == reportView);

  Guardian::crashReportPath.assign("/crashreport.txt");
  unlink(reportPath);
}

static void testRepeatedBootPreservesPreparedCrashReport(TestSuite& suite)
{
  char reportPath[] = "/tmp/basics-guardian-reboot-XXXXXX";
  int reportFD = mkstemp(reportPath);
  EXPECT_TRUE(suite, reportFD >= 0);
  if (reportFD < 0)
  {
    return;
  }
  close(reportFD);

  Guardian::crashReportPath.assign(reportPath);
  pid_t child = fork();
  EXPECT_TRUE(suite, child >= 0);
  if (child == 0)
  {
    Guardian::boot();
    Guardian::crashReportPath.assign("/not-a-real-directory/crashreport.txt");
    Guardian::boot();
    raise(SIGTRAP);
    _exit(99);
  }

  int status = 0;
  bool exited = child > 0 && waitForChild(child, status);
  EXPECT_TRUE(suite, exited);
  EXPECT_TRUE(suite, exited && WIFEXITED(status));
  EXPECT_TRUE(suite, exited && WEXITSTATUS(status) == EXIT_FAILURE);

  char report[128] = {};
  reportFD = open(reportPath, O_RDONLY);
  ssize_t reportSize = reportFD >= 0 ? read(reportFD, report, sizeof(report)) : -1;
  if (reportFD >= 0)
  {
    close(reportFD);
  }
  EXPECT_TRUE(suite, reportSize > 0);
  char expectedPrefix[64] = {};
  std::snprintf(expectedPrefix, sizeof(expectedPrefix), "Caught fatal signal %d code ", SIGTRAP);
  EXPECT_TRUE(
      suite,
      std::string_view(report, reportSize > 0 ? size_t(reportSize) : 0)
          .starts_with(expectedPrefix));

  Guardian::crashReportPath.assign("/crashreport.txt");
  unlink(reportPath);
}

static void testInvalidPathFallsBackToStandardError(TestSuite& suite)
{
  int stderrPipe[2] = {-1, -1};
  EXPECT_EQ(suite, pipe(stderrPipe), 0);
  if (stderrPipe[0] < 0 || stderrPipe[1] < 0)
  {
    return;
  }

  Guardian::crashReportPath.assign("/not-a-real-directory/crashreport.txt");
  pid_t child = fork();
  EXPECT_TRUE(suite, child >= 0);
  if (child == 0)
  {
    close(stderrPipe[0]);
    if (dup2(stderrPipe[1], STDERR_FILENO) < 0)
    {
      _exit(98);
    }
    close(stderrPipe[1]);
    Guardian::boot();
    raise(SIGABRT);
    _exit(99);
  }

  close(stderrPipe[1]);
  int status = 0;
  bool exited = child > 0 && waitForChild(child, status);
  EXPECT_TRUE(suite, exited);
  EXPECT_TRUE(suite, exited && WIFEXITED(status));
  EXPECT_TRUE(suite, exited && WEXITSTATUS(status) == EXIT_FAILURE);

  char output[512] = {};
  ssize_t outputSize = read(stderrPipe[0], output, sizeof(output));
  close(stderrPipe[0]);
  std::string_view outputView(output, outputSize > 0 ? size_t(outputSize) : 0);
  char expectedPrefix[64] = {};
  std::snprintf(expectedPrefix, sizeof(expectedPrefix), "Caught fatal signal %d code ", SIGABRT);
  EXPECT_TRUE(suite, outputSize > 0);
  EXPECT_TRUE(suite, outputView.find(expectedPrefix) != std::string_view::npos);

  Guardian::crashReportPath.assign("/crashreport.txt");
}

static void testConcurrentBootPreparesOneCrashReport(TestSuite& suite)
{
  char reportPath[] = "/tmp/basics-guardian-concurrent-XXXXXX";
  int reportFD = mkstemp(reportPath);
  EXPECT_TRUE(suite, reportFD >= 0);
  if (reportFD < 0)
  {
    return;
  }
  close(reportFD);

  Guardian::crashReportPath.assign(reportPath);
  pid_t child = fork();
  EXPECT_TRUE(suite, child >= 0);
  if (child == 0)
  {
    pthread_t threads[8];
    for (pthread_t& thread : threads)
    {
      if (pthread_create(&thread, nullptr, bootGuardian, nullptr) != 0)
      {
        _exit(98);
      }
    }
    for (pthread_t thread : threads)
    {
      if (pthread_join(thread, nullptr) != 0)
      {
        _exit(98);
      }
    }
    raise(SIGTRAP);
    _exit(99);
  }

  int status = 0;
  bool exited = child > 0 && waitForChild(child, status);
  EXPECT_TRUE(suite, exited);
  EXPECT_TRUE(suite, exited && WIFEXITED(status));
  EXPECT_TRUE(suite, exited && WEXITSTATUS(status) == EXIT_FAILURE);

  char report[128] = {};
  reportFD = open(reportPath, O_RDONLY);
  ssize_t reportSize = reportFD >= 0 ? read(reportFD, report, sizeof(report)) : -1;
  if (reportFD >= 0)
  {
    close(reportFD);
  }
  char expectedPrefix[64] = {};
  std::snprintf(expectedPrefix, sizeof(expectedPrefix), "Caught fatal signal %d code ", SIGTRAP);
  EXPECT_TRUE(suite, reportSize > 0);
  EXPECT_TRUE(
      suite,
      std::string_view(report, reportSize > 0 ? size_t(reportSize) : 0)
          .starts_with(expectedPrefix));

  Guardian::crashReportPath.assign("/crashreport.txt");
  unlink(reportPath);
}

} // namespace

int main()
{
  TestSuite suite;
  testFatalSignalExitsWithoutForkOrUnsafeShutdown(suite, SIGSEGV);
  testFatalSignalExitsWithoutForkOrUnsafeShutdown(suite, SIGTRAP);
  testFatalSignalExitsWithoutForkOrUnsafeShutdown(suite, SIGABRT);
  testRepeatedBootPreservesPreparedCrashReport(suite);
  testInvalidPathFallsBackToStandardError(suite);
  testConcurrentBootPreparesOneCrashReport(suite);
  return suite.finish("guardian tests");
}
