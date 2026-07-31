// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <networking/includes.h>
#include <services/filesystem.h>
#include <csignal>
#include <cstdlib>
#include <functional>
#include <mutex>

#pragma once

class Guardian {
private:

  // https://www.gnu.org/software/libc/manual/html_node/Standard-Signals.html

  constexpr static int block_these_signals[] = {
      SIGHUP,
      SIGQUIT,
      SIGUSR1,
      SIGUSR2,
      SIGPIPE,
      SIGALRM,
      SIGTERM,
      SIGSTKFLT,
      SIGCHLD,
      SIGCONT,
      SIGTSTP,
      SIGTTIN,
      SIGTTOU,
      SIGURG, // MSG_OOB
      SIGXCPU,
      SIGXFSZ,
      SIGVTALRM,
      SIGPROF,
      SIGWINCH,
      SIGPOLL, // == SIGIO
      SIGPWR,
      SIGINT,
      SIGSYS};

  // can never catch or block or handle SIGKILL and SIGSTOP

  // we catch some of these with signalfd

  constexpr static int terminate_on_these_signals[] = {
      SIGBUS,
      SIGFPE,
      SIGILL,
      SIGSEGV,
      SIGABRT,
      SIGTRAP};

  static inline volatile sig_atomic_t crashReportFD = -1;
  static inline std::once_flag crashReportOnce;

  template <size_t N>
  [[gnu::always_inline]] static inline void appendLiteral(char *report, size_t& size, const char (&literal)[N])
  {
    for (size_t i = 0; i + 1 < N; ++i)
    {
      report[size++] = literal[i];
    }
  }

  [[gnu::always_inline]] static inline void appendUnsigned(char *report, size_t& size, uint64_t value)
  {
    char digits[20];
    size_t digitsSize = 0;

    do
    {
      digits[digitsSize++] = char('0' + (value % 10));
      value /= 10;
    }
    while (value != 0);

    while (digitsSize != 0)
    {
      report[size++] = digits[--digitsSize];
    }
  }

  [[gnu::always_inline]] static inline void appendSigned(char *report, size_t& size, int64_t value)
  {
    if (value < 0)
    {
      report[size++] = '-';
      appendUnsigned(report, size, uint64_t(-(value + 1)) + 1);
      return;
    }

    appendUnsigned(report, size, uint64_t(value));
  }

  [[gnu::always_inline]] static inline void appendHex(char *report, size_t& size, uintptr_t value)
  {
    constexpr char digits[] = "0123456789abcdef";
    bool significant = false;

    for (int shift = int(sizeof(value) * 8) - 4; shift >= 0; shift -= 4)
    {
      uint8_t digit = uint8_t((value >> shift) & 0xf);
      if (digit != 0 || significant || shift == 0)
      {
        significant = true;
        report[size++] = digits[digit];
      }
    }
  }

  [[gnu::always_inline]] static inline size_t generateCrashReport(char *report, int sig, siginfo_t *info)
  {
    size_t size = 0;
    appendLiteral(report, size, "Caught fatal signal ");
    appendSigned(report, size, sig);
    appendLiteral(report, size, " code ");
    appendSigned(report, size, info ? info->si_code : 0);
    appendLiteral(report, size, " address 0x");
    appendHex(report, size, reinterpret_cast<uintptr_t>(info ? info->si_addr : nullptr));
    report[size++] = '\n';
    return size;
  }

  static void prepareCrashReport()
  {
    if (crashReportFD >= 0)
    {
      return;
    }

    int reportFD = Filesystem::openFileAt(
        -1,
        crashReportPath,
        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NONBLOCK,
        S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (reportFD < 0)
    {
      dprintf(
          STDERR_FILENO,
          "Guardian could not prepare crash report path=%s errno=%d\n",
          crashReportPath.c_str(),
          errno);
      return;
    }

    crashReportFD = reportFD;
  }

  static void fatalSignalHandler(int signo, siginfo_t *info, void *ucontext)
  {
    // terminate_on_these_signals flow through here

    // SIGILL, SIGFPE, SIGSEGV, SIGBUS, and SIGTRAP fill in si_addr with the address of the fault.
    // and si_code with a subcode
    // https://man7.org/linux/man-pages/man2/sigaction.2.html

    char report[128];
    size_t reportSize = generateCrashReport(report, signo, info);
    (void)ucontext;

    int fd = crashReportFD;
    ssize_t written = fd >= 0 ? write(fd, report, reportSize) : -1;
    if (written != ssize_t(reportSize))
    {
      (void)write(STDERR_FILENO, report, reportSize);
    }

    _exit(EXIT_FAILURE);
  }

public:

  static inline String crashReportPath = String("/crashreport.txt");
  static inline std::function<void(void)> shutdownSequence = [](void) -> void {
  };

  static void signalHandler(int signo, siginfo_t *info, void *ucontext)
  {
    if (signo == SIGINT)
    {
      exit(EXIT_SUCCESS);
    }

    fatalSignalHandler(signo, info, ucontext);
  }

  static void boot()
  {
    struct sigaction act;
    const char *disableFatalSignals = std::getenv("BASICS_DISABLE_GUARDIAN_TERMINATE_SIGNALS");
    bool installFatalHandlers = !(disableFatalSignals && disableFatalSignals[0] == '1');

    sigemptyset(&act.sa_mask);
    act.sa_sigaction = fatalSignalHandler;
    act.sa_flags = SA_SIGINFO | SA_RESETHAND;

    if (installFatalHandlers)
    {
      std::call_once(crashReportOnce, prepareCrashReport);

      for (int signal : terminate_on_these_signals)
      {
        sigaction(signal, &act, NULL);
      }
    }

    act.sa_sigaction = NULL;
    act.sa_handler = SIG_IGN;
    act.sa_flags = 0;

    for (int signal : block_these_signals)
    {
      sigaction(signal, &act, NULL);
    }
  }
};
