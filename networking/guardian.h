// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#include <execinfo.h>
#include <ucontext.h>
#include <cxxabi.h>
#include <sys/wait.h>
#include <csignal>
#include <cstdlib>

#pragma once

class Guardian {
private:

  // https://www.gnu.org/software/libc/manual/html_node/Standard-Signals.html

  constexpr static int block_these_signals[] = {
      SIGHUP,
      SIGQUIT,
      SIGTRAP,
      SIGABRT,
      SIGIOT,
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
      SIGSEGV};

  [[gnu::always_inline]] static inline String generateCrashReport(int sig, siginfo_t *info, void *ucontext)
  {
    String report;

    report.snprintf_add<"Caught signal {itoa}\n"_ctv>(sig);

    (void)info;
    (void)ucontext;

    report.append("Stack trace:\n"_ctv);

    void *frames[64];
    int32_t nFrames = backtrace(frames, 64);

    for (int32_t i = 2; i < nFrames; ++i)
    {
      report.snprintf_add<"\t{itoh}\n"_ctv>(reinterpret_cast<uint64_t>(frames[i]));
    }

    return report;
  }

public:

  static inline String crashReportPath = "/crashreport.txt"_ctv;
  static inline std::function<void(void)> shutdownSequence = [](void) -> void {
  };

  static void signalHandler(int signo, siginfo_t *info, void *ucontext)
  {
    // terminate_on_these_signals flow through here

    // SIGILL, SIGFPE, SIGSEGV, SIGBUS, and SIGTRAP fill in si_addr with the address of the fault.
    // and si_code with a subcode
    // https://man7.org/linux/man-pages/man2/sigaction.2.html

    if (signo == SIGINT)
    {
      exit(EXIT_SUCCESS);
    }

    String report = generateCrashReport(signo, info, ucontext);

    pid_t pid = fork();

    if (pid != -1)
    {
      if (pid == 0)
      {
        Filesystem::openWriteAtClose(-1, crashReportPath, report);
      }
      else
      {
        int status;
        waitpid(pid, &status, 0);
      }
    }

    shutdownSequence();

    exit(EXIT_FAILURE);
  }

  static void boot()
  {
    struct sigaction act;
    const char *disableFatalSignals = std::getenv("BASICS_DISABLE_GUARDIAN_TERMINATE_SIGNALS");
    bool installFatalHandlers = !(disableFatalSignals && disableFatalSignals[0] == '1');

    sigemptyset(&act.sa_mask);
    act.sa_sigaction = signalHandler;
    act.sa_flags = SA_SIGINFO;

    if (installFatalHandlers)
    {
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
