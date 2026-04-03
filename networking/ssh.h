// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <networking/includes.h>
#include <networking/coroutinestack.h>
#include <networking/multiplexer.h>
#include <networking/socket.h>
#include <networking/time.h>
#include <libssh2/libssh2.h>
#include <libssh2/libssh2_sftp.h>

#include <services/vault.h>

#include <cassert>
#include <cerrno>
#include <cstdio>
#include <limits>
#include <string>

class SSHCommandResult {
public:

  int exitStatus = 0;
  String stdoutOutput = {};
  String stderrOutput = {};

  void clear(void)
  {
    exitStatus = 0;
    stdoutOutput.clear();
    stderrOutput.clear();
  }
};

class SSHClient : public CoroutineStack, public TCPSocket, public RingInterface {
private:

  class OperationScope {
  private:

    SSHClient *client = nullptr;

  public:

    explicit OperationScope(SSHClient *_client)
        : client(_client)
    {}

    ~OperationScope()
    {
      if (client != nullptr)
      {
        client->operationInFlight = false;
      }
    }
  };

  static bool ensureLibssh2(void)
  {
    static bool initialized = []() -> bool {
      return (libssh2_init(0) == 0);
    }();

    return initialized;
  }

  static bool readKeyFile(const char *path, String& output)
  {
    output.clear();
    if (path == nullptr || path[0] == '\0')
    {
      return false;
    }

    FILE *file = std::fopen(path, "rb");
    if (file == nullptr)
    {
      return false;
    }

    if (std::fseek(file, 0, SEEK_END) != 0)
    {
      std::fclose(file);
      return false;
    }

    long fileSize = std::ftell(file);
    if (fileSize < 0)
    {
      std::fclose(file);
      return false;
    }

    if (std::fseek(file, 0, SEEK_SET) != 0)
    {
      std::fclose(file);
      return false;
    }

    std::string data(size_t(fileSize), '\0');
    if (data.empty() == false)
    {
      size_t bytesRead = std::fread(data.data(), 1, data.size(), file);
      if (bytesRead != data.size())
      {
        std::fclose(file);
        return false;
      }
    }

    std::fclose(file);
    output.assign(data.data(), data.size());
    return true;
  }

  static bool validateSSHKeyMaterial(const String& privateKeyPath, String& publicKeyPath, String& error)
  {
    error.clear();
    publicKeyPath.clear();

    if (privateKeyPath.size() == 0)
    {
      error.assign("ssh ed25519 private key path is required"_ctv);
      return false;
    }

    publicKeyPath.assign(privateKeyPath);
    publicKeyPath.append(".pub"_ctv);

    String privateKeyPathText = {};
    privateKeyPathText.assign(privateKeyPath);
    String privateKeyFile = {};
    if (readKeyFile(privateKeyPathText.c_str(), privateKeyFile) == false)
    {
      error.assign("ssh ed25519 private key file could not be read"_ctv);
      return false;
    }

    String publicKeyFile = {};
    if (readKeyFile(publicKeyPath.c_str(), publicKeyFile) == false)
    {
      error.assign("ssh ed25519 public key file could not be read"_ctv);
      return false;
    }

    if (Vault::validateSSHKeyPackageEd25519(privateKeyFile, publicKeyFile, &error) == false)
    {
      return false;
    }

    return true;
  }

  void resetFailure(void)
  {
    failed = false;
    lastFailure.clear();
  }

  void failWithSessionError(const char *prefix)
  {
    failed = true;
    lastFailure.clear();
    if (prefix != nullptr && *prefix != '\0')
    {
      lastFailure.assign(prefix);
    }

    char *errorText = nullptr;
    int errorLength = 0;
    int errorCode = (session != nullptr)
                        ? libssh2_session_last_error(session, &errorText, &errorLength, 0)
                        : 0;
    if (errorText != nullptr && errorLength > 0)
    {
      if (lastFailure.size() > 0)
      {
        lastFailure.append(": "_ctv);
      }

      lastFailure.append(reinterpret_cast<const uint8_t *>(errorText), uint64_t(errorLength));
    }
    else if (errorCode != 0)
    {
      if (lastFailure.size() > 0)
      {
        lastFailure.append(" (libssh2="_ctv);
      }
      else
      {
        lastFailure.assign("libssh2="_ctv);
      }

      String code = {};
      code.assignItoa(int64_t(errorCode));
      lastFailure.append(code);
      lastFailure.append(')');
    }

    if (lastFailure.size() == 0)
    {
      lastFailure.assign("ssh operation failed"_ctv);
    }
  }

  void failWithText(const String& text)
  {
    failed = true;
    lastFailure.assign(text);
  }

  void failWithErrno(const char *prefix, int error)
  {
    failed = true;
    lastFailure.clear();
    if (prefix != nullptr && *prefix != '\0')
    {
      lastFailure.assign(prefix);
      lastFailure.append(" (errno="_ctv);
    }
    else
    {
      lastFailure.assign("errno="_ctv);
    }

    String code = {};
    code.assignItoa(int64_t(error));
    lastFailure.append(code);
    lastFailure.append(')');
  }

  bool beginExclusiveOperation(void)
  {
    if (operationInFlight)
    {
      failed = true;
      lastFailure.assign("ssh operation already in progress"_ctv);
      return false;
    }

    resetFailure();
    operationInFlight = true;
    return true;
  }

  int64_t deadlineFromTimeoutMs(int timeoutMs) const
  {
    return Time::now<TimeResolution::ms>() + int64_t(timeoutMs);
  }

  bool ensureDispatcherRegistration(void)
  {
    if (dispatcherRegistered)
    {
      return true;
    }

    if (RingDispatcher::dispatcher == nullptr)
    {
      failed = true;
      lastFailure.assign("ssh client requires ring dispatcher"_ctv);
      return false;
    }

    RingDispatcher::installMultiplexee(this, this);
    dispatcherRegistered = true;
    return true;
  }

  void eraseDispatcherRegistration(void)
  {
    if (dispatcherRegistered == false)
    {
      return;
    }

    RingDispatcher::eraseMultiplexee(this);
    dispatcherRegistered = false;
  }

  void releaseSession(void)
  {
    if (session != nullptr)
    {
      libssh2_session_free(session);
      session = nullptr;
    }
  }

  void initializeSession(void)
  {
    releaseSession();
    resetFailure();

    if (ensureLibssh2() == false)
    {
      failed = true;
      lastFailure.assign("failed to initialize libssh2"_ctv);
      return;
    }

    session = libssh2_session_init();
    if (session == nullptr)
    {
      failed = true;
      lastFailure.assign("failed to initialize ssh session"_ctv);
      return;
    }

    libssh2_session_set_blocking(session, 0);
  }

  void initializeConnectWait(void)
  {
    waitingForConnect = true;
    pendingConnectResult = 0;
  }

  void awaitConnect(int64_t deadlineMs)
  {
    int64_t nowMs = Time::now<TimeResolution::ms>();
    if (deadlineMs > 0 && nowMs >= deadlineMs)
    {
      failed = true;
      lastFailure.assign("ssh tcp connect timed out"_ctv);
      co_return;
    }

    uint64_t timeoutMs = 0;
    if (deadlineMs > 0)
    {
      timeoutMs = uint64_t(deadlineMs - nowMs);
      if (timeoutMs == 0)
      {
        timeoutMs = 1;
      }
    }

    initializeConnectWait();
    Ring::queueConnect(this, timeoutMs);
    co_await suspend();

    if (waitingForConnect)
    {
      failed = true;
      lastFailure.assign("ssh tcp connect did not complete"_ctv);
      co_return;
    }

    if (pendingConnectResult == 0 || pendingConnectResult == -EISCONN)
    {
      setConnected();
      co_return;
    }

    if (pendingConnectResult == -ETIME)
    {
      failed = true;
      lastFailure.assign("ssh tcp connect timed out"_ctv);
      co_return;
    }

    failWithErrno("ssh tcp connect failed", -pendingConnectResult);
  }

  void preferNonBlockingTransportSocket(void)
  {
    isNonBlocking = true;
    if (fd >= 0 && isFixedFile == false)
    {
      setNonBlocking();
    }
  }

  bool ensureSocketNonBlocking(void)
  {
    if (fd < 0)
    {
      failed = true;
      lastFailure.assign("ssh client requires connected tcp socket"_ctv);
      return false;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
    {
      failed = true;
      lastFailure.assign("failed to inspect ssh tcp socket flags"_ctv);
      return false;
    }

    bool socketNonBlocking = ((flags & O_NONBLOCK) != 0);
    assert(socketNonBlocking && "SSHClient requires O_NONBLOCK because libssh2 uses nonblocking send/recv semantics");
    if (socketNonBlocking == false)
    {
      failed = true;
      lastFailure.assign("ssh client requires nonblocking tcp socket"_ctv);
      return false;
    }

    isNonBlocking = true;
    return true;
  }

  void queuePoll(uint64_t timeoutMs = 0)
  {
    if (session == nullptr)
    {
      failed = true;
      lastFailure.assign("ssh session unavailable while waiting for io"_ctv);
      return;
    }

    int directions = libssh2_session_block_directions(session);
    unsigned pollMask = POLLHUP | POLLERR;
    if (directions == 0 || (directions & LIBSSH2_SESSION_BLOCK_INBOUND))
    {
      pollMask |= POLLIN;
    }

    if (directions == 0 || (directions & LIBSSH2_SESSION_BLOCK_OUTBOUND))
    {
      pollMask |= POLLOUT;
    }

    if (timeoutMs > 0)
    {
      Ring::queuePollProcessFD(this, isFixedFile ? fslot : fd, isFixedFile, pollMask, timeoutMs);
    }
    else
    {
      Ring::queuePollProcessFD(this, isFixedFile ? fslot : fd, isFixedFile, pollMask);
    }
  }

  void awaitSessionIO(int64_t deadlineMs)
  {
    int64_t nowMs = Time::now<TimeResolution::ms>();
    if (deadlineMs > 0 && nowMs >= deadlineMs)
    {
      failed = true;
      lastFailure.assign("ssh io timed out"_ctv);
      co_return;
    }

    uint64_t timeoutMs = 0;
    if (deadlineMs > 0)
    {
      timeoutMs = uint64_t(deadlineMs - nowMs);
      if (timeoutMs == 0)
      {
        timeoutMs = 1;
      }
    }

    uint32_t suspendIndex = nextSuspendIndex();
    waitForSSHIO(deadlineMs, timeoutMs);
    if (suspendIndex < nextSuspendIndex())
    {
      co_await suspendAtIndex(suspendIndex);
    }
  }

  void closeChannelGracefully(LIBSSH2_CHANNEL *& channel, int64_t deadlineMs, int *exitStatus = nullptr)
  {
    if (channel == nullptr)
    {
      co_return;
    }

    int rc = 0;
    while ((rc = libssh2_channel_send_eof(channel)) != 0)
    {
      if (rc != LIBSSH2_ERROR_EAGAIN)
      {
        failWithSessionError("failed to send ssh channel eof");
        libssh2_channel_free(channel);
        channel = nullptr;
        co_return;
      }

      uint32_t suspendIndex = nextSuspendIndex();
      awaitSessionIO(deadlineMs);
      if (suspendIndex < nextSuspendIndex())
      {
        co_await suspendAtIndex(suspendIndex);
      }

      if (failed)
      {
        libssh2_channel_free(channel);
        channel = nullptr;
        co_return;
      }
    }

    while ((rc = libssh2_channel_wait_eof(channel)) != 0)
    {
      if (rc != LIBSSH2_ERROR_EAGAIN)
      {
        failWithSessionError("failed waiting for ssh channel eof");
        libssh2_channel_free(channel);
        channel = nullptr;
        co_return;
      }

      uint32_t suspendIndex = nextSuspendIndex();
      awaitSessionIO(deadlineMs);
      if (suspendIndex < nextSuspendIndex())
      {
        co_await suspendAtIndex(suspendIndex);
      }

      if (failed)
      {
        libssh2_channel_free(channel);
        channel = nullptr;
        co_return;
      }
    }

    while ((rc = libssh2_channel_close(channel)) != 0)
    {
      if (rc != LIBSSH2_ERROR_EAGAIN)
      {
        failWithSessionError("failed to close ssh channel");
        libssh2_channel_free(channel);
        channel = nullptr;
        co_return;
      }

      uint32_t suspendIndex = nextSuspendIndex();
      awaitSessionIO(deadlineMs);
      if (suspendIndex < nextSuspendIndex())
      {
        co_await suspendAtIndex(suspendIndex);
      }

      if (failed)
      {
        libssh2_channel_free(channel);
        channel = nullptr;
        co_return;
      }
    }

    if (exitStatus != nullptr)
    {
      *exitStatus = libssh2_channel_get_exit_status(channel);
    }

    libssh2_channel_free(channel);
    channel = nullptr;
  }

  void closeSFTPHandle(LIBSSH2_SFTP_HANDLE *& handle, int64_t deadlineMs)
  {
    if (handle == nullptr)
    {
      co_return;
    }

    int rc = 0;
    while ((rc = libssh2_sftp_close(handle)) != 0)
    {
      if (rc != LIBSSH2_ERROR_EAGAIN)
      {
        failWithSessionError("failed to close ssh sftp handle");
        handle = nullptr;
        co_return;
      }

      uint32_t suspendIndex = nextSuspendIndex();
      awaitSessionIO(deadlineMs);
      if (suspendIndex < nextSuspendIndex())
      {
        co_await suspendAtIndex(suspendIndex);
      }

      if (failed)
      {
        handle = nullptr;
        co_return;
      }
    }

    handle = nullptr;
  }

  void shutdownSFTP(LIBSSH2_SFTP *& sftp, int64_t deadlineMs)
  {
    if (sftp == nullptr)
    {
      co_return;
    }

    int rc = 0;
    while ((rc = libssh2_sftp_shutdown(sftp)) != 0)
    {
      if (rc != LIBSSH2_ERROR_EAGAIN)
      {
        failWithSessionError("failed to shutdown ssh sftp session");
        sftp = nullptr;
        co_return;
      }

      uint32_t suspendIndex = nextSuspendIndex();
      awaitSessionIO(deadlineMs);
      if (suspendIndex < nextSuspendIndex())
      {
        co_await suspendAtIndex(suspendIndex);
      }

      if (failed)
      {
        sftp = nullptr;
        co_return;
      }
    }

    sftp = nullptr;
  }

  void uploadBytes(const uint8_t *bytes, uint64_t size, const String& remotePath, long permissions, int timeoutMs)
  {
    resetFailure();
    if (session == nullptr)
    {
      failed = true;
      lastFailure.assign("ssh session not authenticated"_ctv);
      co_return;
    }

    int64_t deadlineMs = Time::now<TimeResolution::ms>() + int64_t(timeoutMs);
    LIBSSH2_SFTP *sftp = nullptr;
    LIBSSH2_SFTP_HANDLE *handle = nullptr;

    while ((sftp = libssh2_sftp_init(session)) == nullptr)
    {
      if (libssh2_session_last_errno(session) != LIBSSH2_ERROR_EAGAIN)
      {
        failWithSessionError("failed to initialize ssh sftp session");
        co_return;
      }

      uint32_t suspendIndex = nextSuspendIndex();
      awaitSessionIO(deadlineMs);
      if (suspendIndex < nextSuspendIndex())
      {
        co_await suspendAtIndex(suspendIndex);
      }

      if (failed)
      {
        co_return;
      }
    }

    String remotePathText = {};
    remotePathText.assign(remotePath);
    while ((handle = libssh2_sftp_open(
                sftp,
                remotePathText.c_str(),
                LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC,
                permissions)) == nullptr)
    {
      if (libssh2_session_last_errno(session) != LIBSSH2_ERROR_EAGAIN)
      {
        failWithSessionError("failed to open remote ssh sftp file");
        break;
      }

      uint32_t suspendIndex = nextSuspendIndex();
      awaitSessionIO(deadlineMs);
      if (suspendIndex < nextSuspendIndex())
      {
        co_await suspendAtIndex(suspendIndex);
      }

      if (failed)
      {
        break;
      }
    }

    if (failed == false && handle != nullptr)
    {
      uint64_t written = 0;
      while (written < size)
      {
        ssize_t rc = libssh2_sftp_write(handle, reinterpret_cast<const char *>(bytes) + written, size - written);
        if (rc == LIBSSH2_ERROR_EAGAIN)
        {
          uint32_t suspendIndex = nextSuspendIndex();
          awaitSessionIO(deadlineMs);
          if (suspendIndex < nextSuspendIndex())
          {
            co_await suspendAtIndex(suspendIndex);
          }

          if (failed)
          {
            break;
          }

          continue;
        }

        if (rc <= 0)
        {
          failWithSessionError("failed to write ssh sftp file");
          break;
        }

        written += uint64_t(rc);
      }
    }

    if (handle != nullptr)
    {
      uint32_t suspendIndex = nextSuspendIndex();
      closeSFTPHandle(handle, deadlineMs);
      if (suspendIndex < nextSuspendIndex())
      {
        co_await suspendAtIndex(suspendIndex);
      }
    }

    if (sftp != nullptr)
    {
      uint32_t suspendIndex = nextSuspendIndex();
      shutdownSFTP(sftp, deadlineMs);
      if (suspendIndex < nextSuspendIndex())
      {
        co_await suspendAtIndex(suspendIndex);
      }
    }
  }

protected:

  LIBSSH2_SESSION *session = nullptr;
  bool dispatcherRegistered = false;
  bool operationInFlight = false;
  bool waitingForConnect = false;
  int pendingConnectResult = 0;

  virtual void waitForSSHIO(int64_t deadlineMs, uint64_t timeoutMs)
  {
    (void)deadlineMs;
    queuePoll(timeoutMs);
    co_await suspend();
  }

public:

  bool failed = false;
  String lastFailure = {};

  void connectHandler(void *socket, int result) override
  {
    if (socket != this)
    {
      return;
    }

    waitingForConnect = false;
    pendingConnectResult = result;

    if (hasSuspendedCoroutines())
    {
      co_consume();
    }
  }

  void pollHandler(void *socket, int result) override
  {
    if (socket != this)
    {
      return;
    }

    if (result == -ETIME)
    {
      failed = true;
      lastFailure.assign("ssh io timed out"_ctv);
    }
    else if (result < 0)
    {
      failWithErrno("ssh io poll failed", -result);
    }

    if (hasSuspendedCoroutines())
    {
      co_consume();
    }
  }

  void reset(void) override
  {
    CoroutineStack::reset();
    TCPSocket::reset();
    preferNonBlockingTransportSocket();
    operationInFlight = false;
    waitingForConnect = false;
    pendingConnectResult = 0;
    initializeSession();
  }

private:

  void authenticateWithDeadline(const String& userText, const String& privateKeyPathText, int64_t deadlineMs)
  {
    resetFailure();
    if (session == nullptr)
    {
      initializeSession();
    }

    if (failed || session == nullptr)
    {
      co_return;
    }

    if (ensureSocketNonBlocking() == false)
    {
      releaseSession();
      co_return;
    }

    if (userText.size() > uint64_t(std::numeric_limits<unsigned int>::max()))
    {
      failed = true;
      lastFailure.assign("ssh username is too long"_ctv);
      releaseSession();
      co_return;
    }

    String userTextCopy = {};
    userTextCopy.assign(userText);
    String privateKeyPathCopy = {};
    privateKeyPathCopy.assign(privateKeyPathText);
    String publicKeyPathText = {};
    if (validateSSHKeyMaterial(privateKeyPathCopy, publicKeyPathText, lastFailure) == false)
    {
      failed = true;
      releaseSession();
      co_return;
    }

    int rc = 0;

    while ((rc = libssh2_session_handshake(session, fd)) != 0)
    {
      if (rc != LIBSSH2_ERROR_EAGAIN)
      {
        failWithSessionError("ssh handshake failed");
        releaseSession();
        co_return;
      }

      uint32_t suspendIndex = nextSuspendIndex();
      awaitSessionIO(deadlineMs);
      if (suspendIndex < nextSuspendIndex())
      {
        co_await suspendAtIndex(suspendIndex);
      }

      if (failed)
      {
        releaseSession();
        co_return;
      }
    }

    while ((rc = libssh2_userauth_publickey_fromfile_ex(session,
                                                        userTextCopy.c_str(),
                                                        static_cast<unsigned int>(userTextCopy.size()),
                                                        publicKeyPathText.c_str(),
                                                        privateKeyPathCopy.c_str(),
                                                        nullptr)) != 0)
    {
      if (rc != LIBSSH2_ERROR_EAGAIN)
      {
        failWithSessionError("ssh ed25519 auth failed");
        releaseSession();
        co_return;
      }

      uint32_t suspendIndex = nextSuspendIndex();
      awaitSessionIO(deadlineMs);
      if (suspendIndex < nextSuspendIndex())
      {
        co_await suspendAtIndex(suspendIndex);
      }

      if (failed)
      {
        releaseSession();
        co_return;
      }
    }
  }

public:

  void authenticate(StringType auto&& user, StringType auto&& privkeyPath, int timeoutMs = 120'000)
  {
    String userText = {};
    userText.assign(user);
    String privateKeyPathText = {};
    privateKeyPathText.assign(privkeyPath);

    if (beginExclusiveOperation() == false)
    {
      co_return;
    }

    OperationScope operation(this);

    if (session == nullptr)
    {
      initializeSession();
    }

    if (failed || session == nullptr)
    {
      co_return;
    }

    if (ensureDispatcherRegistration() == false)
    {
      releaseSession();
      co_return;
    }

    uint32_t suspendIndex = nextSuspendIndex();
    authenticateWithDeadline(userText,
                             privateKeyPathText,
                             deadlineFromTimeoutMs(timeoutMs));
    if (suspendIndex < nextSuspendIndex())
    {
      co_await suspendAtIndex(suspendIndex);
    }
  }

  void connectAndAuthenticate(StringType auto&& user, StringType auto&& privkeyPath, int timeoutMs = 120'000)
  {
    String userText = {};
    userText.assign(user);
    String privateKeyPathText = {};
    privateKeyPathText.assign(privkeyPath);

    if (beginExclusiveOperation() == false)
    {
      co_return;
    }

    OperationScope operation(this);

    if (session == nullptr)
    {
      initializeSession();
    }

    if (failed || session == nullptr)
    {
      co_return;
    }

    if (ensureDispatcherRegistration() == false || ensureSocketNonBlocking() == false)
    {
      releaseSession();
      co_return;
    }

    if (daddrLen == 0)
    {
      failed = true;
      lastFailure.assign("ssh client requires remote tcp address"_ctv);
      releaseSession();
      co_return;
    }

    int64_t deadlineMs = deadlineFromTimeoutMs(timeoutMs);
    uint32_t suspendIndex = nextSuspendIndex();
    awaitConnect(deadlineMs);
    if (suspendIndex < nextSuspendIndex())
    {
      co_await suspendAtIndex(suspendIndex);
    }

    if (failed)
    {
      releaseSession();
      co_return;
    }

    suspendIndex = nextSuspendIndex();
    authenticateWithDeadline(userText,
                             privateKeyPathText,
                             deadlineMs);
    if (suspendIndex < nextSuspendIndex())
    {
      co_await suspendAtIndex(suspendIndex);
    }
  }

private:

  void uploadFileImpl(const String& localPath, const String& remotePath, long permissions, int timeoutMs)
  {
    String localPathText = {};
    localPathText.assign(localPath);
    FILE *localFile = std::fopen(localPathText.c_str(), "rb");
    if (localFile == nullptr)
    {
      String failure = {};
      failure.snprintf<"failed to open local file {}"_ctv>(localPath);
      failWithText(failure);
      co_return;
    }

    resetFailure();
    uint8_t buffer[1_MB];
    int64_t deadlineMs = Time::now<TimeResolution::ms>() + int64_t(timeoutMs);
    LIBSSH2_SFTP *sftp = nullptr;
    LIBSSH2_SFTP_HANDLE *handle = nullptr;

    while ((sftp = libssh2_sftp_init(session)) == nullptr)
    {
      if (libssh2_session_last_errno(session) != LIBSSH2_ERROR_EAGAIN)
      {
        failWithSessionError("failed to initialize ssh sftp session");
        break;
      }

      uint32_t suspendIndex = nextSuspendIndex();
      awaitSessionIO(deadlineMs);
      if (suspendIndex < nextSuspendIndex())
      {
        co_await suspendAtIndex(suspendIndex);
      }

      if (failed)
      {
        break;
      }
    }

    if (failed == false)
    {
      String remotePathText = {};
      remotePathText.assign(remotePath);
      while ((handle = libssh2_sftp_open(
                  sftp,
                  remotePathText.c_str(),
                  LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC,
                  permissions)) == nullptr)
      {
        if (libssh2_session_last_errno(session) != LIBSSH2_ERROR_EAGAIN)
        {
          failWithSessionError("failed to open remote ssh sftp file");
          break;
        }

        uint32_t suspendIndex = nextSuspendIndex();
        awaitSessionIO(deadlineMs);
        if (suspendIndex < nextSuspendIndex())
        {
          co_await suspendAtIndex(suspendIndex);
        }

        if (failed)
        {
          break;
        }
      }
    }

    if (failed == false && handle != nullptr)
    {
      while (true)
      {
        size_t readBytes = std::fread(buffer, 1, sizeof(buffer), localFile);
        if (readBytes == 0)
        {
          if (std::ferror(localFile) != 0)
          {
            String failure = {};
            failure.snprintf<"failed to read local file {}"_ctv>(localPath);
            failWithText(failure);
          }

          break;
        }

        size_t written = 0;
        while (written < readBytes)
        {
          ssize_t rc = libssh2_sftp_write(handle, reinterpret_cast<const char *>(buffer) + written, readBytes - written);
          if (rc == LIBSSH2_ERROR_EAGAIN)
          {
            uint32_t suspendIndex = nextSuspendIndex();
            awaitSessionIO(deadlineMs);
            if (suspendIndex < nextSuspendIndex())
            {
              co_await suspendAtIndex(suspendIndex);
            }

            if (failed)
            {
              break;
            }

            continue;
          }

          if (rc <= 0)
          {
            failWithSessionError("failed to write ssh sftp file");
            break;
          }

          written += size_t(rc);
        }

        if (failed)
        {
          break;
        }
      }
    }

    if (handle != nullptr)
    {
      uint32_t suspendIndex = nextSuspendIndex();
      closeSFTPHandle(handle, deadlineMs);
      if (suspendIndex < nextSuspendIndex())
      {
        co_await suspendAtIndex(suspendIndex);
      }
    }

    if (sftp != nullptr)
    {
      uint32_t suspendIndex = nextSuspendIndex();
      shutdownSFTP(sftp, deadlineMs);
      if (suspendIndex < nextSuspendIndex())
      {
        co_await suspendAtIndex(suspendIndex);
      }
    }

    std::fclose(localFile);
  }

  void executeCommandImpl(const String& commandText, SSHCommandResult& result, int timeoutMs)
  {
    result.clear();
    resetFailure();
    if (session == nullptr)
    {
      failed = true;
      lastFailure.assign("ssh session not authenticated"_ctv);
      co_return;
    }

    String commandTextCopy = {};
    commandTextCopy.assign(commandText);
    int64_t deadlineMs = deadlineFromTimeoutMs(timeoutMs);
    LIBSSH2_CHANNEL *channel = nullptr;

    while ((channel = libssh2_channel_open_session(session)) == nullptr)
    {
      if (libssh2_session_last_errno(session) != LIBSSH2_ERROR_EAGAIN)
      {
        failWithSessionError("failed to open ssh exec channel");
        co_return;
      }

      uint32_t suspendIndex = nextSuspendIndex();
      awaitSessionIO(deadlineMs);
      if (suspendIndex < nextSuspendIndex())
      {
        co_await suspendAtIndex(suspendIndex);
      }

      if (failed)
      {
        co_return;
      }
    }

    int rc = 0;
    while ((rc = libssh2_channel_exec(channel, commandTextCopy.c_str())) != 0)
    {
      if (rc != LIBSSH2_ERROR_EAGAIN)
      {
        failWithSessionError("failed to execute remote ssh command");
        libssh2_channel_free(channel);
        co_return;
      }

      uint32_t suspendIndex = nextSuspendIndex();
      awaitSessionIO(deadlineMs);
      if (suspendIndex < nextSuspendIndex())
      {
        co_await suspendAtIndex(suspendIndex);
      }

      if (failed)
      {
        libssh2_channel_free(channel);
        co_return;
      }
    }

    char scratch[4096];
    while (true)
    {
      bool progressed = false;

      while (true)
      {
        ssize_t readBytes = libssh2_channel_read(channel, scratch, sizeof(scratch));
        if (readBytes > 0)
        {
          result.stdoutOutput.append(reinterpret_cast<const uint8_t *>(scratch), uint64_t(readBytes));
          progressed = true;
          continue;
        }

        if (readBytes == LIBSSH2_ERROR_EAGAIN)
        {
          break;
        }

        if (readBytes < 0)
        {
          failWithSessionError("failed to read remote ssh stdout");
          break;
        }

        break;
      }

      while (failed == false)
      {
        ssize_t readBytes = libssh2_channel_read_stderr(channel, scratch, sizeof(scratch));
        if (readBytes > 0)
        {
          result.stderrOutput.append(reinterpret_cast<const uint8_t *>(scratch), uint64_t(readBytes));
          progressed = true;
          continue;
        }

        if (readBytes == LIBSSH2_ERROR_EAGAIN)
        {
          break;
        }

        if (readBytes < 0)
        {
          failWithSessionError("failed to read remote ssh stderr");
          break;
        }

        break;
      }

      if (failed)
      {
        break;
      }

      if (libssh2_channel_eof(channel))
      {
        break;
      }

      if (progressed)
      {
        continue;
      }

      uint32_t suspendIndex = nextSuspendIndex();
      awaitSessionIO(deadlineMs);
      if (suspendIndex < nextSuspendIndex())
      {
        co_await suspendAtIndex(suspendIndex);
      }

      if (failed)
      {
        break;
      }
    }

    if (channel != nullptr)
    {
      uint32_t suspendIndex = nextSuspendIndex();
      closeChannelGracefully(channel, deadlineMs, &result.exitStatus);
      if (suspendIndex < nextSuspendIndex())
      {
        co_await suspendAtIndex(suspendIndex);
      }
    }

    if (failed)
    {
      co_return;
    }

    if (result.exitStatus != 0)
    {
      failed = true;
      if (result.stderrOutput.size() > 0)
      {
        lastFailure.snprintf<"remote command failed exitStatus={} stderr: {}"_ctv>(int64_t(result.exitStatus), result.stderrOutput);
      }
      else if (result.stdoutOutput.size() > 0)
      {
        lastFailure.snprintf<"remote command failed exitStatus={} stdout: {}"_ctv>(int64_t(result.exitStatus), result.stdoutOutput);
      }
      else
      {
        lastFailure.snprintf<"remote command failed exitStatus={}"_ctv>(int64_t(result.exitStatus));
      }
    }
  }

  void disconnectImpl(void)
  {
    if (session == nullptr)
    {
      co_return;
    }

    int64_t deadlineMs = Time::now<TimeResolution::ms>() + 5000;
    int rc = 0;
    while ((rc = libssh2_session_disconnect(session, "Normal Shutdown")) != 0)
    {
      if (rc != LIBSSH2_ERROR_EAGAIN)
      {
        break;
      }

      uint32_t suspendIndex = nextSuspendIndex();
      awaitSessionIO(deadlineMs);
      if (suspendIndex < nextSuspendIndex())
      {
        co_await suspendAtIndex(suspendIndex);
      }

      if (failed)
      {
        break;
      }
    }

    releaseSession();
  }

public:

  void uploadFile(const String& localPath, const String& remotePath, long permissions = 0600, int timeoutMs = 120'000)
  {
    String localPathText = {};
    localPathText.assign(localPath);
    String remotePathText = {};
    remotePathText.assign(remotePath);

    if (beginExclusiveOperation() == false)
    {
      co_return;
    }

    OperationScope operation(this);

    uint32_t suspendIndex = nextSuspendIndex();
    uploadFileImpl(localPathText, remotePathText, permissions, timeoutMs);
    if (suspendIndex < nextSuspendIndex())
    {
      co_await suspendAtIndex(suspendIndex);
    }
  }

  void uploadString(const String& content, const String& remotePath, long permissions = 0600, int timeoutMs = 120'000)
  {
    String contentCopy = {};
    contentCopy.assign(content);
    String remotePathText = {};
    remotePathText.assign(remotePath);

    if (beginExclusiveOperation() == false)
    {
      co_return;
    }

    OperationScope operation(this);

    uint32_t suspendIndex = nextSuspendIndex();
    uploadBytes(contentCopy.data(), contentCopy.size(), remotePathText, permissions, timeoutMs);
    if (suspendIndex < nextSuspendIndex())
    {
      co_await suspendAtIndex(suspendIndex);
    }
  }

  void executeCommand(StringType auto&& command, SSHCommandResult& result, int timeoutMs = 120'000)
  {
    String commandText = {};
    commandText.assign(command);

    if (beginExclusiveOperation() == false)
    {
      co_return;
    }

    OperationScope operation(this);

    uint32_t suspendIndex = nextSuspendIndex();
    executeCommandImpl(commandText, result, timeoutMs);
    if (suspendIndex < nextSuspendIndex())
    {
      co_await suspendAtIndex(suspendIndex);
    }
  }

  void executeCommand(StringType auto&& command, String& response, int timeoutMs = 120'000)
  {
    String commandText = {};
    commandText.assign(command);
    SSHCommandResult commandResult = {};
    if (beginExclusiveOperation() == false)
    {
      co_return;
    }

    OperationScope operation(this);

    uint32_t suspendIndex = nextSuspendIndex();
    executeCommandImpl(commandText, commandResult, timeoutMs);
    if (suspendIndex < nextSuspendIndex())
    {
      co_await suspendAtIndex(suspendIndex);
    }

    if (failed == false)
    {
      response.assign(commandResult.stdoutOutput);
    }
  }

  void executeCommand(StringType auto&& command, int timeoutMs = 120'000)
  {
    String commandText = {};
    commandText.assign(command);

    if (beginExclusiveOperation() == false)
    {
      co_return;
    }

    OperationScope operation(this);

    SSHCommandResult commandResult = {};
    uint32_t suspendIndex = nextSuspendIndex();
    executeCommandImpl(commandText, commandResult, timeoutMs);
    if (suspendIndex < nextSuspendIndex())
    {
      co_await suspendAtIndex(suspendIndex);
    }
  }

  void disconnect(void)
  {
    if (beginExclusiveOperation() == false)
    {
      co_return;
    }

    OperationScope operation(this);

    uint32_t suspendIndex = nextSuspendIndex();
    disconnectImpl();
    if (suspendIndex < nextSuspendIndex())
    {
      co_await suspendAtIndex(suspendIndex);
    }
  }

  SSHClient()
  {
    preferNonBlockingTransportSocket();
    initializeSession();
    ensureDispatcherRegistration();

    // LIBSSH2_TRACE_TRANS
    // LIBSSH2_TRACE_SOCKET
    // LIBSSH2_TRACE_SFTP
    // LIBSSH2_TRACE_CONN
    // LIBSSH2_TRACE_KEX
    // LIBSSH2_TRACE_AUTH
    // LIBSSH2_TRACE_SCP
    // LIBSSH2_TRACE_PUBLICKEY
    // libssh2_trace(session, LIBSSH2_TRACE_ERROR);
  }

  ~SSHClient()
  {
    eraseDispatcherRegistration();
    releaseSession();
  }

  SSHClient(const SSHClient&) = delete;
  SSHClient& operator=(const SSHClient&) = delete;
  SSHClient(SSHClient&&) = delete;
  SSHClient& operator=(SSHClient&&) = delete;
};
