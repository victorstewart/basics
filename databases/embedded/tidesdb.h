// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <networking/includes.h>
#include <types/types.containers.h>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>

extern "C" {
#include <tidesdb/db.h>
}

#include <services/filesystem.h>

class TidesDB {
private:

  tidesdb_t *db = nullptr;
  String dbPath;
  bytell_hash_map<String, tidesdb_column_family_t *> columnFamilies;

  static void setFailure(String *failure, const char *message)
  {
    if (failure == nullptr)
    {
      return;
    }

    failure->assign(message);
  }

  static void setFailure(String *failure, const String& message)
  {
    if (failure == nullptr)
    {
      return;
    }

    *failure = message;
  }

  static const char *describeError(int rc)
  {
    switch (rc)
    {
      case TDB_SUCCESS:
        {
          return "success";
        }
      case TDB_ERR_MEMORY:
        {
          return "memory error";
        }
      case TDB_ERR_INVALID_ARGS:
        {
          return "invalid args";
        }
      case TDB_ERR_NOT_FOUND:
        {
          return "not found";
        }
      case TDB_ERR_IO:
        {
          return "i/o error";
        }
      case TDB_ERR_CORRUPTION:
        {
          return "corruption";
        }
      case TDB_ERR_EXISTS:
        {
          return "already exists";
        }
      case TDB_ERR_CONFLICT:
        {
          return "conflict";
        }
      case TDB_ERR_TOO_LARGE:
        {
          return "too large";
        }
      case TDB_ERR_MEMORY_LIMIT:
        {
          return "memory limit";
        }
      case TDB_ERR_INVALID_DB:
        {
          return "invalid database";
        }
      case TDB_ERR_LOCKED:
        {
          return "locked";
        }
      case TDB_ERR_UNKNOWN:
      default:
        {
          return "unknown";
        }
    }
  }

  static bool ensureDirectoryHierarchy(const String& path)
  {
    if (path.size() == 0)
    {
      return false;
    }

    for (uint64_t index = 1; index <= path.size(); ++index)
    {
      if (index != path.size() && path[index] != '/')
      {
        continue;
      }

      String prefix = path.substr(0, index, Copy::yes);
      if (prefix.size() == 0 || prefix == "/"_ctv)
      {
        continue;
      }

      if (Filesystem::createDirectoryAt(-1, prefix, 0755) != 0 && errno != EEXIST)
      {
        return false;
      }
    }

    return true;
  }

  bool ensureOpen(String *failure = nullptr)
  {
    if (db != nullptr)
    {
      return true;
    }

    if (dbPath.size() == 0)
    {
      setFailure(failure, "tidesdb path required");
      return false;
    }

    if (ensureDirectoryHierarchy(dbPath) == false)
    {
      setFailure(failure, "failed to create tidesdb directory");
      return false;
    }

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = const_cast<char *>(dbPath.c_str());
    config.log_level = TDB_LOG_NONE;
    config.num_flush_threads = 1;
    config.num_compaction_threads = 1;

    int rc = tidesdb_open(&config, &db);
    if (rc != TDB_SUCCESS)
    {
      String message;
      message.snprintf<"tidesdb_open failed: {} ({itoa})"_ctv>(String(describeError(rc)), rc);
      setFailure(failure, message);
      db = nullptr;
      return false;
    }

    return true;
  }

  bool ensureColumnFamily(const String& columnFamilyName, tidesdb_column_family_t **columnFamily, String *failure = nullptr)
  {
    if (columnFamilyName.size() == 0)
    {
      setFailure(failure, "column family name required");
      return false;
    }

    if (ensureOpen(failure) == false)
    {
      return false;
    }

    if (auto it = columnFamilies.find(columnFamilyName); it != columnFamilies.end())
    {
      *columnFamily = it->second;
      return true;
    }

    String mutableColumnFamilyName(columnFamilyName.data(), columnFamilyName.size(), Copy::yes);
    tidesdb_column_family_t *resolved = tidesdb_get_column_family(db, mutableColumnFamilyName.c_str());
    if (resolved == nullptr)
    {
      tidesdb_column_family_config_t config = tidesdb_default_column_family_config();
      int rc = tidesdb_create_column_family(db, mutableColumnFamilyName.c_str(), &config);
      if (rc != TDB_SUCCESS && rc != TDB_ERR_EXISTS)
      {
        String message;
        message.snprintf<"tidesdb column family init failed: {} ({itoa})"_ctv>(String(describeError(rc)), rc);
        setFailure(failure, message);
        return false;
      }

      resolved = tidesdb_get_column_family(db, mutableColumnFamilyName.c_str());
    }

    if (resolved == nullptr)
    {
      setFailure(failure, "tidesdb column family init failed");
      return false;
    }

    columnFamilies.insert_or_assign(columnFamilyName, resolved);
    *columnFamily = resolved;
    return true;
  }

public:

  explicit TidesDB(const String& path = ""_ctv)
      : dbPath(path)
  {
  }

  TidesDB(const TidesDB&) = delete;
  TidesDB& operator=(const TidesDB&) = delete;

  ~TidesDB()
  {
    close();
  }

  void setPath(const String& path)
  {
    if (dbPath == path)
    {
      return;
    }

    close();
    dbPath = path;
  }

  const String& path(void) const
  {
    return dbPath;
  }

  bool open(String *failure = nullptr)
  {
    return ensureOpen(failure);
  }

  void close(void)
  {
    if (db != nullptr)
    {
      tidesdb_close(db);
      db = nullptr;
    }

    columnFamilies.clear();
  }

  bool write(const String& columnFamilyName, const String& key, const String& value, String *failure = nullptr)
  {
    tidesdb_column_family_t *columnFamily = nullptr;
    if (ensureColumnFamily(columnFamilyName, &columnFamily, failure) == false)
    {
      return false;
    }

    tidesdb_txn_t *txn = nullptr;
    int rc = tidesdb_txn_begin(db, &txn);
    if (rc != TDB_SUCCESS)
    {
      String message;
      message.snprintf<"tidesdb_txn_begin failed: {} ({itoa})"_ctv>(String(describeError(rc)), rc);
      setFailure(failure, message);
      return false;
    }

    rc = tidesdb_txn_put(txn,
                         columnFamily,
                         reinterpret_cast<const uint8_t *>(key.data()),
                         key.size(),
                         reinterpret_cast<const uint8_t *>(value.data()),
                         value.size(),
                         0);
    if (rc == TDB_SUCCESS)
    {
      rc = tidesdb_txn_commit(txn);
    }
    else
    {
      (void)tidesdb_txn_rollback(txn);
    }

    tidesdb_txn_free(txn);

    if (rc != TDB_SUCCESS)
    {
      String message;
      message.snprintf<"tidesdb write failed: {} ({itoa})"_ctv>(String(describeError(rc)), rc);
      setFailure(failure, message);
      return false;
    }

    return true;
  }

  bool read(const String& columnFamilyName, const String& key, String& value, String *failure = nullptr)
  {
    value.clear();

    tidesdb_column_family_t *columnFamily = nullptr;
    if (ensureColumnFamily(columnFamilyName, &columnFamily, failure) == false)
    {
      return false;
    }

    tidesdb_txn_t *txn = nullptr;
    int rc = tidesdb_txn_begin(db, &txn);
    if (rc != TDB_SUCCESS)
    {
      String message;
      message.snprintf<"tidesdb_txn_begin failed: {} ({itoa})"_ctv>(String(describeError(rc)), rc);
      setFailure(failure, message);
      return false;
    }

    uint8_t *bytes = nullptr;
    size_t byteCount = 0;
    rc = tidesdb_txn_get(txn,
                         columnFamily,
                         reinterpret_cast<const uint8_t *>(key.data()),
                         key.size(),
                         &bytes,
                         &byteCount);

    (void)tidesdb_txn_rollback(txn);
    tidesdb_txn_free(txn);

    if (rc != TDB_SUCCESS)
    {
      if (rc == TDB_ERR_NOT_FOUND)
      {
        setFailure(failure, "record not found");
      }
      else
      {
        String message;
        message.snprintf<"tidesdb read failed: {} ({itoa})"_ctv>(String(describeError(rc)), rc);
        setFailure(failure, message);
      }

      return false;
    }

    value.append(bytes, byteCount);
    tidesdb_free(bytes);
    return true;
  }

  bool remove(const String& columnFamilyName, const String& key, String *failure = nullptr)
  {
    tidesdb_column_family_t *columnFamily = nullptr;
    if (ensureColumnFamily(columnFamilyName, &columnFamily, failure) == false)
    {
      return false;
    }

    tidesdb_txn_t *txn = nullptr;
    int rc = tidesdb_txn_begin(db, &txn);
    if (rc != TDB_SUCCESS)
    {
      String message;
      message.snprintf<"tidesdb_txn_begin failed: {} ({itoa})"_ctv>(String(describeError(rc)), rc);
      setFailure(failure, message);
      return false;
    }

    rc = tidesdb_txn_delete(txn,
                            columnFamily,
                            reinterpret_cast<const uint8_t *>(key.data()),
                            key.size());
    if (rc == TDB_SUCCESS)
    {
      rc = tidesdb_txn_commit(txn);
    }
    else
    {
      (void)tidesdb_txn_rollback(txn);
    }

    tidesdb_txn_free(txn);

    if (rc != TDB_SUCCESS)
    {
      if (rc == TDB_ERR_NOT_FOUND)
      {
        setFailure(failure, "record not found");
      }
      else
      {
        String message;
        message.snprintf<"tidesdb delete failed: {} ({itoa})"_ctv>(String(describeError(rc)), rc);
        setFailure(failure, message);
      }

      return false;
    }

    return true;
  }

  bool listValues(const String& columnFamilyName, Vector<String>& values, String *failure = nullptr)
  {
    values.clear();

    tidesdb_column_family_t *columnFamily = nullptr;
    if (ensureColumnFamily(columnFamilyName, &columnFamily, failure) == false)
    {
      return false;
    }

    tidesdb_txn_t *txn = nullptr;
    int rc = tidesdb_txn_begin(db, &txn);
    if (rc != TDB_SUCCESS)
    {
      String message;
      message.snprintf<"tidesdb_txn_begin failed: {} ({itoa})"_ctv>(String(describeError(rc)), rc);
      setFailure(failure, message);
      return false;
    }

    tidesdb_iter_t *iter = nullptr;
    rc = tidesdb_iter_new(txn, columnFamily, &iter);
    if (rc != TDB_SUCCESS)
    {
      String message;
      message.snprintf<"tidesdb_iter_new failed: {} ({itoa})"_ctv>(String(describeError(rc)), rc);
      setFailure(failure, message);
      (void)tidesdb_txn_rollback(txn);
      tidesdb_txn_free(txn);
      return false;
    }

    rc = tidesdb_iter_seek_to_first(iter);
    if (rc != TDB_SUCCESS && rc != TDB_ERR_NOT_FOUND)
    {
      String message;
      message.snprintf<"tidesdb_iter_seek_to_first failed: {} ({itoa})"_ctv>(String(describeError(rc)), rc);
      setFailure(failure, message);
      tidesdb_iter_free(iter);
      (void)tidesdb_txn_rollback(txn);
      tidesdb_txn_free(txn);
      return false;
    }

    while (tidesdb_iter_valid(iter))
    {
      uint8_t *bytes = nullptr;
      size_t byteCount = 0;

      rc = tidesdb_iter_value(iter, &bytes, &byteCount);
      if (rc != TDB_SUCCESS)
      {
        String message;
        message.snprintf<"tidesdb_iter_value failed: {} ({itoa})"_ctv>(String(describeError(rc)), rc);
        setFailure(failure, message);
        tidesdb_iter_free(iter);
        (void)tidesdb_txn_rollback(txn);
        tidesdb_txn_free(txn);
        return false;
      }

      String value;
      value.append(bytes, byteCount);
      values.push_back(value);

      if (tidesdb_iter_next(iter) != TDB_SUCCESS)
      {
        break;
      }
    }

    tidesdb_iter_free(iter);
    (void)tidesdb_txn_rollback(txn);
    tidesdb_txn_free(txn);
    return true;
  }
};
