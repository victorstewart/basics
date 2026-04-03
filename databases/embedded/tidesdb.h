// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <networking/includes.h>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>

extern "C" {
// Mirror the pinned TidesDB 8.6.2 C ABI here because the upstream public header
// exposes `_Atomic(...)` declarations that `g++` rejects in C++ mode.

struct tidesdb_t;
struct tidesdb_column_family_t;
struct tidesdb_txn_t;
struct tidesdb_iter_t;

typedef enum
{
   TDB_LOG_DEBUG = 0,
   TDB_LOG_INFO = 1,
   TDB_LOG_WARN = 2,
   TDB_LOG_ERROR = 3,
   TDB_LOG_FATAL = 4,
   TDB_LOG_NONE = 99
} tidesdb_log_level_t;

typedef enum
{
   TDB_ISOLATION_READ_UNCOMMITTED = 0,
   TDB_ISOLATION_READ_COMMITTED = 1,
   TDB_ISOLATION_REPEATABLE_READ = 2,
   TDB_ISOLATION_SNAPSHOT = 3,
   TDB_ISOLATION_SERIALIZABLE = 4
} tidesdb_isolation_level_t;

#define TDB_SUCCESS 0
#define TDB_ERR_MEMORY -1
#define TDB_ERR_INVALID_ARGS -2
#define TDB_ERR_NOT_FOUND -3
#define TDB_ERR_IO -4
#define TDB_ERR_CORRUPTION -5
#define TDB_ERR_EXISTS -6
#define TDB_ERR_CONFLICT -7
#define TDB_ERR_TOO_LARGE -8
#define TDB_ERR_MEMORY_LIMIT -9
#define TDB_ERR_INVALID_DB -10
#define TDB_ERR_UNKNOWN -11
#define TDB_ERR_LOCKED -12

#define TDB_MAX_CF_NAME_LEN 128
#define TDB_MAX_COMPARATOR_NAME 64
#define TDB_MAX_COMPARATOR_CTX 256

typedef enum
{
   TDB_SYNC_NONE,
   TDB_SYNC_FULL,
   TDB_SYNC_INTERVAL
} tidesdb_sync_mode_t;

typedef enum
{
   TDB_COMPRESS_NONE = 0,
   TDB_COMPRESS_SNAPPY = 1,
   TDB_COMPRESS_LZ4 = 2,
   TDB_COMPRESS_ZSTD = 3,
   TDB_COMPRESS_LZ4_FAST = 4
} compression_algorithm;

typedef int (*skip_list_comparator_fn)(const uint8_t *key1,
                                       size_t key1_size,
                                       const uint8_t *key2,
                                       size_t key2_size,
                                       void *ctx);

typedef struct tidesdb_commit_op_t
{
   const uint8_t *key;
   size_t key_size;
   const uint8_t *value;
   size_t value_size;
   time_t ttl;
   int is_delete;
} tidesdb_commit_op_t;

typedef int (*tidesdb_commit_hook_fn)(const tidesdb_commit_op_t *ops,
                                      int num_ops,
                                      uint64_t commit_seq,
                                      void *ctx);

typedef struct tidesdb_column_family_config_t
{
   char name[TDB_MAX_CF_NAME_LEN];
   size_t write_buffer_size;
   size_t level_size_ratio;
   int min_levels;
   int dividing_level_offset;
   size_t klog_value_threshold;
   compression_algorithm compression_algorithm;
   int enable_bloom_filter;
   double bloom_fpr;
   int enable_block_indexes;
   int index_sample_ratio;
   int block_index_prefix_len;
   int sync_mode;
   uint64_t sync_interval_us;
   char comparator_name[TDB_MAX_COMPARATOR_NAME];
   char comparator_ctx_str[TDB_MAX_COMPARATOR_CTX];
   skip_list_comparator_fn comparator_fn_cached;
   void *comparator_ctx_cached;
   int skip_list_max_level;
   float skip_list_probability;
   tidesdb_isolation_level_t default_isolation_level;
   uint64_t min_disk_space;
   int l1_file_count_trigger;
   int l0_queue_stall_threshold;
   int use_btree;
   tidesdb_commit_hook_fn commit_hook_fn;
   void *commit_hook_ctx;
} tidesdb_column_family_config_t;

typedef struct tidesdb_config_t
{
   char *db_path;
   int num_flush_threads;
   int num_compaction_threads;
   tidesdb_log_level_t log_level;
   size_t block_cache_size;
   size_t max_open_sstables;
   int log_to_file;
   size_t log_truncation_at;
   size_t max_memory_usage;
} tidesdb_config_t;

tidesdb_column_family_config_t tidesdb_default_column_family_config(void);
tidesdb_config_t tidesdb_default_config(void);

int tidesdb_open(const tidesdb_config_t *config, tidesdb_t **db);
int tidesdb_close(tidesdb_t *db);
int tidesdb_create_column_family(tidesdb_t *db,
                                 const char *name,
                                 const tidesdb_column_family_config_t *config);
tidesdb_column_family_t *tidesdb_get_column_family(tidesdb_t *db, const char *name);

int tidesdb_txn_begin(tidesdb_t *db, tidesdb_txn_t **txn);
int tidesdb_txn_put(tidesdb_txn_t *txn,
                    tidesdb_column_family_t *cf,
                    const uint8_t *key,
                    size_t key_size,
                    const uint8_t *value,
                    size_t value_size,
                    time_t ttl);
int tidesdb_txn_get(tidesdb_txn_t *txn,
                    tidesdb_column_family_t *cf,
                    const uint8_t *key,
                    size_t key_size,
                    uint8_t **value,
                    size_t *value_size);
int tidesdb_txn_delete(tidesdb_txn_t *txn,
                       tidesdb_column_family_t *cf,
                       const uint8_t *key,
                       size_t key_size);
int tidesdb_txn_rollback(tidesdb_txn_t *txn);
int tidesdb_txn_commit(tidesdb_txn_t *txn);
void tidesdb_txn_free(tidesdb_txn_t *txn);

int tidesdb_iter_new(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, tidesdb_iter_t **iter);
int tidesdb_iter_seek_to_first(tidesdb_iter_t *iter);
int tidesdb_iter_next(tidesdb_iter_t *iter);
int tidesdb_iter_valid(tidesdb_iter_t *iter);
int tidesdb_iter_value(tidesdb_iter_t *iter, uint8_t **value, size_t *value_size);
void tidesdb_iter_free(tidesdb_iter_t *iter);

void tidesdb_free(void *ptr);
}

#include <services/filesystem.h>

class TidesDB
{
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
