// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <networking/async.dns.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstring>

class HappyEyeballsPlan {
public:

   using Delay = std::chrono::milliseconds;

   static constexpr Delay attemptDelay = std::chrono::milliseconds(250);
   static constexpr size_t maximumAttempts = AsyncDnsResolver::maximumAnswers;

   enum class Status : uint8_t {
      ready,
      resolverFailure,
      invalidResult,
      noUsableAddresses
   };

   struct Attempt {
      AsyncDnsResolver::Address address;
      Delay delay = {};
   };

   class Cursor {
   private:

      const HappyEyeballsPlan *plan_ = nullptr;
      size_t next_ = 0;
      Delay readyAt_ = {};

      const Attempt *take(Delay elapsed)
      {
         const Attempt *attempt = &plan_->attempts_[next_++];
         if (next_ != plan_->size_)
         {
            readyAt_ = elapsed + plan_->attempts_[next_].delay;
         }
         return attempt;
      }

   public:

      explicit Cursor(const HappyEyeballsPlan& plan) : plan_(&plan) {}

      const Attempt *nextReady(Delay elapsed)
      {
         if (next_ == plan_->size_ || elapsed < readyAt_)
         {
            return nullptr;
         }

         return take(elapsed);
      }

      const Attempt *advanceAfterImmediateFailure(Delay elapsed)
      {
         if (next_ == 0 || next_ == plan_->size_)
         {
            return nullptr;
         }

         return take(elapsed);
      }

      size_t remaining(void) const
      {
         return plan_->size_ - next_;
      }
   };

private:

   std::array<Attempt, maximumAttempts> attempts_ = {};
   size_t size_ = 0;
   Status status_ = Status::invalidResult;

   static bool usable(const AsyncDnsResolver::Address& address)
   {
      return (address.family() == AF_INET && address.length == sizeof(sockaddr_in)) ||
             (address.family() == AF_INET6 && address.length == sizeof(sockaddr_in6));
   }

   static bool sameEndpoint(const AsyncDnsResolver::Address& left,
                            const AsyncDnsResolver::Address& right)
   {
      if (left.family() != right.family())
      {
         return false;
      }

      if (left.family() == AF_INET)
      {
         sockaddr_in leftAddress = {};
         sockaddr_in rightAddress = {};
         std::memcpy(&leftAddress, &left.storage, sizeof(leftAddress));
         std::memcpy(&rightAddress, &right.storage, sizeof(rightAddress));
         return leftAddress.sin_port == rightAddress.sin_port &&
                std::memcmp(&leftAddress.sin_addr, &rightAddress.sin_addr, sizeof(in_addr)) == 0;
      }

      sockaddr_in6 leftAddress = {};
      sockaddr_in6 rightAddress = {};
      std::memcpy(&leftAddress, &left.storage, sizeof(leftAddress));
      std::memcpy(&rightAddress, &right.storage, sizeof(rightAddress));
      return leftAddress.sin6_port == rightAddress.sin6_port &&
             leftAddress.sin6_scope_id == rightAddress.sin6_scope_id &&
             std::memcmp(&leftAddress.sin6_addr, &rightAddress.sin6_addr, sizeof(in6_addr)) == 0;
   }

public:

   explicit HappyEyeballsPlan(const AsyncDnsResolver::Result& result)
   {
      if (!result.succeeded())
      {
         status_ = Status::resolverFailure;
         return;
      }

      if (result.addresses.size() > maximumAttempts)
      {
         status_ = Status::invalidResult;
         return;
      }

      std::array<const AsyncDnsResolver::Address *, maximumAttempts> ipv4 = {};
      std::array<const AsyncDnsResolver::Address *, maximumAttempts> ipv6 = {};
      size_t ipv4Size = 0;
      size_t ipv6Size = 0;
      int firstFamily = AF_UNSPEC;

      for (const AsyncDnsResolver::Address& address : result.addresses)
      {
         if (!usable(address))
         {
            continue;
         }

         bool duplicate = false;
         const auto& family = address.family() == AF_INET ? ipv4 : ipv6;
         const size_t familySize = address.family() == AF_INET ? ipv4Size : ipv6Size;
         for (size_t index = 0; index < familySize; ++index)
         {
            if (sameEndpoint(address, *family[index]))
            {
               duplicate = true;
               break;
            }
         }

         if (duplicate)
         {
            continue;
         }

         if (firstFamily == AF_UNSPEC)
         {
            firstFamily = address.family();
         }

         if (address.family() == AF_INET)
         {
            ipv4[ipv4Size++] = &address;
         }
         else
         {
            ipv6[ipv6Size++] = &address;
         }
      }

      if (firstFamily == AF_UNSPEC)
      {
         status_ = Status::noUsableAddresses;
         return;
      }

      size_t ipv4Index = 0;
      size_t ipv6Index = 0;
      int family = firstFamily;
      while (ipv4Index != ipv4Size || ipv6Index != ipv6Size)
      {
         const AsyncDnsResolver::Address *address = nullptr;
         if (family == AF_INET && ipv4Index != ipv4Size)
         {
            address = ipv4[ipv4Index++];
         }
         else if (family == AF_INET6 && ipv6Index != ipv6Size)
         {
            address = ipv6[ipv6Index++];
         }
         else if (ipv4Index != ipv4Size)
         {
            address = ipv4[ipv4Index++];
         }
         else
         {
            address = ipv6[ipv6Index++];
         }

         attempts_[size_] = {*address, size_ == 0 ? Delay{} : attemptDelay};
         ++size_;
         family = address->family() == AF_INET ? AF_INET6 : AF_INET;
      }

      status_ = Status::ready;
   }

   Status status(void) const
   {
      return status_;
   }

   bool valid(void) const
   {
      return status_ == Status::ready;
   }

   size_t size(void) const
   {
      return size_;
   }

   const Attempt& operator[](size_t index) const
   {
      return attempts_[index];
   }

   Cursor cursor(void) const &
   {
      return Cursor(*this);
   }

   Cursor cursor(void) const && = delete;
};
