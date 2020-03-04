#include <array>
#include <gtest/gtest.h>

#include "utils/DynamicMempool.h"

namespace {
    TEST(MempoolBasic, GetNonAllocation)
    {
        DDP::DynamicMempool pool(4, 16);
        std::array<uint32_t*, 16> items{};

        //Get all elements from mempool
        auto i = 0u;
        for (auto&& item: items) {
            ASSERT_FALSE(pool.full()) << "Pool shouldn't be full!";
            item = static_cast<uint32_t*>(pool.get(4));
            ASSERT_TRUE(pool.in_mempool(item)) << "Item is not in mempool!";
            *item = i;
            i++;
        }

        ASSERT_TRUE(pool.full()) << "Pool should be depleted but there is some item free.";

        //Free all elements back to mempool
        i = 0u;
        for (auto item: items) {
            EXPECT_EQ(*item, i) << "Read item differs from inserted.";
            pool.free(item);
            i++;
        }

        ASSERT_FALSE(pool.full()) << "Pool shouldn't be full!";
    }

    TEST(MempoolBasic, GetOnlyAllocation)
    {
        DDP::DynamicMempool pool(4, 16);
        std::array<uint64_t*, 16> items{};

        //Get elements through allocation because required space is bigger then elements in mempool
        auto i = 0u;
        for (auto&& item: items) {
            ASSERT_FALSE(pool.full()) << "Pool shouldn't be full!";
            item = static_cast<uint64_t*>(pool.get(8));
            ASSERT_FALSE(pool.in_mempool(item)) << "Item is in mempool while it should be allocated!";
            *item = i;
            i++;
        }

        ASSERT_FALSE(pool.full()) << "Pool should be still empty.";

        //Free all allocated elements
        i = 0u;
        for (auto item: items) {
            EXPECT_EQ(*item, i) << "Read item differs from inserted.";
            pool.free(item);
            i++;
        }

        ASSERT_FALSE(pool.full()) << "Pool shouldn't be full!";
    }

    TEST(MempoolBasic, GetOverLimit)
    {
        DDP::DynamicMempool pool(4, 16);
        std::array<uint32_t*, 32> items{};

        //Get all elements from mempool
        for (auto i = 0u; i < 16; i++) {
            ASSERT_FALSE(pool.full()) << "Pool shouldn't be full!";
            items[i] = static_cast<uint32_t*>(pool.get(4));
            ASSERT_TRUE(pool.in_mempool(items[i])) << "Item is not in mempool!";
            *items[i] = i;
        }

        //Now get other elements with allocation cause mempool is empty
        for (auto i = 16u; i < 32; i++) {
            ASSERT_TRUE(pool.full()) << "Pool should be full!";
            items[i] = static_cast<uint32_t*>(pool.get(4));
            ASSERT_FALSE(pool.in_mempool(items[i])) << "Item is in mempool!";
            *items[i] = i;
        }

        //Free all elements back to mempool and other deallocate
        auto i = 0u;
        for (auto item: items) {
            EXPECT_EQ(*item, i) << "Read item differs from inserted.";
            pool.free(item);
            i++;
        }

        ASSERT_FALSE(pool.full()) << "Pool shouldn't be full!";
    }

    TEST(MempoolAdvanced, ReuseFreedSpace)
    {
        DDP::DynamicMempool pool(4, 16);
        std::array<uint32_t*, 16> items{};

        //Get all elements from mempool
        for (auto i = 0u; i < 16; i++) {
            ASSERT_FALSE(pool.full()) << "Pool shouldn't be full!";
            items[i] = static_cast<uint32_t*>(pool.get(4));
            ASSERT_TRUE(pool.in_mempool(items[i])) << "Item is not in mempool!";
            *items[i] = i;
        }

        ASSERT_TRUE(pool.full()) << "Pool should be full!";

        //Free all elements back to mempool
        auto i = 0u;
        for (auto item: items) {
            EXPECT_EQ(*item, i) << "Read item differs from inserted.";
            pool.free(item);
            i++;
            ASSERT_FALSE(pool.full()) << "Pool shouldn't be full!";
        }

        //Get freed elements from mempool
        for (i = 0u; i < 16; i++) {
            ASSERT_FALSE(pool.full()) << "Pool shouldn't be full!";
            items[i] = static_cast<uint32_t*>(pool.get(4));
            ASSERT_TRUE(pool.in_mempool(items[i])) << "Item is not in mempool!";
            *items[i] = i;
        }

        ASSERT_TRUE(pool.full()) << "Pool should be full!";

        //Free all elements back to mempool
        i = 0u;
        for (auto item: items) {
            EXPECT_EQ(*item, i) << "Read item differs from inserted.";
            pool.free(item);
            i++;
            ASSERT_FALSE(pool.full()) << "Pool shouldn't be full!";
        }

        ASSERT_FALSE(pool.full()) << "Pool shouldn't be full!";
    }

    TEST(MempoolAdvanced, MixinAllocations)
    {
        DDP::DynamicMempool pool(4, 16);
        std::array<uint32_t*, 24> items{};

        //Get half of all elements from mempool
        for (auto i = 0u; i < 8; i++) {
            ASSERT_FALSE(pool.full()) << "Pool shouldn't be full!";
            items[i] = static_cast<uint32_t*>(pool.get(4));
            ASSERT_TRUE(pool.in_mempool(items[i])) << "Item is not in mempool!";
            *items[i] = i;
        }

        //Require bigger elements than those in mempool
        for (auto i = 8u; i < 16; i++) {
            ASSERT_FALSE(pool.full()) << "Pool shouldn't be full!";
            items[i] = static_cast<uint32_t*>(pool.get(8));
            ASSERT_FALSE(pool.in_mempool(items[i])) << "Item is in mempool!";
            *items[i] = i;
        }

        //Deplete rest of mempool
        for (auto i = 16u; i < 24; i++) {
            ASSERT_FALSE(pool.full()) << "Pool shouldn't be full!";
            items[i] = static_cast<uint32_t*>(pool.get(4));
            ASSERT_TRUE(pool.in_mempool(items[i])) << "Item is not in mempool!";
            *items[i] = i;
        }

        //Deallocate allocated elements
        for (auto i = 8u; i < 16; i++) {
            ASSERT_TRUE(pool.full()) << "Pool should be full!";
            EXPECT_EQ(*items[i], i) << "Read item differs from inserted.";
            pool.free(items[i]);
            items[i] = nullptr;
        }

        ASSERT_TRUE(pool.full()) << "Pool should be full!";

        //Free all elements back to mempool and other deallocate
        auto i = 0u;
        for (auto item: items) {
            if(item != nullptr) {
                EXPECT_EQ(*item, i) << "Read item differs from inserted.";
                pool.free(item);
            }
            i++;
        }

        ASSERT_FALSE(pool.full()) << "Pool shouldn't be full!";
    }
}