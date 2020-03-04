/*
 *  Copyright (C) 2018 Brno University of Technology
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <cstdint>
#include <smmintrin.h>

namespace DDP {
    /**
     * @brief Calculate CRC32 hash
     */
    class CRC32 {
        public:
        CRC32() = delete;
        CRC32(const CRC32&) = delete;
        CRC32& operator=(const CRC32) = delete;

        /**
         * @brief Calculate CRC32 hash from input data using Intel's optimized implementation
         * @param first Pointer to the start of data for hash calculation
         * @param last Pointer to next byte after the end of data for hash calculation
         * @return CRC32 hash value for given input data
         */
        static uint32_t hash(const char* first, const char* last)
        {
            uint32_t ret = ~0U;

            for ( ; first < last; ) {
                // At least 8 bytes of data left
                if (first + 8 <= last) {
                    ret = _mm_crc32_u64(ret, *reinterpret_cast<const uint64_t*>(first));
                    first += 8;
                }
                // At least 4 bytes of data left
                else if (first + 4 <= last) {
                    ret = _mm_crc32_u32(ret, *reinterpret_cast<const uint32_t*>(first));
                    first += 4;
                }
                // At least 2 bytes of data left
                else if (first + 2 <= last) {
                    ret = _mm_crc32_u16(ret, *reinterpret_cast<const uint16_t*>(first));
                    first += 2;
                }
                // 1 byte of data left
                else {
                    ret = _mm_crc32_u8(ret, *reinterpret_cast<const uint8_t*>(first));
                    first += 1;
                }
            }

            return ~ret;
        }
    };
}