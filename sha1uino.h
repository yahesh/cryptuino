/*
 * File:    sha1uino.h
 * Author:  Yahe <hello@yahe.sh>
 * Version: 0.4.0
 *
 * Created on 13. April 2013
 *
 * Release 0.1.0 on 26. April 2013
 * initial implementation
 *
 * Release 0.2.0 on 10. May 2013
 * introduced PROGMEM
 * introduced password-check option
 * enhanced chunk API
 *
 * Release 0.3.0 on 12. May 2013
 * changed special char generation from hashInformation to hmacPassword
 *
 * Release 0.4.0 on 18. July 2013
 * hardened against dictionary attacks against hashInformation
 * renamed hashInformation to hmacInformation
 */

/*
 * sha1uino.h contains an implementation of the SHA-1 hash algorithm.
 *
 * Copyright (C) 2013-2018 Yahe <hello@yahe.sh>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __SHA1UINO_H__
#define	__SHA1UINO_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include "chunkuino.h"

#define SHA1_BLOCKSIZE  0x40
#define SHA1_OUTPUTSIZE (sizeof(uint32_t)*0x05)
#define SHA1_HASH1      0x67452301
#define SHA1_HASH2      0xEFCDAB89
#define SHA1_HASH3      0x98BADCFE
#define SHA1_HASH4      0x10325476
#define SHA1_HASH5      0xC3D2E1F0
#define SHA1_KEY1       0x5A827999
#define SHA1_KEY2       0x6ED9EBA1
#define SHA1_KEY3       0x8F1BBCDC
#define SHA1_KEY4       0xCA62C1D6
#define SHA1_HMAC_IPAD  0x36
#define SHA1_HMAC_OPAD  0x5c
#define SHA1_PADSTART   0x80
#define __SHA1_SHORT    __sha1_short
#define __SHA1_LONG     __sha1_long

    bool __littleEndian_sha1();
    bool __bigEndian_sha1();
    uint32_t __rotl_sha1(uint32_t input, uint8_t count);
    uint32_t __rotr_sha1(uint32_t input, uint8_t count);
    uint32_t __swap_sha1(uint32_t input);
    uint32_t __readLong_sha1(CHUNK input, CHUNK_SIZE index);
    bool __writeLong_sha1(CHUNK input, CHUNK_SIZE index, uint32_t value);
    uint32_t __readBuffer_sha1(CHUNK bufferA, CHUNK bufferB, CHUNK_SIZE index);
    bool __writeBuffer_sha1(CHUNK bufferA, CHUNK bufferB, CHUNK_SIZE index, uint32_t value);


    CHUNK hash_sha1(CHUNK input);
    CHUNK hmac_sha1(CHUNK input, CHUNK password);

#ifdef	__cplusplus
}
#endif

#endif	/* __SHA1UINO_H__ */
