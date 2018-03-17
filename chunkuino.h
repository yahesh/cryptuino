/*
 * File:    chunkuino.h
 * Author:  Yahe <hello@yahe.sh>
 * Version: 0.4.0
 *
 * Created on 11. April 2013
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
 * chunkuino.h contains an implementation of a simple memory chunk manager.
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

#ifndef __CHUNKUINO_H__
#define	__CHUNKUINO_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include "memuino.h"

#define CHUNK_ERROR 0xFF

#define CHUNK        uint8_t
#define CHUNK_SIZE   uint8_t
#define CHUNK_TYPE   MEM_TYPE
#define __CHUNK_TYPE __chunk_type
#define __CHUNK      __CHUNK_TYPE*

#define COUNTOF_CHUNK countof_chunk()
#define MAX_CHUNK     max_chunk()
#define MIN_CHUNK     min_chunk()

    CHUNK init_chunk(MEM_SIZE memSize, CHUNK_SIZE chunkCount);
    bool deinit_chunk();
    bool is_init_chunk();

    CHUNK alloc_chunk(CHUNK_SIZE size);
    bool dealloc_chunk(CHUNK number);
    bool is_alloc_chunk(CHUNK number);
    bool resize_chunk(CHUNK number, CHUNK_SIZE size);

    CHUNK_SIZE countof_chunk();
    CHUNK_SIZE max_chunk();
    CHUNK_SIZE min_chunk();

    CHUNK_SIZE free_chunk();
    CHUNK_SIZE used_chunk();
    MEM_SIZE freeMem_chunk();
    MEM_SIZE usedMem_chunk();
    CHUNK_SIZE sizeof_chunk(CHUNK number);

    CHUNK_TYPE get_chunk(CHUNK number, CHUNK_SIZE position);
    bool set_chunk(CHUNK number, CHUNK_SIZE position, CHUNK_TYPE value);
    bool copy_chunk(CHUNK source, CHUNK destination);
    bool copyOffset_chunk(CHUNK source, CHUNK destination, CHUNK_SIZE sourceOffset, CHUNK_SIZE destinationOffset);
    bool copyOffsetLength_chunk(CHUNK source, CHUNK destination, CHUNK_SIZE sourceOffset, CHUNK_SIZE destinationOffset, CHUNK_SIZE length);
    CHUNK duplicate_chunk(CHUNK number);
    bool equal_chunk(CHUNK source, CHUNK destination);
    bool equalOffset_chunk(CHUNK source, CHUNK destination, CHUNK_SIZE sourceOffset, CHUNK_SIZE destinationOffset);
    bool equalOffsetLength_chunk(CHUNK source, CHUNK destination, CHUNK_SIZE sourceOffset, CHUNK_SIZE destinationOffset, CHUNK_SIZE length);
    CHUNK make_chunk(CHUNK_TYPE* chunk, CHUNK_SIZE size);
    bool print_chunk(CHUNK number);
    bool printHex_chunk(CHUNK number);
    bool zero_chunk(CHUNK number);
    bool zeroOffset_chunk(CHUNK number, CHUNK_SIZE offset);
    bool zeroOffsetLength_chunk(CHUNK number, CHUNK_SIZE offset, CHUNK_SIZE length);
    MEM_SIZE zeroFreeMem_chunk();

#ifdef	__cplusplus
}
#endif

#endif	/* __CHUNKUINO_H__ */
