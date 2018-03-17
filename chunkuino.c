/*
 * File:    chunkuino.c
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
 * chunkuino.c contains an implementation of a simple memory chunk manager.
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

#include "chunkuino.h"

// __chunk_type
// __CHUNK_TYPE

typedef struct {
    CHUNK number;
    CHUNK_SIZE size;
} __chunk_type;

__CHUNK __chunk_table = NULL;

CHUNK_SIZE __chunk_count = 0x00;
CHUNK_SIZE __chunk_max = 0x00;
CHUNK_SIZE __chunk_min = 0x00;

CHUNK init_chunk(MEM_SIZE memSize, CHUNK_SIZE chunkCount) {

    CHUNK result = CHUNK_ERROR;

    if ((!is_init_chunk()) && (0x0000 < memSize) && (0x00 < chunkCount) && (CHUNK_ERROR > chunkCount)) {
        init_mem(memSize);
        if (is_init_mem()) {
            __chunk_count = chunkCount;
            __chunk_max = chunkCount - 0x01;
            __chunk_min = 0x00;

            __chunk_table = (__CHUNK) malloc(sizeof (__CHUNK_TYPE) * COUNTOF_CHUNK);

            if (is_init_chunk()) {
                // preset the numbers of the chunks
                // this is important so that alloc_chunk()
                // knows which number to use for a new chunk
                CHUNK index = 0x00;

                for (index = MIN_CHUNK; index <= MAX_CHUNK; index++) {
                    __chunk_table[index].number = index;
                    __chunk_table[index].size = 0x00;
                }

                result = COUNTOF_CHUNK;
            }
        }
    }

    return result;

}

bool deinit_chunk() {

    bool result = false;

    if (is_init_chunk()) {
        deinit_mem();
        if (!is_init_mem()) {
            free(__chunk_table);
            __chunk_table = NULL;

            __chunk_count = 0x0000;
            __chunk_max = 0x0000;
            __chunk_min = 0x0000;

            result = true;
        }
    }

    return result;

}

bool is_init_chunk() {

    return ((is_init_mem()) && (0x00 < COUNTOF_CHUNK) && (NULL != __chunk_table));

}

CHUNK alloc_chunk(CHUNK_SIZE size) {

    CHUNK result = CHUNK_ERROR;

    if ((is_init_chunk()) && (0x00 < free_chunk()) && (size <= freeMem_chunk()) && (0x00 < size)) {
        CHUNK index = 0x00;

        for (index = MIN_CHUNK; index <= MAX_CHUNK; index++) {
            if (0x00 == __chunk_table[index].size) {
                // the number of the chunk is already known
                // have a look at init_chunk() and dealloc_chunk()
                // to see how this works
                __chunk_table[index].size = size;

                result = __chunk_table[index].number;

                break;
            }
        }
    }

    return result;

}

bool dealloc_chunk(CHUNK number) {

    bool result = false;

    if ((is_init_chunk()) && (number < COUNTOF_CHUNK)) {
        // find position of chunk in memory
        CHUNK index = 0x00;
        MEM memPosition = MIN_MEM;

        for (index = MIN_CHUNK; index <= MAX_CHUNK; index++) {
            // if chunk is at current position purge
            // used memory, update chunk table and
            // leave the loop
            if (number == __chunk_table[index].number) {
                __CHUNK_TYPE chunk;
                CHUNK chunkIndex = 0x00;
                CHUNK maxIndex = 0x00;
                MEM_SIZE memUsed = 0x0000;

                // save data of the chunk that is to be deleted
                chunk.number = __chunk_table[index].number;
                chunk.size = __chunk_table[index].size;

                // calculate used memory BEHIND the chunk that is
                // to be deleted - this is used to move the memory
                memUsed = 0x0000;
                for (chunkIndex = index + 0x01; chunkIndex <= MAX_CHUNK; chunkIndex++) {
                    if (0x00 < __chunk_table[chunkIndex].size) {
                        memUsed += __chunk_table[chunkIndex].size;
                    } else {
                        break;
                    }
                }

                // move memory whereby memPosition is the memory
                // position of the chunk that is to be deleted
                if (memUsed > 0x0000) {
                    copy_mem(memPosition + chunk.size, memPosition, memUsed);
                }

                // update the chunk table by repeatedly copying the
                // next chunk one chunk below - keep track of maxIndex
                // so the first empty chunk gets the number of the
                // removed chunk => THIS IS IMPORTANT!
                maxIndex = index;
                for (chunkIndex = index; chunkIndex < MAX_CHUNK; chunkIndex++) {
                    if (0x00 < __chunk_table[chunkIndex + 0x01].size) {
                        __chunk_table[chunkIndex].number = __chunk_table[chunkIndex + 0x01].number;
                        __chunk_table[chunkIndex].size = __chunk_table[chunkIndex + 0x01].size;

                        maxIndex = chunkIndex + 0x01;
                    } else {
                        break;
                    }
                }

                // set the number of the first empty chunk
                // this is important so alloc_chunk() knows
                // which number to use
                __chunk_table[maxIndex].number = chunk.number;
                __chunk_table[maxIndex].size = 0x00;

                break;
            } else {
                // if current chunk is not requested chunk
                // move offset behind bounds of current chunk
                // if we encounter an empty chunk
                // leave the loop
                if (0x00 < __chunk_table[index].size) {
                    memPosition += __chunk_table[index].size;
                } else {
                    break;
                }
            }
        }
    }

    return result;

}

bool is_alloc_chunk(CHUNK number) {

    return (0x00 < sizeof_chunk(number));

}

bool resize_chunk(CHUNK number, CHUNK_SIZE size) {

    bool result = false;

    if ((is_init_chunk()) && (number < COUNTOF_CHUNK) && (0x00 < size)) {
        // find position of chunk in memory
        CHUNK index = 0x00;
        MEM memPosition = MIN_MEM;

        for (index = MIN_CHUNK; index <= MAX_CHUNK; index++) {
            // if chunk is at current position enlarge
            // or reduce used memory, update chunk table
            // and leave the loop
            if (number == __chunk_table[index].number) {
                if (size != __chunk_table[index].size) {
                    CHUNK chunkIndex = 0x00;
                    MEM_SIZE memUsed = 0x0000;

                    // calculate used memory BEHIND the chunk that is
                    // to be resized - this is used to move the memory
                    memUsed = 0x0000;
                    for (chunkIndex = index + 0x01; chunkIndex <= MAX_CHUNK; chunkIndex++) {
                        if (0x00 < __chunk_table[chunkIndex].size) {
                            memUsed += __chunk_table[chunkIndex].size;
                        } else {
                            break;
                        }
                    }

                    // if the resized chunk fits into the memory
                    if (SIZEOF_MEM >= memPosition + memUsed + size) {
                        // move memory whereby memPosition is the memory
                        // position of the chunk that is to be deleted
                        if (0x0000 < memUsed) {
                            if (size > __chunk_table[index].size) {
                                // copy in reverse order to not loose any bytes
                                copy_mem_rev(memPosition + __chunk_table[index].size,
                                        memPosition + size, memUsed);
                            } else {
                                copy_mem(memPosition + __chunk_table[index].size,
                                        memPosition + size, memUsed);
                            }
                        }

                        // update the size of the resized chunk
                        __chunk_table[index].size = size;

                        result = true;
                    }
                } else {
                    // everything is fine when the size does not change
                    result = true;
                }

                break;
            } else {
                // if current chunk is not requested chunk
                // move offset behind bounds of current chunk
                // if we encounter an empty chunk
                // leave the loop
                if (0x00 < __chunk_table[index].size) {
                    memPosition += __chunk_table[index].size;
                } else {
                    break;
                }
            }
        }
    }

    return result;

}

CHUNK_SIZE countof_chunk() {

    return __chunk_count;

}

CHUNK_SIZE max_chunk() {

    return __chunk_max;

}

CHUNK_SIZE min_chunk() {

    return __chunk_min;

}

CHUNK_SIZE free_chunk() {

    CHUNK_SIZE result = 0x00;

    if (is_init_chunk()) {
        result = COUNTOF_CHUNK - used_chunk();
    }

    return result;

}

CHUNK_SIZE used_chunk() {

    CHUNK_SIZE result = 0x00;

    if (is_init_chunk()) {
        CHUNK index = 0x00;

        for (index = MIN_CHUNK; index <= MAX_CHUNK; index++) {
            if (0x00 < __chunk_table[index].size) {
                result++;
            } else {
                break;
            }
        }
    }

    return result;

}

MEM_SIZE freeMem_chunk() {

    MEM_SIZE result = 0x0000;

    if (is_init_chunk()) {
        result = SIZEOF_MEM - usedMem_chunk();
    }

    return result;

}

MEM_SIZE usedMem_chunk() {

    MEM_SIZE result = 0x0000;

    if (is_init_chunk()) {
        CHUNK index = 0x00;

        for (index = MIN_CHUNK; index <= MAX_CHUNK; index++) {
            if (0x00 < __chunk_table[index].size) {
                result += __chunk_table[index].size;
            } else {
                break;
            }
        }
    }

    return result;

}

CHUNK_SIZE sizeof_chunk(CHUNK number) {

    CHUNK_SIZE result = 0x00;

    if ((is_init_chunk()) && (number < COUNTOF_CHUNK)) {
        CHUNK index = 0x00;

        for (index = MIN_CHUNK; index <= MAX_CHUNK; index++) {
            if (0x00 < __chunk_table[index].size) {
                if (number == __chunk_table[index].number) {
                    result = __chunk_table[index].size;

                    break;
                }
            } else {
                break;
            }
        }
    }

    return result;

}

CHUNK_TYPE get_chunk(CHUNK number, CHUNK_SIZE position) {

    CHUNK_TYPE result = 0x00;

    if ((is_init_chunk()) && (number < COUNTOF_CHUNK)) {
        // find position of chunk in memory
        CHUNK index = 0x00;
        MEM memPosition = MIN_MEM;

        for (index = MIN_CHUNK; index <= MAX_CHUNK; index++) {
            // if chunk is at current position read
            // from position offset and leave the loop
            if (number == __chunk_table[index].number) {
                // if requested position within chunk matches
                // the bounds of the chunk then get the
                // value at that position
                if (position < __chunk_table[index].size) {
                    result = get_mem(memPosition + position);
                }

                break;
            } else {
                // if current chunk is not requested chunk
                // move offset behind bounds of current chunk
                // if we encounter an empty chunk
                // leave the loop
                if (0x00 < __chunk_table[index].size) {
                    memPosition += __chunk_table[index].size;
                } else {
                    break;
                }
            }
        }
    }

    return result;

}

bool set_chunk(CHUNK number, CHUNK_SIZE position, CHUNK_TYPE value) {

    bool result = false;

    if ((is_init_chunk()) && (number < COUNTOF_CHUNK)) {
        // find position of chunk in memory
        CHUNK index = 0x00;
        MEM memPosition = MIN_MEM;

        for (index = MIN_CHUNK; index <= MAX_CHUNK; index++) {
            // if chunk is at current position read
            // from position offset and leave the loop
            if (number == __chunk_table[index].number) {
                // if requested position within chunk matches
                // the bounds of the chunk then set the
                // value at that position
                if (position < __chunk_table[index].size) {
                    result = set_mem(memPosition + position, value);
                }

                break;
            } else {
                // if current chunk is not requested chunk
                // move offset behind bounds of current chunk
                // if we encounter an empty chunk
                // leave the loop
                if (0x00 < __chunk_table[index].size) {
                    memPosition += __chunk_table[index].size;
                } else {
                    break;
                }
            }
        }
    }

    return result;

}

bool copy_chunk(CHUNK source, CHUNK destination) {

    return copyOffset_chunk(source, destination, 0x00, 0x00);

}

bool copyOffset_chunk(CHUNK source, CHUNK destination,
        CHUNK_SIZE sourceOffset, CHUNK_SIZE destinationOffset) {

    bool result = false;

    CHUNK_SIZE destinationSize = sizeof_chunk(destination);
    CHUNK_SIZE sourceSize = sizeof_chunk(source);

    if ((sourceOffset < sourceSize) &&
            (destinationOffset < destinationSize)) {
        // zero destination chunk
        zeroOffset_chunk(destination, destinationOffset);

        // fill offset dependent of source and destination length and offset
        if (sourceSize - sourceOffset > destinationSize - destinationOffset) {
            result = copyOffsetLength_chunk(source, destination,
                    sourceOffset, destinationOffset, destinationSize - destinationOffset);
        } else {
            result = copyOffsetLength_chunk(source, destination,
                    sourceOffset, destinationOffset, sourceSize - sourceOffset);
        }
    }

    return result;

}

bool copyOffsetLength_chunk(CHUNK source, CHUNK destination,
        CHUNK_SIZE sourceOffset, CHUNK_SIZE destinationOffset,
        CHUNK_SIZE length) {

    bool result = false;

    CHUNK_SIZE destinationSize = sizeof_chunk(destination);
    CHUNK_SIZE sourceSize = sizeof_chunk(source);

    if ((sourceOffset + length <= sourceSize) &&
            (destinationOffset + length <= destinationSize)) {
        CHUNK_SIZE index = 0x00;

        for (index = 0x00; index < length; index++) {
            set_chunk(destination, index + destinationOffset,
                    get_chunk(source, index + sourceOffset));
        }

        result = true;
    }

    return result;

}

CHUNK duplicate_chunk(CHUNK number) {

    CHUNK result = CHUNK_ERROR;

    CHUNK_SIZE chunkSize = sizeof_chunk(number);

    if (0x00 < chunkSize) {
        result = alloc_chunk(chunkSize);
        if (CHUNK_ERROR != result) {
            if (!copy_chunk(number, result)) {
                dealloc_chunk(result);
                result = CHUNK_ERROR;
            }
        }
    }

    return result;

}

bool equal_chunk(CHUNK source, CHUNK destination) {

    bool result = false;

    CHUNK_SIZE destinationSize = sizeof_chunk(destination);
    CHUNK_SIZE sourceSize = sizeof_chunk(source);

    if (sourceSize == destinationSize) {
        result = equalOffset_chunk(source, destination, 0x00, 0x00);
    }

    return result;

}

bool equalOffset_chunk(CHUNK source, CHUNK destination,
        CHUNK_SIZE sourceOffset, CHUNK_SIZE destinationOffset) {

    bool result = false;

    CHUNK_SIZE destinationSize = sizeof_chunk(destination);
    CHUNK_SIZE sourceSize = sizeof_chunk(source);

    if ((sourceOffset < sourceSize) &&
            (destinationOffset < destinationSize) &&
            ((sourceSize - sourceOffset) == (destinationSize - destinationOffset))) {
        result = equalOffsetLength_chunk(source, destination, sourceOffset,
                destinationOffset, (sourceSize - sourceOffset));
    }

    return result;

}

bool equalOffsetLength_chunk(CHUNK source, CHUNK destination,
        CHUNK_SIZE sourceOffset, CHUNK_SIZE destinationOffset,
        CHUNK_SIZE length) {

    bool result = false;

    CHUNK_SIZE destinationSize = sizeof_chunk(destination);
    CHUNK_SIZE sourceSize = sizeof_chunk(source);

    if ((sourceOffset + length <= sourceSize) &&
            (destinationOffset + length <= destinationSize)) {
        CHUNK_SIZE index = 0x00;

        result = true; // set result

        for (index = 0x00; index < length; index++) {
            result = (get_chunk(source, index + sourceOffset) ==
                    get_chunk(destination, index + destinationOffset));
            if (!result) {
                break;
            }
        }
    }

    return result;

}

CHUNK make_chunk(CHUNK_TYPE* chunk, CHUNK_SIZE size) {

    CHUNK result = CHUNK_ERROR;

    if (NULL != chunk) {
        result = alloc_chunk(size);
        if (CHUNK_ERROR != result) {
            CHUNK_SIZE index = 0x00;

            for (index = 0x00; index < size; index++) {
                set_chunk(result, index, chunk[index]);
            }
        }
    }

    return result;

}

bool print_chunk(CHUNK number) {

    bool result = false;

    CHUNK_SIZE chunkSize = sizeof_chunk(number);

    if (0x00 < chunkSize) {
        CHUNK_SIZE index = 0x00;
        CHUNK_TYPE character = 0x00;

        for (index = 0x00; index < chunkSize; index++) {
            character = get_chunk(number, index);
            if (0x20 <= character) {
                printf("%c", (char) (character & 0xFF));
            }
        }
    }

    return result;

}

bool printHex_chunk(CHUNK number) {

    bool result = false;

    CHUNK_SIZE chunkSize = sizeof_chunk(number);

    if (0x00 < chunkSize) {
        CHUNK_SIZE index = 0x00;

        for (index = 0x00; index < chunkSize; index++) {
            printf("%02x", (get_chunk(number, index) & 0xFF));
        }
    }

    return result;

}

bool zero_chunk(CHUNK number) {

    return zeroOffset_chunk(number, 0x00);

}

bool zeroOffset_chunk(CHUNK number, CHUNK_SIZE offset) {

    bool result = false;

    CHUNK_SIZE chunkSize = sizeof_chunk(number);

    if (offset < chunkSize) {
        result = zeroOffsetLength_chunk(number, offset, chunkSize - offset);
    }

    return result;

}

bool zeroOffsetLength_chunk(CHUNK number, CHUNK_SIZE offset, CHUNK_SIZE length) {

    bool result = false;

    CHUNK_SIZE chunkSize = sizeof_chunk(number);

    if (offset + length <= chunkSize) {
        CHUNK_SIZE index = 0x00;

        for (index = 0x00; index < length; index++) {
            set_chunk(number, index + offset, 0x00);
        }

        result = true;
    }

    return result;

}

MEM_SIZE zeroFreeMem_chunk() {

    MEM_SIZE result = 0x0000;

    MEM_SIZE memIndex = 0x0000;
    MEM_SIZE usedMem = usedMem_chunk();

    for (memIndex = MIN_MEM + usedMem; memIndex <= MAX_MEM; memIndex++) {
        set_mem(memIndex, 0x00);

        result++;
    }

    return result;
}
