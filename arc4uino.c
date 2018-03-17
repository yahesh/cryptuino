/*
 * File:    arc4uino.c
 * Author:  Yahe <hello@yahe.sh>
 * Version: 0.4.0
 *
 * Created on 14. April 2013
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
 * arc4uino.c contains an implementation of the Arc4 encryption algorithm.
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

#include "arc4uino.h"

CHUNK_TYPE __readBuffer_arc4(CHUNK bufferA, CHUNK bufferB, MEM_SIZE index) {

    CHUNK_TYPE result = 0x00;

    MEM_SIZE bufferASize = (MEM_SIZE) sizeof_chunk(bufferA);
    MEM_SIZE bufferBSize = (MEM_SIZE) sizeof_chunk(bufferB);

    if (index < bufferASize) {
        result = get_chunk(bufferA, (CHUNK_SIZE) index);
    } else {
        if (index < (bufferASize + bufferBSize)) {
            result = get_chunk(bufferB, (CHUNK_SIZE) (index - bufferASize));
        }
    }

    return result;

}

bool __writeBuffer_arc4(CHUNK bufferA, CHUNK bufferB, MEM_SIZE index, CHUNK_TYPE value) {

    bool result = false;

    MEM_SIZE bufferASize = (MEM_SIZE) sizeof_chunk(bufferA);
    MEM_SIZE bufferBSize = (MEM_SIZE) sizeof_chunk(bufferB);

    if (index < bufferASize) {
        result = set_chunk(bufferA, (CHUNK_SIZE) index, value);
    } else {
        if (index < (bufferASize + bufferBSize)) {
            result = set_chunk(bufferB, (CHUNK_SIZE) (index - bufferASize), value);
        }
    }

    return result;

}

CHUNK __arc4(CHUNK input, CHUNK password) {

    CHUNK result = CHUNK_ERROR;

    CHUNK_SIZE inputSize = sizeof_chunk(input);
    CHUNK_SIZE passwordSize = sizeof_chunk(password);

    if ((0x00 < inputSize) && (0x00 < passwordSize)) {
        CHUNK bufferA = alloc_chunk((CHUNK_SIZE) (ARC4_BUFFERSIZE / 0x02));
        CHUNK bufferB = alloc_chunk((CHUNK_SIZE) (ARC4_BUFFERSIZE / 0x02));

        if ((CHUNK_ERROR != bufferA) && (CHUNK_ERROR != bufferB)) {
            MEM_SIZE bufferIndex = 0x0000;
            CHUNK_SIZE chunkIndex = 0x00;

            result = alloc_chunk(inputSize);
            if (CHUNK_ERROR != result) {
                CHUNK_TYPE temp = 0x00;
                MEM_SIZE tempIndex = 0x0000;

                // intialize buffer
                for (bufferIndex = 0x0000; ARC4_BUFFERSIZE > bufferIndex; bufferIndex++) {
                    __writeBuffer_arc4(bufferA, bufferB, bufferIndex, (CHUNK_TYPE) bufferIndex);
                }
                for (bufferIndex = 0x0000; ARC4_BUFFERSIZE > bufferIndex; bufferIndex++) {
                    tempIndex = ((MEM_SIZE) get_chunk(password, (CHUNK_SIZE) (bufferIndex % passwordSize)) +
                            (MEM_SIZE) __readBuffer_arc4(bufferA, bufferB, bufferIndex) +
                            tempIndex) % ARC4_BUFFERSIZE;

                    temp = __readBuffer_arc4(bufferA, bufferB, tempIndex);
                    __writeBuffer_arc4(bufferA, bufferB, tempIndex, __readBuffer_arc4(bufferA, bufferB, bufferIndex));
                    __writeBuffer_arc4(bufferA, bufferB, bufferIndex, temp);
                }

                MEM_SIZE indexA = 0x0000;
                MEM_SIZE indexB = 0x0000;

                // harden the encryption by throwing away
                // the first N bytes of the key stream
                for (bufferIndex = 0x0000; ARC4_DROPPEDBYTES > bufferIndex; bufferIndex++) {
                    indexA = (indexA + 0x01) % ARC4_BUFFERSIZE;
                    indexB = ((MEM_SIZE) __readBuffer_arc4(bufferA, bufferB, indexA) +
                            indexB) % ARC4_BUFFERSIZE;

                    temp = __readBuffer_arc4(bufferA, bufferB, indexA);
                    __writeBuffer_arc4(bufferA, bufferB, indexA, __readBuffer_arc4(bufferA, bufferB, indexB));
                    __writeBuffer_arc4(bufferA, bufferB, indexB, temp);
                }

                // do the actual encryption
                for (chunkIndex = 0x00; inputSize > chunkIndex; chunkIndex++) {
                    indexA = (indexA + 0x01) % ARC4_BUFFERSIZE;
                    indexB = ((MEM_SIZE) __readBuffer_arc4(bufferA, bufferB, indexA) +
                            indexB) % ARC4_BUFFERSIZE;

                    temp = __readBuffer_arc4(bufferA, bufferB, indexA);
                    __writeBuffer_arc4(bufferA, bufferB, indexA, __readBuffer_arc4(bufferA, bufferB, indexB));
                    __writeBuffer_arc4(bufferA, bufferB, indexB, temp);

                    tempIndex = (__readBuffer_arc4(bufferA, bufferB, indexA) +
                            __readBuffer_arc4(bufferA, bufferB, indexB)) % ARC4_BUFFERSIZE;
                    temp = __readBuffer_arc4(bufferA, bufferB, tempIndex);
                    set_chunk(result, chunkIndex, get_chunk(input, chunkIndex) ^ temp);
                }

                // do some clean up
                indexA = 0x0000;
                indexB = 0x0000;
                tempIndex = 0x0000;
                temp = 0x00;
            }
        }

        dealloc_chunk(bufferA);
        dealloc_chunk(bufferB);
    }

    // clean up memory
    zeroFreeMem_chunk();

    return result;

}

CHUNK encrypt_arc4(CHUNK input, CHUNK password) {

    return __arc4(input, password);

}

CHUNK decrypt_arc4(CHUNK input, CHUNK password) {

    return __arc4(input, password);

}
