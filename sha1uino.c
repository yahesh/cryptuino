/*
 * File:    sha1uino.c
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
 * sha1uino.c contains an implementation of the SHA-1 hash algorithm.
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

// FIXME: (major)
// This library works for little endian systems.
// This has been tested on Mac OS X 10.7 (Lion)
// and on the Arduino platform. However it is not
// save to asume that this library also works for
// big endian systems. This has not been tested
// due to the lack of access to a big endian
// system. There are functions in place to check
// for endianess and to do swaps. However, they
// are currently not in use.

#include "sha1uino.h"

// __sha1_short
// __SHA1_SHORT

typedef union {
    uint16_t Short;
    uint8_t Chars[sizeof (uint16_t) / sizeof (uint8_t)];
} __sha1_short;

// __sha1_long
// __SHA1_LONG

typedef union {
    uint32_t Long;
    uint8_t Chars[sizeof (uint32_t) / sizeof (uint8_t)];
} __sha1_long;

bool __littleEndian_sha1() {

    __SHA1_SHORT temp;

    temp.Short = 0x01;

    // so memory layout is "[0x01][0x00]"
    return (temp.Chars[0x00] == 0x01);

}

bool __bigEndian_sha1() {

    return (!__littleEndian_sha1());

}

uint32_t __rotl_sha1(uint32_t input, uint8_t count) {

    // can only be n bits (depending on size of uint32_t)
    count = count % (sizeof (uint32_t) * 0x08);

    return ((input << count) | (input >> ((sizeof (uint32_t) * 0x08) - count)));

}

uint32_t __rotr_sha1(uint32_t input, uint8_t count) {

    // can only be n bits (depending on size of uint32_t)
    count = count % (sizeof (uint32_t) * 0x08);

    return ((input >> count) | (input << ((sizeof (uint32_t) * 0x08) - count)));

}

// will change input to big endian

uint32_t __swap_sha1(uint32_t input) {

    uint32_t result = input;

    if (__bigEndian_sha1()) {
        uint8_t tempChar;
        __SHA1_LONG tempLong;

        // swap from "[a][b][c][d]" to "[d][c][b][a]"
        tempLong.Long = input;
        tempChar = tempLong.Chars[0x00];
        tempLong.Chars[0x00] = tempLong.Chars[0x03];
        tempLong.Chars[0x03] = tempChar;
        tempChar = tempLong.Chars[0x01];
        tempLong.Chars[0x01] = tempLong.Chars[0x02];
        tempLong.Chars[0x02] = tempChar;

        result = tempLong.Long;
    }

    return result;

}

uint32_t __readLong_sha1(CHUNK input, CHUNK_SIZE index) {

    uint32_t result = 0x00000000;

    CHUNK_SIZE inputSize = sizeof_chunk(input);

    if (((index + 0x01) * sizeof (uint32_t)) <= inputSize) {
        result = (((uint32_t) get_chunk(input, index * sizeof (uint32_t) + 0x00) << 0x18) |
                ((uint32_t) get_chunk(input, index * sizeof (uint32_t) + 0x01) << 0x10) |
                ((uint32_t) get_chunk(input, index * sizeof (uint32_t) + 0x02) << 0x08) |
                ((uint32_t) get_chunk(input, index * sizeof (uint32_t) + 0x03) << 0x00));
    }

    return result;

}

bool __writeLong_sha1(CHUNK input, CHUNK_SIZE index, uint32_t value) {

    bool result = false;

    CHUNK_SIZE inputSize = sizeof_chunk(input);

    if (((index + 0x01) * sizeof (uint32_t)) <= inputSize) {
        set_chunk(input, index * sizeof (uint32_t) + 0x00, (CHUNK_TYPE) ((value >> 0x18) & 0xFF));
        set_chunk(input, index * sizeof (uint32_t) + 0x01, (CHUNK_TYPE) ((value >> 0x10) & 0xFF));
        set_chunk(input, index * sizeof (uint32_t) + 0x02, (CHUNK_TYPE) ((value >> 0x08) & 0xFF));
        set_chunk(input, index * sizeof (uint32_t) + 0x03, (CHUNK_TYPE) ((value >> 0x00) & 0xFF));

        result = true;
    }

    return result;

}

uint32_t __readBuffer_sha1(CHUNK bufferA, CHUNK bufferB, CHUNK_SIZE index) {

    uint32_t result = 0x00000000;

    CHUNK_SIZE bufferASize = sizeof_chunk(bufferA) / sizeof (uint32_t);
    CHUNK_SIZE bufferBSize = sizeof_chunk(bufferB) / sizeof (uint32_t);

    if (index < bufferASize) {
        result = __readLong_sha1(bufferA, index);
    } else {
        if (index < (bufferASize + bufferBSize)) {
            result = __readLong_sha1(bufferB, index - bufferASize);
        }
    }

    return result;

}

bool __writeBuffer_sha1(CHUNK bufferA, CHUNK bufferB, CHUNK_SIZE index, uint32_t value) {

    bool result = false;

    CHUNK_SIZE bufferASize = sizeof_chunk(bufferA) / sizeof (uint32_t);
    CHUNK_SIZE bufferBSize = sizeof_chunk(bufferB) / sizeof (uint32_t);

    if (index < bufferASize) {
        result = __writeLong_sha1(bufferA, index, value);
    } else {
        if (index < (bufferASize + bufferBSize)) {
            result = __writeLong_sha1(bufferB, index - bufferASize, value);
        }
    }

    return result;

}

CHUNK hash_sha1(CHUNK input) {

    CHUNK result = CHUNK_ERROR;

    // initialize output
    uint32_t hashA = SHA1_HASH1;
    uint32_t hashB = SHA1_HASH2;
    uint32_t hashC = SHA1_HASH3;
    uint32_t hashD = SHA1_HASH4;
    uint32_t hashE = SHA1_HASH5;

    // pad input to 512 bit blocks
    CHUNK_SIZE inputSize = sizeof_chunk(input);
    CHUNK tempInput = CHUNK_ERROR;

    if (0x00 < inputSize) {
        // calculate size of tempInput
        CHUNK_SIZE newSize = ((inputSize + SHA1_BLOCKSIZE - 0x01) / SHA1_BLOCKSIZE) * SHA1_BLOCKSIZE;

        if ((newSize - inputSize) < (sizeof (uint32_t) * 0x02)) {
            newSize += SHA1_BLOCKSIZE;
        }

        tempInput = alloc_chunk(newSize);
        copy_chunk(input, tempInput);
        set_chunk(tempInput, inputSize, SHA1_PADSTART);

        // set padding length in bits
        CHUNK_SIZE padIndex = 0x00;
        __SHA1_LONG padSize;

        padSize.Long = ((uint32_t) inputSize) * 0x08;
        for (padIndex = 0x00; sizeof (uint32_t) > padIndex; padIndex++) {
            set_chunk(tempInput, newSize - padIndex - 0x01, padSize.Chars[padIndex]);
        }
    } else {
        tempInput = alloc_chunk(SHA1_BLOCKSIZE);
        zero_chunk(tempInput);
        set_chunk(tempInput, 0x00, SHA1_PADSTART);
    }

    // main loop
    CHUNK bufferA = alloc_chunk(0x28 * sizeof (uint32_t)); // 40 long space
    CHUNK bufferB = alloc_chunk(0x28 * sizeof (uint32_t)); // 40 long space
    CHUNK_SIZE index = 0x00;
    CHUNK_SIZE longIndex = 0x00;
    CHUNK_SIZE tempSize = sizeof_chunk(tempInput);
    uint32_t key = 0x00000000;
    uint32_t partA = 0x00000000;
    uint32_t partB = 0x00000000;
    uint32_t partC = 0x00000000;
    uint32_t partD = 0x00000000;
    uint32_t partE = 0x00000000;
    uint32_t round = 0x00000000;
    uint32_t spare = 0x00000000;

    for (index = 0x00; index < (tempSize / SHA1_BLOCKSIZE); index++) {
        // set up word spaces with next block
        zero_chunk(bufferA); // clear long space
        zero_chunk(bufferB); // clear long space
        for (longIndex = 0x00; longIndex < (SHA1_BLOCKSIZE / sizeof (uint32_t)); longIndex++) {
            __writeBuffer_sha1(bufferA, bufferB, longIndex,
                    __readLong_sha1(tempInput, (index * (SHA1_BLOCKSIZE / sizeof (uint32_t)) + longIndex)));
        }
        for (longIndex = (SHA1_BLOCKSIZE / sizeof (uint32_t)); longIndex < ((sizeof_chunk(bufferA) + sizeof_chunk(bufferB)) / sizeof (uint32_t)); longIndex++) {
            spare = __readBuffer_sha1(bufferA, bufferB, longIndex - 0x03) ^
                    __readBuffer_sha1(bufferA, bufferB, longIndex - 0x08) ^
                    __readBuffer_sha1(bufferA, bufferB, longIndex - 0x0E) ^
                    __readBuffer_sha1(bufferA, bufferB, longIndex - 0x10);
            __writeBuffer_sha1(bufferA, bufferB, longIndex,
                    __rotl_sha1(spare, 0x01));
        }

        // initialize parts for this round
        partA = hashA;
        partB = hashB;
        partC = hashC;
        partD = hashD;
        partE = hashE;

        for (longIndex = 0x00; longIndex < ((sizeof_chunk(bufferA) + sizeof_chunk(bufferB)) / sizeof (uint32_t)); longIndex++) {
            if (0x13 >= longIndex) {
                key = SHA1_KEY1;
                round = (partB & partC) | ((0xFFFFFFFF ^ partB) & partD);
            } else {
                if ((0x14 <= longIndex) && (0x27 >= longIndex)) {
                    key = SHA1_KEY2;
                    round = partB ^ partC ^ partD;
                } else {
                    if ((0x28 <= longIndex) && (0x3B >= longIndex)) {
                        key = SHA1_KEY3;
                        round = (partB & partC) | (partB & partD) | (partC & partD);
                    } else {
                        if ((0x3C <= longIndex) && (0x4F >= longIndex)) {
                            key = SHA1_KEY4;
                            round = partB ^ partC ^ partD;
                        }
                    }
                }
            }

            // calculate next round state
            spare = __rotl_sha1(partA, 0x05) + round + partE + key + __readBuffer_sha1(bufferA, bufferB, longIndex);
            partE = partD;
            partD = partC;
            partC = __rotl_sha1(partB, 0x1E);
            partB = partA;
            partA = spare;
        }

        // add results to the hash
        hashA += partA;
        hashB += partB;
        hashC += partC;
        hashD += partD;
        hashE += partE;
    }

    // do some clean up
    dealloc_chunk(bufferB);
    dealloc_chunk(bufferA);
    dealloc_chunk(tempInput);

    partA = 0x00000000;
    partB = 0x00000000;
    partC = 0x00000000;
    partD = 0x00000000;
    partE = 0x00000000;
    round = 0x00000000;
    spare = 0x00000000;

    // try to make sure the clean up is not optimized away
    hashA += partA + round + spare;
    hashB += partB + round + spare;
    hashC += partC + round + spare;
    hashD += partD + round + spare;
    hashE += partE + round + spare;

    // write the actual result
    result = alloc_chunk(SHA1_OUTPUTSIZE);
    __writeLong_sha1(result, 0x00, hashA);
    __writeLong_sha1(result, 0x01, hashB);
    __writeLong_sha1(result, 0x02, hashC);
    __writeLong_sha1(result, 0x03, hashD);
    __writeLong_sha1(result, 0x04, hashE);

    // clean up memory
    zeroFreeMem_chunk();

    return result;

}

CHUNK hmac_sha1(CHUNK input, CHUNK password) {

    CHUNK result = CHUNK_ERROR;

    CHUNK_SIZE inputSize = sizeof_chunk(input);
    CHUNK_SIZE passwordSize = sizeof_chunk(password);

    if ((0x00 < inputSize) && (0x00 < passwordSize)) {
        CHUNK halfOutput = CHUNK_ERROR;
        CHUNK_SIZE padIndex = 0x00;
        CHUNK tempPassword = CHUNK_ERROR;

        if (passwordSize > SHA1_BLOCKSIZE) {
            // reduce size of password
            tempPassword = hash_sha1(password);
        }
        if (passwordSize < SHA1_BLOCKSIZE) {
            // pad password to match SHA-1 block size
            if (CHUNK_ERROR == tempPassword) {
                tempPassword = alloc_chunk(SHA1_BLOCKSIZE);
                copy_chunk(password, tempPassword);
            } else {
                resize_chunk(tempPassword, SHA1_BLOCKSIZE);
                for (padIndex = SHA1_OUTPUTSIZE; SHA1_BLOCKSIZE > padIndex; padIndex++) {
                    set_chunk(tempPassword, padIndex, 0x00);
                }
            }
        }

        if (CHUNK_ERROR != tempPassword) {
            // pad tempPassword to IPAD
            for (padIndex = 0x00; SHA1_BLOCKSIZE > padIndex; padIndex++) {
                set_chunk(tempPassword, padIndex, get_chunk(tempPassword, padIndex) ^ SHA1_HMAC_IPAD);
            }

            // append input to tempPassword
            resize_chunk(tempPassword, SHA1_BLOCKSIZE + inputSize);
            copyOffsetLength_chunk(input, tempPassword, 0x00, SHA1_BLOCKSIZE, inputSize);

            halfOutput = hash_sha1(tempPassword);

            if (CHUNK_ERROR != halfOutput) {
                // pad tempPassword to OPAD
                for (padIndex = 0x00; SHA1_BLOCKSIZE > padIndex; padIndex++) {
                    set_chunk(tempPassword, padIndex, get_chunk(tempPassword, padIndex) ^ SHA1_HMAC_IPAD ^ SHA1_HMAC_OPAD);
                }

                // append halfOutput to tempPassword
                resize_chunk(tempPassword, SHA1_BLOCKSIZE + SHA1_OUTPUTSIZE);
                copyOffsetLength_chunk(halfOutput, tempPassword, 0x00, SHA1_BLOCKSIZE, SHA1_OUTPUTSIZE);

                // clean halfOutput
                dealloc_chunk(halfOutput);

                result = hash_sha1(tempPassword);
            }

            // clean tempPassword,
            dealloc_chunk(tempPassword);
        }
    }

    // clean up memory
    zeroFreeMem_chunk();

    return result;

}
