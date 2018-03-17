/*
 * File:    base64uino.c
 * Author:  Yahe <hello@yahe.sh>
 * Version: 0.4.0
 *
 * Created on 09. April 2013
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
 * base64uino.c contains an implementation of the Base64 encoding algorithm.
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

#include "base64uino.h"

PROGMEM prog_uchar BASE64_SET[BASE64_CHAR_COUNT] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G',
    'H', 'I', 'J', 'K', 'L', 'M', 'N',
    'O', 'P', 'Q', 'R', 'S', 'T', 'U',
    'V', 'W', 'X', 'Y', 'Z', 'a', 'b',
    'c', 'd', 'e', 'f', 'g', 'h', 'i',
    'j', 'k', 'l', 'm', 'n', 'o', 'p',
    'q', 'r', 's', 't', 'u', 'v', 'w',
    'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+',
    '/'
};

CHUNK_TYPE __value_base64(CHUNK_TYPE input) {

    CHUNK_TYPE result = CHUNK_ERROR;

    if (BASE64_PADDING != input) {
        CHUNK_SIZE index = 0x00;

        for (index = 0x00; index < BASE64_CHAR_COUNT; index++) {
            if (pm_byte(BASE64_SET, index) == input) {
                result = index;

                break;
            }
        }
    } else {
        result = 0x00;
    }

    return result;

}

CHUNK encode_base64(CHUNK input) {

    CHUNK result = CHUNK_ERROR;

    // retrieve input size
    CHUNK_SIZE inputSize = sizeof_chunk(input);

    if (0x00 < inputSize) {
        CHUNK_TYPE charA = 0x00;
        CHUNK_TYPE charB = 0x00;
        CHUNK_TYPE charC = 0x00;
        CHUNK_SIZE inputIndex = 0x00;
        CHUNK_SIZE padSize = 0x00;
        CHUNK_SIZE resultIndex = 0x00;
        CHUNK_SIZE resultSize = 0x00;

        // pad result
        padSize = inputSize % BASE64_RATIO_BEFORE;

        // calculate result size
        resultSize = (((inputSize + BASE64_RATIO_BEFORE - 0x01) / BASE64_RATIO_BEFORE) * BASE64_RATIO_AFTER);

        // get result chunk
        result = alloc_chunk(resultSize);

        // map to base64 set
        inputIndex = 0x00;
        resultIndex = 0x00;
        while (inputIndex < inputSize) {
            // get next character values
            if ((inputIndex + 0x00) < inputSize) {
                charA = get_chunk(input, inputIndex + 0x00);
            } else {
                charA = 0x00;
            }
            if ((inputIndex + 0x01) < inputSize) {
                charB = get_chunk(input, inputIndex + 0x01);
            } else {
                charB = 0x00;
            }
            if ((inputIndex + 0x02) < inputSize) {
                charC = get_chunk(input, inputIndex + 0x02);
            } else {
                charC = 0x00;
            }

            // grap characters from character set
            set_chunk(result, resultIndex + 0x00, pm_byte(BASE64_SET, ((charA >> 0x02) & 0x3F)));
            set_chunk(result, resultIndex + 0x01, pm_byte(BASE64_SET, (((charA << 0x04) & 0x30) | ((charB >> 0x04) & 0x0F))));
            set_chunk(result, resultIndex + 0x02, pm_byte(BASE64_SET, (((charB << 0x02) & 0x3C) | ((charC >> 0x06) & 0x03))));
            set_chunk(result, resultIndex + 0x03, pm_byte(BASE64_SET, (charC & 0x3F)));

            // increment base index
            inputIndex += BASE64_RATIO_BEFORE;
            resultIndex += BASE64_RATIO_AFTER;
        }

        if (padSize > 0x00) {
            for (resultIndex = 0x00; padSize < BASE64_RATIO_BEFORE; resultIndex++, padSize++) {
                set_chunk(result, resultSize - resultIndex - 0x01, BASE64_PADDING);
            }
        }
    }

    // clean up memory
    zeroFreeMem_chunk();

    return result;

}

// FIXME: (minor)
// When BASE64_PADDING characters in the middle of the
// input the they are interpreted as simple '0' characters
// not leading to an abortion. This can be handled by some
// more if statements in the garbage check. But as it is,
// this does not impose any problems in the current
// situation.
//
// "0A=A" is equivalent to "0A0A".

CHUNK decode_base64(CHUNK input) {

    CHUNK result = CHUNK_ERROR;

    // retrieve input size
    CHUNK_SIZE inputSize = sizeof_chunk(input);

    if (0x00 < inputSize) {
        CHUNK_TYPE charA = 0x00;
        CHUNK_TYPE charB = 0x00;
        CHUNK_TYPE charC = 0x00;
        CHUNK_TYPE charD = 0x00;
        CHUNK_SIZE inputIndex = 0x00;
        CHUNK_SIZE padSize = 0x00;
        CHUNK_SIZE resultIndex = 0x00;
        CHUNK_SIZE resultSize = 0x00;

        // count padding chars
        inputIndex = inputSize - 0x01;
        padSize = 0x00;
        while (true) {
            if (BASE64_PADDING == get_chunk(input, inputIndex)) {
                padSize++;

                if (0x00 < inputIndex) {
                    inputIndex--;
                } else {
                    break;
                }
            } else {
                break;
            }

        }

        // if we found some non-garbage
        if (padSize < inputSize) {
            // calculate result size
            resultSize = (((inputSize + BASE64_RATIO_AFTER - 0x01) / BASE64_RATIO_AFTER) * BASE64_RATIO_BEFORE);

            // get result chunk
            result = alloc_chunk(resultSize);

            // map to base64 set
            inputIndex = 0x00;
            resultIndex = 0x00;
            while (inputIndex < inputSize) {
                // get next character values
                if ((inputIndex + 0x00) < inputSize) {
                    charA = __value_base64(get_chunk(input, inputIndex + 0x00));
                } else {
                    // missing padding character
                    charA = 0x00;
                    padSize++;
                }
                if ((inputIndex + 0x01) < inputSize) {
                    charB = __value_base64(get_chunk(input, inputIndex + 0x01));
                } else {
                    // missing padding character
                    charB = 0x00;
                    padSize++;
                }
                if ((inputIndex + 0x02) < inputSize) {
                    charC = __value_base64(get_chunk(input, inputIndex + 0x02));
                } else {
                    // missing padding character
                    charC = 0x00;
                    padSize++;
                }
                if ((inputIndex + 0x03) < inputSize) {
                    charD = __value_base64(get_chunk(input, inputIndex + 0x03));
                } else {
                    // missing padding character
                    charD = 0x00;
                    padSize++;
                }

                // only proceed if we did not encounter garbage
                if ((CHUNK_ERROR != charA) && (CHUNK_ERROR != charB) &&
                        (CHUNK_ERROR != charC) && (CHUNK_ERROR != charD)) {
                    // set characters
                    set_chunk(result, resultIndex + 0x00, ((charA << 0x02) & 0xFC) | ((charB >> 0x04) & 0x03));
                    set_chunk(result, resultIndex + 0x01, ((charB << 0x04) & 0xF0) | ((charC >> 0x02) & 0x0F));
                    set_chunk(result, resultIndex + 0x02, ((charC << 0x06) & 0xC0) | (charD & 0x3F));

                    // increment base index
                    inputIndex += 0x04;
                    resultIndex += 0x03;
                } else {
                    // leave loop
                    dealloc_chunk(result);
                    result = CHUNK_ERROR;

                    break;
                }
            }

            if (CHUNK_ERROR != result) {
                // enforce padding
                resize_chunk(result, resultSize - padSize);
            }
        }
    }

    // clean up memory
    zeroFreeMem_chunk();

    return result;

}
