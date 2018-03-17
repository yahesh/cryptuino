/*
 * File:    inputuino.c
 * Author:  Yahe <hello@yahe.sh>
 * Version: 0.4.0
 *
 * Created on 24. April 2013
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
 * inputuino.c contains an implementation of the input handling of calc.pw.
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

#include "inputuino.h"

PROGMEM prog_uchar NUMBER_SET[0x0A] = {
    '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9'
};

bool __sort_input(CHUNK input) {

    bool result = false;

    CHUNK_SIZE inputSize = sizeof_chunk(input);

    if (0x00 < inputSize) {
        CHUNK_SIZE indexA = 0x00;
        CHUNK_SIZE indexB = 0x00;
        CHUNK_TYPE temp = 0x00;

        for (indexA = 0x01; indexA < inputSize; indexA++) {
            for (indexB = 0x00; indexB < inputSize - indexA; indexB++) {
                if (get_chunk(input, indexB) > get_chunk(input, indexB + 0x01)) {
                    temp = get_chunk(input, indexB);
                    set_chunk(input, indexB, get_chunk(input, indexB + 0x01));
                    set_chunk(input, indexB + 0x01, temp);
                }
            }
        }

        result = true;
    }

    return result;

}

CHUNK_TYPE __chartoint_input(CHUNK_TYPE input) {

    uint8_t result = CHUNK_ERROR;

    uint8_t index = 0x00;

    for (index = 0x00; index < 0x0A; index++) {
        if (pm_byte(NUMBER_SET, index) == input) {
            result = index;

            break;
        }
    }

    return result;

}

bool extractCheck_input(CHUNK input) {

    bool result = false;

    CHUNK_SIZE inputSize = sizeof_chunk(input);

    if (0x00 < inputSize) {
        result = (INPUT_CHECKCHAR == get_chunk(input, 0x00));
    }

    return result;

}

CHUNK extractInformation_input(CHUNK input) {

    CHUNK result = CHUNK_ERROR;

    CHUNK_SIZE inputSize = sizeof_chunk(input);

    if (0x00 < inputSize) {
        bool checkChar = false;
        CHUNK_SIZE count = 0x00;
        CHUNK_SIZE index = 0x00;

        for (index = 0x00; index < inputSize; index++) {
            if ((INPUT_LENGTHCHAR == get_chunk(input, index)) ||
                    (INPUT_SPECIALCHAR == get_chunk(input, index))) {
                break;
            }

            // INPUT_CHECKCHAR at first position is ignored
            if ((0x00 != index) || (INPUT_CHECKCHAR != get_chunk(input, index))) {
                count++;
            } else {
                checkChar = true;
            }
        }

        if (0x00 < count) {
            result = alloc_chunk(count);

            if (checkChar) {
                copyOffset_chunk(input, result, 0x01, 0x00);
            } else {
                copy_chunk(input, result);
            }
        }
    }

    // clean up memory
    zeroFreeMem_chunk();

    return result;

}

CHUNK_SIZE extractLength_input(CHUNK input) {

    CHUNK_SIZE result = INPUT_DEFAULTLENGTH;

    CHUNK_SIZE inputSize = sizeof_chunk(input);

    if (0x00 < inputSize) {
        CHUNK_SIZE count = 0x00;
        CHUNK_SIZE indexA = 0x00;
        CHUNK_SIZE indexB = 0x00;
        CHUNK_TYPE temp = 0x00;

        for (indexA = 0x00; indexA < inputSize; indexA++) {
            if (INPUT_SPECIALCHAR != get_chunk(input, indexA)) {
                if (INPUT_LENGTHCHAR == get_chunk(input, indexA)) {
                    result = 0x00; // set to non-default length

                    for (indexB = indexA + 0x01; indexB < inputSize; indexB++) {
                        if (INPUT_SPECIALCHAR == get_chunk(input, indexB)) {
                            break;
                        }

                        count++;
                    }

                    if (0x00 < count) {
                        for (indexB = 0x00; indexB < count; indexB++) {
                            temp = __chartoint_input(get_chunk(input, indexA + indexB + 0x01));
                            if (CHUNK_ERROR != temp) {
                                result *= 0x0A;
                                result += temp;
                            }
                        }
                    }

                    break;
                }
            } else {
                break;
            }
        }
    }

    // clean up memory
    zeroFreeMem_chunk();

    return result;

}

CHUNK extractSpecialChars_input(CHUNK input) {

    CHUNK result = CHUNK_ERROR;

    CHUNK_SIZE inputSize = sizeof_chunk(input);

    if (0x00 < inputSize) {
        CHUNK_SIZE count = 0x00;
        CHUNK_SIZE index = 0x00;

        for (index = 0x00; index < inputSize; index++) {
            if (INPUT_SPECIALCHAR == get_chunk(input, index)) {
                count = inputSize - index - 0x01;

                if (0x00 < count) {
                    result = alloc_chunk(count);
                    if (CHUNK_ERROR != result) {
                        copyOffsetLength_chunk(input, result, index + 0x01, 0x00, count);
                        __sort_input(result);
                    }

                    break;
                }
            }
        }
    }

    // clean up memory
    zeroFreeMem_chunk();

    return result;

}
