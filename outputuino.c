/*
 * File:    outputuino.c
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
 * outputuino.c contains an implementation of the password generation of calc.pw.
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

#include "outputuino.h"

bool __check_output(CHUNK input) {

    bool result = false;

    CHUNK_SIZE inputSize = sizeof_chunk(input);
    if (0x00 < inputSize) {
        bool charFound = false;
        CHUNK_SIZE index = 0x00;
        bool numFound = false;
        CHUNK_TYPE tempChar = 0x00;
        CHUNK_TYPE tempValA = 0x00;
        CHUNK_TYPE tempValB = 0x00;

        for (index = 0x00; index < inputSize; index++) {
            tempChar = get_chunk(input, index);
            tempValA = __chartoint_input(tempChar);
            if (CHUNK_ERROR != tempValA) {
                numFound = true;
            } else {
                tempValB = __value_base64(tempChar);
                if ((BASE64_PADDING != tempChar) ||
                        (OUTPUT_CHARNUMCOUNT > tempValB)) {
                    charFound = true;
                }
            }

            if (charFound && numFound) {
                break;
            }
        }

        result = (charFound && numFound);
    }

    return result;

}

bool __killSpecialChars_output(CHUNK input) {

    bool result = false;

    CHUNK_SIZE inputSize = sizeof_chunk(input);
    if (0x00 < inputSize) {
        CHUNK_SIZE count = 0x00;
        CHUNK_SIZE indexA = 0x00;
        CHUNK_SIZE indexB = 0x00;
        CHUNK_TYPE tempChar = 0x00;
        CHUNK_TYPE tempVal = 0x00;

        for (indexA = inputSize; indexA > 0x00; indexA--) {
            tempChar = get_chunk(input, indexA - 0x01);
            tempVal = __value_base64(tempChar);
            if ((BASE64_PADDING == tempChar) ||
                    (OUTPUT_CHARNUMCOUNT <= tempVal)) {
                for (indexB = indexA - 0x01; indexB < inputSize - count - 0x01; indexB++) {
                    set_chunk(input, indexB, get_chunk(input, indexB + 0x01));
                }

                count++;
            }
        }

        if (0x00 < count) {
            resize_chunk(input, inputSize - count);
        }

        result = true;
    }

    return result;

}

CHUNK __single_output(CHUNK information, CHUNK_SIZE length,
        CHUNK specialChars, CHUNK password) {

    CHUNK result = CHUNK_ERROR;

    CHUNK_SIZE informationSize = sizeof_chunk(information);
    CHUNK_SIZE passwordSize = sizeof_chunk(password);

    if ((0x00 < informationSize) && (0x00 < passwordSize) &&
            (OUTPUT_MINSIZE <= length) && (OUTPUT_MAXSIZE >= length)) {
        CHUNK_SIZE done = 0x00;
        CHUNK hmacInformation = CHUNK_ERROR;
        CHUNK hmacPassword = CHUNK_ERROR;
        CHUNK_SIZE index = 0x00;
        CHUNK_TYPE specialCharIndex = 0x00;
        CHUNK_TYPE specialCharPos = 0x00;
        CHUNK tempInput = CHUNK_ERROR;
        CHUNK tempOutput = CHUNK_ERROR;

        // create session password for Arc4
        hmacPassword = hmac_sha1(information, password);
        if (CHUNK_ERROR != hmacPassword) {
            // create information stream of 60 characters
            hmacInformation = alloc_chunk(OUTPUT_HASHSIZE);
            if (CHUNK_ERROR != hmacInformation) {
                // initialize done as zero
                done = 0x00;

                // initialize tempInput as the hash of the hmacPassword
                tempInput = hash_sha1(hmacPassword);
                if (CHUNK_ERROR != tempInput) {
                    // expand the tempInput to hmacInformation
                    for (index = 0x00; index < OUTPUT_HASHCOUNT; index++) {
                        // create parts of hmacInformation by creating the
                        // HMAC of the tempInput and the information
                        tempOutput = hmac_sha1(tempInput, information);
                        if (CHUNK_ERROR != tempOutput) {
                            // copy tempOutput to part of hmacInformation
                            copyOffsetLength_chunk(tempOutput, hmacInformation,
                                    0x00, SHA1_OUTPUTSIZE * index, SHA1_OUTPUTSIZE);

                            // set tempInput to last tempOutput
                            dealloc_chunk(tempInput);
                            tempInput = tempOutput;
                            tempOutput = CHUNK_ERROR;

                            // increment done counter
                            done++;
                        }
                    }

                    dealloc_chunk(tempInput);
                }

                // proceed if we generated 3 hmacInformation parts
                if (OUTPUT_HASHCOUNT == done) {
                    // encrypt everything
                    tempOutput = encrypt_arc4(hmacInformation, hmacPassword);
                    if (CHUNK_ERROR != tempOutput) {
                        // encode to Base64 for readability
                        result = encode_base64(tempOutput);
                        if (CHUNK_ERROR != result) {
                            // normalize output
                            __killSpecialChars_output(result);
                            resize_chunk(result, length);

                            // handle special characters
                            // XORing first half of hmacPassword gets us
                            // the index of the special character
                            // XORing second half of hmacPassword gets us
                            // the final position of the special character
                            if (CHUNK_ERROR != specialChars) {
                                specialCharIndex = 0x00;
                                specialCharPos = 0x00;
                                for (index = 0x00; index < SHA1_OUTPUTSIZE; index++) {
                                    if (index < (SHA1_OUTPUTSIZE / 0x02)) {
                                        specialCharIndex ^= get_chunk(hmacPassword, index);
                                    } else {
                                        specialCharPos ^= get_chunk(hmacPassword, index);
                                    }
                                }
                                specialCharIndex = (specialCharIndex % sizeof_chunk(specialChars));
                                specialCharPos = (specialCharPos % (sizeof_chunk(result) - 0x02)) + 0x01;
                                set_chunk(result, specialCharPos, get_chunk(specialChars, specialCharIndex));
                            }
                        }

                        dealloc_chunk(tempOutput);
                    }
                }

                dealloc_chunk(hmacInformation);
            }

            dealloc_chunk(hmacPassword);
        }
    }

    // clean up memory
    zeroFreeMem_chunk();

    return result;

}

CHUNK generate_output(CHUNK input, CHUNK password) {

    CHUNK result = CHUNK_ERROR;

    CHUNK_SIZE inputSize = sizeof_chunk(input);
    CHUNK_SIZE passwordSize = sizeof_chunk(password);

    if ((0x00 < inputSize) && (0x00 < passwordSize)) {
        bool checkOutput = false;
        CHUNK_TYPE count = 0x00;
        bool done = false;
        CHUNK information = CHUNK_ERROR;
        CHUNK_SIZE length = 0x00;
        CHUNK specialChars = CHUNK_ERROR;
        CHUNK tempInput = CHUNK_ERROR;
        CHUNK tempOutput = CHUNK_ERROR;

        information = extractInformation_input(input);
        if (CHUNK_ERROR != information) {
            specialChars = extractSpecialChars_input(input);
            length = extractLength_input(input);
            if ((OUTPUT_MINSIZE <= length) && (OUTPUT_MAXSIZE >= length)) {
                checkOutput = extractCheck_input(input);

                // INPUT_CHECKCHAR encountered:
                // check that output contains at
                // least one character and one number
                if (checkOutput) {
                    // temporary input with spare round field
                    tempInput = alloc_chunk(sizeof_chunk(information) + 0x01);
                    if (CHUNK_ERROR != tempInput) {
                        copyOffsetLength_chunk(information, tempInput, 0x00, 0x01, sizeof_chunk(information));

                        count = 0x00;
                        do {
                            // set round field
                            set_chunk(tempInput, 0x00, count);

                            // generate output
                            tempOutput = __single_output(tempInput, length, specialChars, password);
                            if (CHUNK_ERROR != tempOutput) {
                                // check output for good structure
                                done = __check_output(tempOutput);
                                if (done) {
                                    result = tempOutput;
                                } else {
                                    dealloc_chunk(tempOutput);
                                    tempOutput = CHUNK_ERROR;
                                    count++;
                                }
                            } else {
                                break;
                            }
                        } while ((!done) && (count < 0xFF));

                        dealloc_chunk(tempInput);
                    }
                } else {
                    result = __single_output(information, length, specialChars, password);
                }
            }

            dealloc_chunk(specialChars);
            dealloc_chunk(information);
        }
    }

    // clean up memory
    zeroFreeMem_chunk();

    return result;

}
