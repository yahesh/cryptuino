/*
 * File:    base64uino.h
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
 * base64uino.h contains an implementation of the Base64 encoding algorithm.
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

#ifndef __BASE64UINO_H__
#define	__BASE64UINO_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include "chunkuino.h"
#include "progmemuino.h"

#define BASE64_CHAR_COUNT   0x40
#define BASE64_PADDING      '='
#define BASE64_RATIO_AFTER  0x04
#define BASE64_RATIO_BEFORE 0x03

    CHUNK_TYPE __value_base64(CHUNK_TYPE input);

    CHUNK encode_base64(CHUNK input);
    CHUNK decode_base64(CHUNK input);

#ifdef	__cplusplus
}
#endif

#endif	/* __BASE64UINO_H__ */
