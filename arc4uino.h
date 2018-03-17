/*
 * File:    arc4uino.h
 * Author:  Yahe <hello@yahe.sh>
 * Version: 0.4.0
 *
 * Created on 14. April 2013
 *
 * Release 0.2.0 on 26. April 2013
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
 * arc4uino.h contains an implementation of the Arc4 encryption algorithm.
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

#ifndef __ARC4UINO_H__
#define	__ARC4UINO_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include "chunkuino.h"

#define ARC4_BUFFERSIZE   0x0100
#define ARC4_DROPPEDBYTES 0x0400

    CHUNK_TYPE __readBuffer_arc4(CHUNK bufferA, CHUNK bufferB, MEM_SIZE index);
    bool __writeBuffer_arc4(CHUNK bufferA, CHUNK bufferB, MEM_SIZE index, CHUNK_TYPE value);
    CHUNK __arc4(CHUNK input, CHUNK password);

    CHUNK encrypt_arc4(CHUNK input, CHUNK password);
    CHUNK decrypt_arc4(CHUNK input, CHUNK password);

#ifdef	__cplusplus
}
#endif

#endif	/* __ARC4UINO_H__ */
