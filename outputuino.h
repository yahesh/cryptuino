/*
 * File:    outputuino.h
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
 * outputuino.h contains an implementation of the password generation of calc.pw.
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

#ifndef __OUTPUTUINO_H__
#define	__OUTPUTUINO_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include "arc4uino.h"
#include "base64uino.h"
#include "inputuino.h"
#include "sha1uino.h"

#define OUTPUT_CHARNUMCOUNT 0x3E
#define OUTPUT_HASHCOUNT    0x03
#define OUTPUT_HASHSIZE     (SHA1_OUTPUTSIZE*OUTPUT_HASHCOUNT)
#define OUTPUT_MAXSIZE      0x32
#define OUTPUT_MINSIZE      0x03

    bool __check_output(CHUNK input);
    bool __killSpecialChars_output(CHUNK input);
    CHUNK __single_output(CHUNK information, CHUNK_SIZE length, CHUNK specialChars, CHUNK password);

    CHUNK generate_output(CHUNK input, CHUNK password);

#ifdef	__cplusplus
}
#endif

#endif	/* __OUTPUTUINO_H__ */
