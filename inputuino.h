/*
 * File:    inputuino.h
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
 * inputuino.h contains an implementation of the input handling of calc.pw.
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

#ifndef __INPUTUINO_H__
#define	__INPUTUINO_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include "chunkuino.h"
#include "progmemuino.h"

#define INPUT_DEFAULTLENGTH 0x08
#define INPUT_CHECKCHAR     '#'
#define INPUT_LENGTHCHAR    '?'
#define INPUT_SPECIALCHAR   '!'

    bool __sort_input(CHUNK input);
    CHUNK_TYPE __chartoint_input(CHUNK_TYPE input);

    bool extractCheck_input(CHUNK input);
    CHUNK extractInformation_input(CHUNK input);
    CHUNK_SIZE extractLength_input(CHUNK input);
    CHUNK extractSpecialChars_input(CHUNK input);

#ifdef	__cplusplus
}
#endif

#endif	/* __INPUTUINO_H__ */
