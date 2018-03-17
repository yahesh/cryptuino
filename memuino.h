/*
 * File:    memuino.h
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
 * memuino.h contains an implementation of a simple memory manager.
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

#ifndef __MEMUINO_H__
#define	__MEMUINO_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#define MEM         uint16_t
#define MEM_SIZE    uint16_t
#define MEM_TYPE    uint8_t
#define __MEM       MEM_TYPE*

#define MAX_MEM    max_mem()
#define MIN_MEM    min_mem()
#define SIZEOF_MEM sizeof_mem()

    MEM_SIZE init_mem(MEM_SIZE size);
    bool deinit_mem();
    bool is_init_mem();

    MEM_SIZE max_mem();
    MEM_SIZE min_mem();
    MEM_SIZE sizeof_mem();

    MEM_TYPE get_mem(MEM position);
    bool set_mem(MEM position, MEM_TYPE value);
    bool copy_mem(MEM source, MEM destination, MEM_SIZE count);
    bool copy_mem_rev(MEM source, MEM destination, MEM_SIZE count);

#ifdef	__cplusplus
}
#endif

#endif	/* __MEMUINO_H__ */
