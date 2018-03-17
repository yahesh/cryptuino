/*
 * File:    memuino.c
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
 * memuino.c contains an implementation of a simple memory manager.
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

#include "memuino.h"

__MEM __mem_buffer = NULL;

MEM_SIZE __mem_max = 0x0000;
MEM_SIZE __mem_min = 0x0000;
MEM_SIZE __mem_size = 0x0000;

MEM_SIZE init_mem(MEM_SIZE size) {

    MEM_SIZE result = 0x0000;

    if ((!is_init_mem()) && (0x0000 < size)) {
        __mem_max = size - 0x0001;
        __mem_min = 0x0000;
        __mem_size = size;

        __mem_buffer = (__MEM) malloc(sizeof (MEM_TYPE) * SIZEOF_MEM);

        if (is_init_mem()) {
            result = SIZEOF_MEM;
        }
    }

    return result;

}

bool deinit_mem() {

    bool result = false;

    if (is_init_mem()) {
        free(__mem_buffer);
        __mem_buffer = NULL;

        __mem_max = 0x0000;
        __mem_min = 0x0000;
        __mem_size = 0x0000;

        result = true;
    }

    return result;

}

bool is_init_mem() {

    return ((0x0000 < SIZEOF_MEM) && (NULL != __mem_buffer));

}

MEM_SIZE max_mem() {

    return __mem_max;

}

MEM_SIZE min_mem() {

    return __mem_min;

}

MEM_SIZE sizeof_mem() {

    return __mem_size;

}

MEM_TYPE get_mem(MEM position) {

    MEM_TYPE result = 0x00;

    if ((is_init_mem()) && (position < SIZEOF_MEM)) {
        result = __mem_buffer[position];
    }

    return result;

}

bool set_mem(MEM position, MEM_TYPE value) {

    bool result = false;

    if ((is_init_mem()) && (position < SIZEOF_MEM)) {
        __mem_buffer[position] = value;

        result = true;
    }

    return result;

}

bool copy_mem(MEM source, MEM destination, MEM_SIZE count) {

    bool result = false;

    if ((is_init_mem()) && ((source + count) < SIZEOF_MEM) && ((destination + count) < SIZEOF_MEM)) {
        MEM index = 0x0000;

        for (index = 0x0000; index < count; index++) {
            __mem_buffer[destination + index] = __mem_buffer[source + index];
        }

        result = true;
    }

    return result;

}

bool copy_mem_rev(MEM source, MEM destination, MEM_SIZE count) {

    bool result = false;

    if ((is_init_mem()) && ((source + count) < SIZEOF_MEM) && ((destination + count) < SIZEOF_MEM)) {
        MEM index = 0x0000;

        for (index = count; index > 0x0000; index--) {
            __mem_buffer[destination + index - 0x0001] = __mem_buffer[source + index - 0x0001];
        }

        result = true;
    }

    return result;

}
