/*  
 *  This file is free software: you may copy, redistribute and/or modify it  
 *  under the terms of the GNU General Public License as published by the  
 *  Free Software Foundation, either version 2 of the License, or (at your  
 *  option) any later version.  
 *  
 *  This file is distributed in the hope that it will be useful, but  
 *  WITHOUT ANY WARRANTY; without even the implied warranty of  
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU  
 *  General Public License for more details.  
 *  
 *  You should have received a copy of the GNU General Public License  
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.  
 *  
 * This file incorporates work covered by the following copyright and  
 * permission notice:  
 *  

Copyright 2007, 2008 by Grégoire Henry, Julien Cristau and Juliusz Chroboczek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <sys/time.h>
#include <sys/param.h>
#include <time.h>

#include "babeld.h"

#include "kernel_zebra.c"

/* Like gettimeofday, but returns monotonic time.  If POSIX clocks are not
   available, falls back to gettimeofday but enforces monotonicity. */
int
gettime(struct timeval *tv)
{
    int rc;
    static time_t offset = 0, previous = 0;

#if defined(_POSIX_TIMERS) && _POSIX_TIMERS > 0 && defined(CLOCK_MONOTONIC)
    static int have_posix_clocks = -1;

    if(UNLIKELY(have_posix_clocks < 0)) {
        struct timespec ts;
        rc = clock_gettime(CLOCK_MONOTONIC, &ts);
        if(rc < 0) {
            have_posix_clocks = 0;
        } else {
            have_posix_clocks = 1;
        }
    }

    if(have_posix_clocks) {
        struct timespec ts;
        int rc;
        rc = clock_gettime(CLOCK_MONOTONIC, &ts);
        if(rc < 0)
            return rc;
        tv->tv_sec = ts.tv_sec;
        tv->tv_usec = ts.tv_nsec / 1000;
        return rc;
    }
#endif

    rc = gettimeofday(tv, NULL);
    if(rc < 0)
        return rc;
    tv->tv_sec += offset;
    if(UNLIKELY(previous > tv->tv_sec)) {
        offset += previous - tv->tv_sec;
        tv->tv_sec = previous;
    }
    previous = tv->tv_sec;
    return rc;
}

/* If /dev/urandom doesn't exist, this will fail with ENOENT, which the
   caller will deal with gracefully. */

int
read_random_bytes(void *buf, size_t len)
{
    int fd;
    int rc;

    fd = open("/dev/urandom", O_RDONLY);
    if(fd < 0) {
        rc = -1;
    } else {
        rc = read(fd, buf, len);
        if(rc < 0 || (unsigned) rc < len)
            rc = -1;
        close(fd);
    }
    return rc;
}

