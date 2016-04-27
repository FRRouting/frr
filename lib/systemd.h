/* lib/systemd Code
   Copyright (C) 2016 Cumulus Networks, Inc.
   Donald Sharp

This file is part of Quagga.

Quagga is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

Quagga is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with Quagga; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

/*
 * Wrapper functions to systemd calls.
 *
 * Design point is that if systemd is not being used on this system
 * then these functions becomes a no-op.
 *
 * To turn on systemd compilation, use --enable-systemd on
 * configure run.
 */
void systemd_send_information (const char *info);
void systemd_send_stopping (void);

/*
 *  master - The struct thread_master * to use to schedule ourself
 *  the_process - Should we send watchdog if we are not the requested
 *                process?
 */
void systemd_send_started (struct thread_master *master, int the_process);

