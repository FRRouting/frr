/*
 * pathd-specific error messages.
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Sebastien Merle
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "lib/ferr.h"
#include "path_errors.h"

/* clang-format off */
static struct log_ref ferr_path_err[] = {
        {
                .code = EC_PATH_SYSTEM_CALL,
                .title = "Thread setup error",
                .description = "A system call for creating, or setting up pcep module's pthread failed",
                .suggestion = "Open an Issue with all relevant log files and restart FRR"
        },
        {
                .code = EC_PATH_PCEP_PCC_INIT,
                .title = "PCC initialization error",
                .description = "pceplib PCC initialization call failed",
                .suggestion = "Open an Issue with all relevant log files and restart FRR"
        },
        {
                .code = EC_PATH_PCEP_PCC_FINI,
                .title = "PCC finalization error",
                .description = "pceplib PCC finalization call failed",
                .suggestion = "Open an Issue with all relevant log files and restart FRR"
        },
        {
                .code = EC_PATH_PCEP_PCC_CONF_UPDATE,
                .title = "PCC configuration update error",
                .description = "The update of the PCC configuration failed",
                .suggestion = "Open an Issue with all relevant log files and restart FRR"
        },
        {
                .code = END_FERR,
        }
};

static struct log_ref ferr_path_warn[] = {
        {
                .code = EC_PATH_PCEP_LIB_CONNECT,
                .title = "PCC connection error",
                .description = "The PCEP module failed to connected to configured PCE",
                .suggestion = "Check the connectivity between the PCC and the PCE"
        },
        {
                .code = EC_PATH_PCEP_RECOVERABLE_INTERNAL_ERROR,
                .title = "Recoverable internal error",
                .description = "Some recoverable internal error",
                .suggestion = "Open an Issue with all relevant log files"
        },
        {
                .code = EC_PATH_PCEP_UNEXPECTED_PCEP_MESSAGE,
                .title = "Unexpected pcep message",
                .description = "The PCEP module received an unexpected pcep message",
                .suggestion = "Open an Issue with all relevant log files"
        },
        {
                .code = EC_PATH_PCEP_UNEXPECTED_PCEPLIB_EVENT,
                .title = "Unexpected pceplib event",
                .description = "The PCEP module received an unexpected event from pceplib",
                .suggestion = "Open an Issue with all relevant log files"
        },
        {
                .code = EC_PATH_PCEP_UNEXPECTED_PCEP_OBJECT,
                .title = "Unexpected PCEP object",
                .description = "The PCEP module received an unexpected PCEP object from a PCE",
                .suggestion = "Open an Issue with all relevant log files"
        },
        {
                .code = EC_PATH_PCEP_UNEXPECTED_PCEP_TLV,
                .title = "Unexpected PCEP TLV",
                .description = "The PCEP module received an unexpected PCEP TLV from a PCE",
                .suggestion = "Open an Issue with all relevant log files"
        },
        {
                .code = EC_PATH_PCEP_UNEXPECTED_PCEP_ERO_SUBOBJ,
                .title = "Unexpected PCEP ERO sub-object",
                .description = "The PCEP module received an unexpected PCEP ERO sub-object from a PCE",
                .suggestion = "Open an Issue with all relevant log files"
        },
        {
                .code = END_FERR,
        }
};
/* clang-format on */

void path_error_init(void)
{
        log_ref_add(ferr_path_err);
        log_ref_add(ferr_path_warn);
}
