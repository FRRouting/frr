/*
 * Library-specific error messages.
 * Copyright (C) 2018  Cumulus Networks, Inc.
 *                     Donald Sharp
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

#include "lib_errors.h"

DEFINE_LOGCAT(LIB_ERR_PRIVILEGES, ROOT, "Failure to raise or lower privileges",
	.description = "FRR attempted to raise or lower its privileges and was unable to do so",
	.suggestion = "Ensure that you are running FRR as the frr user and that the user has sufficient privileges to properly access root privileges",
)
DEFINE_LOGCAT(LIB_ERR_VRF_START, ROOT, "VRF Failure on Start",
	.description = "Upon startup FRR failed to properly initialize and startup the VRF subsystem",
	.suggestion = "Ensure that there is sufficient memory to start processes and restart FRR",
)
DEFINE_LOGCAT(LIB_ERR_SOCKET, ROOT, "Socket Error",
	.description = "When attempting to access a socket a system error has occured and we were unable to properly complete the request",
	.suggestion = "Ensure that there are sufficient system resources available and ensure that the frr user has sufficient permisions to work",
)
DEFINE_LOGCAT(LIB_ERR_ZAPI_MISSMATCH, ROOT, "ZAPI Error",
	.description = "A version miss-match has been detected between zebra and client protocol",
	.suggestion = "Two different versions of FRR have been installed and the install is not properly setup.  Completely stop FRR, remove it from the system and reinstall.  Typically only developers should see this issue.",
)
DEFINE_LOGCAT(LIB_ERR_ZAPI_ENCODE, ROOT, "ZAPI Error",
	.description = "The ZAPI subsystem has detected an encoding issue, between zebra and a client protocol",
	.suggestion = "Restart FRR",
)
DEFINE_LOGCAT(LIB_ERR_ZAPI_SOCKET, ROOT, "ZAPI Error",
	.description = "The ZAPI subsystem has detected a socket error between zebra and a client",
	.suggestion = "Restart FRR",
)
DEFINE_LOGCAT(LIB_ERR_SYSTEM_CALL, ROOT, "System Call Error",
	.description = "FRR has detected a error from using a vital system call and has probably already exited",
	.suggestion = "Ensure permissions are correct for FRR files, users and groups are correct. Additionally check that sufficient system resources are available.",
)
DEFINE_LOGCAT(LIB_ERR_VTY, ROOT, "VTY Subsystem Error",
	.description = "FRR has detected a problem with the specified configuration file",
	.suggestion = "Ensure configuration file exists and has correct permissions for operations Additionally ensure that all config lines are correct as well",
)
DEFINE_LOGCAT(LIB_ERR_SNMP, ROOT, "SNMP Subsystem Error",
	.description = "FRR has detected a problem with the snmp library it uses A callback from this subsystem has indicated some error",
	.suggestion = "Examine callback message and ensure snmp is properly setup and working",
)
DEFINE_LOGCAT(LIB_ERR_INTERFACE, ROOT, "Interface Subsystem Error",
	.description = "FRR has detected a problem with interface data from the kernel as it deviates from what we would expect to happen via normal netlink messaging",
	.suggestion = "Open an Issue with all relevant log files and restart FRR",
)
DEFINE_LOGCAT(LIB_ERR_NS, ROOT, "NameSpace Subsystem Error",
	.description = "FRR has detected a problem with NameSpace data from the kernel as it deviates from what we would expect to happen via normal kernel messaging",
	.suggestion = "Open an Issue with all relevant log files and restart FRR",
)
DEFINE_LOGCAT(LIB_ERR_DEVELOPMENT, ROOT, "Developmental Escape Error",
	.description = "FRR has detected an issue where new development has not properly updated all code paths.",
	.suggestion = "Open an Issue with all relevant log files",
)
DEFINE_LOGCAT(LIB_ERR_ZMQ, ROOT, "ZMQ Subsystem Error",
	.description = "FRR has detected an issue with the Zero MQ subsystem and ZeroMQ is not working properly now",
	.suggestion = "Open an Issue with all relevant log files and restart FRR",
)
DEFINE_LOGCAT(LIB_ERR_UNAVAILABLE, ROOT, "Feature or system unavailable",
	.description = "FRR was not compiled with support for a particular feature, or it is not available on the current platform",
	.suggestion = "Recompile FRR with the feature enabled, or find out what platforms support the feature",
)
