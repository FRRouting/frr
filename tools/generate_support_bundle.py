#!/usr/bin/env python3

########################################################
### Python Script to generate the FRR support bundle ###
########################################################
import os
import subprocess
import datetime

ETC_DIR = "/etc/frr/"
LOG_DIR = "/var/log/frr/"
SUCCESS = 1
FAIL = 0

inputFile = ETC_DIR + "support_bundle_commands.conf"

# Create the output file name
def createOutputFile(procName):
    fileName = procName + "_support_bundle.log"
    oldFile = LOG_DIR + fileName
    cpFileCmd = "cp " + oldFile + " " + oldFile + ".prev"
    rmFileCmd = "rm -rf " + oldFile
    print("Making backup of " + oldFile)
    os.system(cpFileCmd)
    print("Removing " + oldFile)
    os.system(rmFileCmd)
    return fileName


# Open the output file for this process
def openOutputFile(fileName):
    crt_file_cmd = LOG_DIR + fileName
    print(crt_file_cmd)
    try:
        outputFile = open(crt_file_cmd, "w")
        return outputFile
    except IOError:
        return ()


# Close the output file for this process
def closeOutputFile(f):
    try:
        f.close()
        return SUCCESS
    except IOError:
        return FAIL


# Execute the command over vtysh and store in the
# output file
def executeCommand(cmd, outputFile):
    cmd_exec_str = 'vtysh -c "' + cmd + '" '
    try:
        cmd_output = subprocess.check_output(
                cmd_exec_str.encode(encoding="utf-8"),
                shell=True
        )
        try:
            dateTime = datetime.datetime.now()
            outputFile.write(">>[" + str(dateTime) + "]" + cmd + "\n")
            outputFile.write(str(cmd_output))
            outputFile.write(
                "########################################################\n"
            )
            outputFile.write("\n")
        except Exception as e:
            print("Writing to output file Failed: ", e)
    except subprocess.CalledProcessError as e:
        dateTime = datetime.datetime.now()
        outputFile.write(">>[" + str(dateTime) + "]" + cmd + "\n")
        outputFile.write(e.output)
        outputFile.write("########################################################\n")
        outputFile.write("\n")
        print("Error:" + e.output)


# Process the support bundle configuration file
# and call appropriate functions
def processConfFile():

    lines = list()
    outputFile = None

    try:
        with open(inputFile, "r") as supportBundleConfFile:
            for l in supportBundleConfFile:
                lines.append(l.rstrip())
    except IOError:
        print("conf file {} not present".format(inputFile))
        return

    for line in lines:
        if len(line) == 0 or line[0] == "#":
            continue

        cmd_line = line.split(":")
        if cmd_line[0] == "PROC_NAME":
            outputFileName = createOutputFile(cmd_line[1])
            if outputFileName:
                print(outputFileName, "created for", cmd_line[1])
        elif cmd_line[0] == "CMD_LIST_START":
            outputFile = openOutputFile(outputFileName)
            if outputFile:
                print(outputFileName, "opened")
            else:
                print(outputFileName, "open failed")
                return FAIL
        elif cmd_line[0] == "CMD_LIST_END":
            if closeOutputFile(outputFile):
                print(outputFileName, "closed")
            else:
                print(outputFileName, "close failed")
        else:
            print("Execute:", cmd_line[0])
            executeCommand(cmd_line[0], outputFile)


# Main Function
processConfFile()
