#!/usr/bin/python

########################################################
### Python Script to generate the FRR support bundle ###
########################################################
import os
import subprocess
import datetime

TOOLS_DIR="tools/"
ETC_DIR="/etc/frr/"
LOG_DIR="/var/log/frr/"
SUCCESS = 1
FAIL = 0

inputFile = ETC_DIR + "support_bundle_commands.conf"

# Open support bundle configuration file
def openConfFile(i_file):
  try:
    with open(i_file) as supportBundleConfFile:
      lines = filter(None, (line.rstrip() for line in supportBundleConfFile))
    return lines
  except IOError:
    return ([])

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
def closeOutputFile(file):
  try:
    file.close()
    return SUCCESS
  except IOError:
    return FAIL

# Execute the command over vtysh and store in the
# output file
def executeCommand(cmd, outputFile):
  cmd_exec_str = "vtysh -c \"" + cmd + "\" "
  try:
    cmd_output = subprocess.check_output(cmd_exec_str, shell=True)
    try:
      dateTime = datetime.datetime.now()
      outputFile.write(">>[" + str(dateTime) + "]" + cmd + "\n")
      outputFile.write(cmd_output)
      outputFile.write("########################################################\n")
      outputFile.write('\n')
    except:
      print("Writing to ouptut file Failed")
  except subprocess.CalledProcessError as e:
    dateTime = datetime.datetime.now()
    outputFile.write(">>[" + str(dateTime) + "]" + cmd + "\n")
    outputFile.write(e.output)
    outputFile.write("########################################################\n")
    outputFile.write('\n')
    print("Error:" + e.output)


# Process the support bundle configuration file
# and call appropriate functions
def processConfFile(lines):
  for line in lines:
    if line[0][0] == '#':
      continue
    cmd_line = line.split(':')
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
      print("Execute:" , cmd_line[0])
      executeCommand(cmd_line[0], outputFile)
      
# Main Function
lines = openConfFile(inputFile)
if not lines:
  print("File support_bundle_commands.conf not present in /etc/frr/ directory")
else:
  processConfFile(lines)
