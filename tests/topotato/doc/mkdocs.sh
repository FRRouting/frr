#!/bin/sh

: "${PYTHON:=python3}"

cd "`dirname $0`"
"${PYTHON}" -m sphinx -a -q -b text -d "_build/.doctrees" "." "_build/text"
"${PYTHON}" -m sphinx -q -b html -d "_build/.doctrees" "." "_build/html"
