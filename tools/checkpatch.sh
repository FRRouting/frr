#!/bin/bash
# Check a patch for style errors.
# Usage:
#	./checkpatch.sh <patch>
checkpatch="./checkpatch.pl --no-tree -f"

git status | grep "working directory clean"
if [ $? -ne 0 ]; then
	echo "[!] git working directory must be clean."
	exit 1
fi

mkdir -p f1 f2
bash -c "cd .. && git apply $1 2> /dev/null"
mod=$(git ls-files -m .. | grep ".*\.[ch]")
cp $mod f1/
git reset --hard
cp $mod f2/
for file in f1/*; do
  $checkpatch $file > "$file"_cp 2> /dev/null
done
for file in f2/*; do
  $checkpatch $file > "$file"_cp 2> /dev/null
done
for file in f1/*_cp; do
  diff $file f2/$(basename $file) | grep -A3 "ERROR\|WARNING"
done
rm -rf f1 f2
