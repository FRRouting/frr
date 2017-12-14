#!/bin/bash
# Check a patch for style errors.
# Usage:
#	./checkpatch.sh <patch>
checkpatch="./checkpatch.pl --no-tree -f"
ignore="ldpd\|babeld"
cwd=${PWD##*/}
dirty=0

# check running from frr/tools/
if [[ $cwd != *"tools"* ]]; then
  echo "[!] script must be run from tools/ directory"
  exit 1
fi

# save working tree
cd ..
if git status --porcelain | egrep --silent '^(\?\?|.[DM])'; then
  echo "Detected dirty tree, caching state..."
  dirty=1
  git config gc.auto 0;
  td=$(git status -z | grep -z "^[ARM]D" | cut -z -d' ' -f2- | tr '\0' '\n')
  INDEX=`git write-tree`
  git add -f .
  WORKTREE=`git write-tree`
  echo "Saved index to $INDEX"
  echo "Saved working tree to $WORKTREE"
fi

# double check
if git status --porcelain | egrep --silent '^(\?\?|.[DM])'; then
  echo "[!] git working directory must be clean."
  exit 1
fi

git reset --hard
git apply $1 2> /dev/null
cd tools
mkdir -p f1 f2
mod=$(git ls-files -m .. | grep ".*\.[ch]" | grep -v $ignore)
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
  if [ -a f2/$(basename $file) ]; then
    diff $file f2/$(basename $file) | grep -A3 "ERROR\|WARNING"
  else
    cat $file
  fi
done
rm -rf f1 f2
cd ..

# restore working tree
if [ $dirty -eq 1 ]; then
  git read-tree $WORKTREE;
  git checkout-index -af;
  git read-tree $INDEX;
  if [ -n "$td" ]; then
    rm $td
  fi
  git config --unset gc.auto;
fi
