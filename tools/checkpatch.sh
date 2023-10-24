#!/bin/bash
# Check a patch for style errors.
usage="./checkpatch.sh <patch> <tree>"
patch=$1
tree=$2
scriptdir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)"
checkpatch="$scriptdir/checkpatch.pl --no-tree -f"
ignore="ldpd\|babeld"
cwd=${PWD##*/}
dirty=0
stat=0
tmp1=/tmp/f1-$$
tmp2=/tmp/f2-$$

if [[ -z "$1" || -z "$2" ]]; then
  echo "$usage"
  exit 0
fi

# remove temp directories
rm -rf ${tmp1} ${tmp2}

# save working tree
if git -C $tree status --porcelain | egrep --silent '^(\?\?|.[DM])'; then
  echo "Detected dirty tree, caching state..."
  dirty=1
  git -C $tree config gc.auto 0;
  td=$(git -C $tree status -z | grep -z "^[ARM]D" | cut -z -d' ' -f2- | tr '\0' '\n')
  INDEX=$(git -C $tree write-tree)
  git -C $tree add -f .
  WORKTREE=$(git -C $tree write-tree)
  echo "Saved index to $INDEX"
  echo "Saved working tree to $WORKTREE"
fi

# double check
if git -C $tree status --porcelain | egrep --silent '^(\?\?|.[DM])'; then
  echo "[!] git working directory must be clean."
  exit 1
fi

git -C $tree reset --hard
git -C $tree apply < $patch
mkdir -p ${tmp1} ${tmp2}
mod=$(git -C $tree ls-files -m | grep ".*\.[ch]" | grep -v $ignore)
mod+=" $(git -C $tree ls-files --others --exclude-standard | grep '.*\.[ch]' | grep -v $ignore)"
echo $mod
if [ -z "$mod" ]; then
  echo "There doesn't seem to be any changes."
else
  echo "Copying source to temp directory..."
  for file in $mod; do
    echo "$tree/$file --> ${tmp1}/$file"
    cp $tree/$file ${tmp1}/
  done
  git -C $tree reset --hard
  git -C $tree clean -fd
  for file in $mod; do
    if [ -f $tree/$file ]; then
      echo "$tree/$file --> ${tmp2}/$file"
      cp $tree/$file ${tmp2}/
    fi
  done
  echo "Running style checks..."
  for file in ${tmp1}/*; do
    echo "$checkpatch $file > $file _cp"
    $checkpatch $file > "$file"_cp 2> /dev/null
  done
  for file in ${tmp2}/*; do
    echo "$checkpatch $file > $file _cp"
    $checkpatch $file > "$file"_cp 2> /dev/null
  done
  echo "Done."
  for file in ${tmp1}/*_cp; do
    if [ -a ${tmp2}/$(basename $file) ]; then
      result=$(diff $file ${tmp2}/$(basename $file) | awk '/< ERROR|< WARNING/,/^< $|^< #|^<[^ ]/ { print $0; ++n }; END { exit n }')
    else
      result=$(cat $file | awk '/ERROR|WARNING/,/^$/ { print $0; ++n }; END { exit n }')
    fi
    ni="$?"
    if [ "$ni" -ne "0" ]; then
      echo "Report for $(basename $file _cp) | $ni issues" 1>&2
      echo "===============================================" 1>&2
      echo "$result" 1>&2
      if echo $result | grep -q "ERROR"; then
        stat=2
      elif [ "$stat" -eq "0" ]; then
        stat=1
      fi
    fi
  done
fi

# restore working tree
if [ $dirty -eq 1 ]; then
  git -C $tree read-tree $WORKTREE;
  git -C $tree checkout-index -af;
  git -C $tree read-tree $INDEX;
  if [ -n "$td" ]; then
    rm $td
  fi
  git -C $tree config --unset gc.auto;
fi

# remove temp directories
rm -rf ${tmp1} ${tmp2}

exit $stat
