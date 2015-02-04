#! /bin/bash
#
# Github Developer Git Checkout
#
# Delete remote branch qpimd:    git push origin :qpimd
#                                (git push origin :refs/heads/branch_to_delete)
# Delete remote tag v0.139:      git push origin :v0.139
#                                (git push origin :refs/tags/tag_to_delete)
# Create remote-tracking branch: git checkout -b pim0.142 origin/pim0.142
# Rename branch qpimd to pim:    git branch -m qpimd pim
# Commit changes:                git commit -a
# Send changes:                  git push --all
#
# Recipe to re-sync with Quagga repository:
#  git clone https://github.com/udhos/qpimd quagga
#  cd quagga
#  git checkout master
#  git pull http://git.sv.gnu.org/r/quagga.git master
#  git checkout -b pim origin/pim
#  git rebase master pim
#  # Test, then push back into Github repository:
#  git push origin :pim ;# delete remote branch pim
#  git push --all
#
# $QuaggaId: $Format:%an, %ai, %h$ $

git clone https://github.com/udhos/qpimd
