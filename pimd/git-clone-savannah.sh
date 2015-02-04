#! /bin/bash
#
# Savannah Developer Git Checkout
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
#  git clone ssh://evertonm@git.sv.gnu.org/srv/git/qpimd.git quagga
#  cd quagga
#  git checkout master
#  git pull git://code.quagga.net/quagga.git master
#  git checkout -b pim origin/pim
#  git rebase master pim
#  # Test, then push back into Savannah repository:
#  git push origin :pim ;# delete remote branch pim
#  git push --all
#
# $QuaggaId: $Format:%an, %ai, %h$ $

git clone ssh://evertonm@git.sv.gnu.org/srv/git/qpimd.git quagga
