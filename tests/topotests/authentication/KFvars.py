
#
# Define keyfile paths and commands in this file and import to scripts
#

# Directory containing keyfile
#KFdir = '~frr/.ssh'
KFdir = '/etc/frr'

# basename of keyfile
#KFbase = 'frr'
KFbase = 'frr_pk_rsa'

# Full path of keyfile
KFfile = '{}/{}'.format(KFdir, KFbase)

# openssl variant to create keyfile
KFmk_o = 'openssl genpkey -algorithm RSA -out {}'.format(KFfile)

# can specify "--bits=1024" to certtool for keys smaller than default 3072
# certtool variant to create keyfile
KFmk_c = 'certtool --generate-privkey --key-type=rsa --null-password --outfile {}'.format(KFfile)

# create keyfile based on which command is available
KFmk = 'mkdir {} ; if which certtool ; then {}; else if which openssl ; then {} ; fi ; fi; chown -R frr.frr {} ; chmod -R go-rwx {} '.format(KFdir, KFmk_c, KFmk_o, KFdir, KFdir)


