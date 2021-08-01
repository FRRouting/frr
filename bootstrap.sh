#!/bin/sh

[ ! -d "lua/" ] && tar -xf lua-5.3.6.tar.gz && mv lua-5.3.6/ lua/

# This file exists to document the proper way to initialize autotools,
# and so that those used to the presence of bootstrap.sh or autogen.sh
# will have an eaiser time.

exec autoreconf -is -Wall,no-override
