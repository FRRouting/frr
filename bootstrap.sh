#!/bin/sh

# Download Lua
LUA_SUFFIX="5.3.6"
LUA_SOURCE_SHA1="f27d20d6c81292149bc4308525a9d6733c224fa5"

lua() {
    [ -f "lua-${LUA_SUFFIX}.tar.gz" ] && \
        [ $(shasum lua-${LUA_SUFFIX}.tar.gz | cut -f 1 -d ' ') == "${LUA_SOURCE_SHA1}" ] && \
        return 0
    wget -t 3 "https://www.lua.org/ftp/lua-${LUA_SUFFIX}.tar.gz"
    status="$?"
    test $status -eq 0 || exit $eq
    tar zxf "lua-${LUA_SUFFIX}.tar.gz"
    cd "lua-${LUA_SUFFIX}" && make linux install INSTALL_TOP=../install
    cd ..
}

lua

# This file exists to document the proper way to initialize autotools,
# and so that those used to the presence of bootstrap.sh or autogen.sh
# will have an eaiser time.

exec autoreconf -is -Wall,no-override
