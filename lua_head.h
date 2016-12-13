#ifndef __LUA_HEAD__
#define __LUA_HEAD__
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#define LUAFN(NAME) static int lua_fn_##NAME(lua_State *L)
#define FN_ENTRY(NAME) { #NAME, lua_fn_##NAME }
#define AT_NAME_PUT(NAME, VALUE, TYPE)		\
    lua_pushstring(L, #NAME);  \
    lua_push##TYPE(L, VALUE);  \
    lua_rawset(L, -3)
#define AT_NAME_PUT_INT(NAME, VALUE) AT_NAME_PUT(NAME, VALUE, integer)
#endif
