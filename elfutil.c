#include "lua_head.h"
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <gelf.h>
#include <errno.h>
#include <alloca.h>

char *realpath(const char *path, char *resolved_path);

#define PT_INTERP       3
#define SHT_DYNAMIC     6

static int architecture = 0;

LUAFN(filter_on_machine)
{
    if (lua_isnoneornil(L,1)) {
	architecture = 0;
	return 0;
    }
    int newarch = luaL_checkinteger(L, 1);
    if (newarch < 0 || newarch > 110) {
	lua_pushstring(L, "Invalid architecture!");
	lua_error(L);
    }
    architecture = newarch;
    return 0;
}

static int read_at(int fd, char *buffer, size_t len, size_t where)
{
    size_t old = lseek(fd, SEEK_CUR, 0);
    if (old == -1 ||
 	lseek(fd, where, SEEK_SET) == -1 ||
	read(fd, buffer, len) == -1 ||
	lseek(fd, old, SEEK_SET) == -1)
	return -1;
    return 0;
}

/* Note: since this function will get randoms from find, silently
 * return nil for non-elfs and wrong size/architecture.
 */
LUAFN(scan_elf)
{
    const char *filename = luaL_checkstring(L, 1);
    int fd = -1;
    Elf *handle = NULL;
    const char *errmsg = NULL;
    GElf_Ehdr ehdr;
    int return_items = 0;

    if (elf_version(EV_CURRENT) == EV_NONE)
	goto bugout;

    if ((fd = open(filename, O_RDONLY)) < 0) {
	errmsg = strerror(errno);
	goto bugout;
    }

    if ((handle = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
	goto bugout;

    if (elf_kind(handle) != ELF_K_ELF)
	goto done;

    lua_newtable(L);
    lua_pushstring(L, "class");
    switch (gelf_getclass(handle)) {
    case ELFCLASS32:
	lua_pushinteger(L, 32);
	break;
    case ELFCLASS64:
	lua_pushinteger(L, 64);
	break;
    default:
	errmsg = "Unknown ELF class";
	goto bugout;
    }
    lua_rawset(L, -3);

    if (gelf_getehdr(handle, &ehdr) == NULL)
	goto bugout;

    // The caller specified an architecture, but we don't match,
    // then skip this.
    if (architecture && ehdr.e_machine != architecture)
	goto done;
    
    lua_pushstring(L, "machine");
    lua_pushinteger(L, ehdr.e_machine);
    lua_rawset(L, -3);    

    lua_pushstring(L, "type");
    switch (ehdr.e_type) {
    case 2:
	lua_pushstring(L, "executable");
	break;
    case 3:
	lua_pushstring(L, "shared library");
	break;
    default:
	errmsg = "Unexpected elf type";
	goto bugout;
    }
    lua_rawset(L, -3);

    // Find the interpreter (loader)
    size_t n;
    if (elf_getphdrnum(handle, &n))
	goto bugout;

    GElf_Phdr phdr;
    for (size_t i=0; i < n; i++) {
	if (gelf_getphdr(handle, i, &phdr) != &phdr)
	    goto bugout;
	if (phdr.p_type == PT_INTERP) {
	    char *tempbuf = alloca(phdr.p_filesz);
	    if (read_at(fd, tempbuf, phdr.p_filesz, phdr.p_offset)) {
		errmsg = strerror(errno);
		goto bugout;
	    }
	    lua_pushstring(L, "interp");
	    lua_pushstring(L, tempbuf);
	    lua_rawset(L, -3);
	    break;
	}
    }

    size_t shstrndx;
    
    if (elf_getshdrstrndx(handle, &shstrndx))
	goto bugout;

    char *name;
    Elf_Scn *scn = NULL;
    char *strtab = NULL;
    Elf_Data *edata = NULL;
    int strtablen;
    while ((scn = elf_nextscn(handle, scn)) != NULL) {
	static GElf_Shdr shdr;
	if (gelf_getshdr(scn, &shdr) != &shdr)
	    goto bugout;
	if (shdr.sh_type == SHT_STRTAB) {
	    if (!(name = elf_strptr(handle, shstrndx, shdr.sh_name )))
		goto bugout;
	    if (strcmp(name, ".dynstr"))
		continue;
	    strtab = alloca(shdr.sh_size);
	    read_at(fd, strtab, strtablen = shdr.sh_size, shdr.sh_offset);
	}
	if (shdr.sh_type == SHT_DYNAMIC) {
	    if (!(name = elf_strptr(handle, shstrndx, shdr.sh_name )))
		goto bugout;
	    if (strcmp(name, ".dynamic"))
		continue;
	    if (!(edata = elf_getdata(scn, NULL)))
		goto bugout;
	}
    }
    // No dynamic section?  No worries.
    if (!edata)
	goto done;
    GElf_Dyn gdyn;
    lua_pushstring(L, "needed");
    lua_newtable(L);
    int libnum = 1;
    for (int i = 0; gelf_getdyn(edata, i, &gdyn) == &gdyn; i++) {
	switch(gdyn.d_tag) {
	case DT_NEEDED:
	    lua_pushstring(L, strtab + gdyn.d_un.d_val);
	    // STACK: dt_value needed_table "needed" elf_table
	    lua_rawseti(L, -2, libnum++);
	    continue;
	case DT_SONAME:
	    lua_pushstring(L, "soname");
	    lua_pushstring(L, strtab + gdyn.d_un.d_val);
	    // STACK: dt_value dt_name needed_table "needed" elf_table
	    lua_rawset(L, -5);
	    continue;
	case DT_RPATH:
	    lua_pushstring(L, "rpath");
	    break;
	case DT_RUNPATH:
	    lua_pushstring(L, "runpath");
	    break;
	default:
	    continue;
	}
	lua_newtable(L);
	char *pathptr = strtab + gdyn.d_un.d_val;
	char *next;
	int i;  // Shadows loopvar.
	for (i = 1;
	     next = strchr(pathptr, ':');
	     i++, pathptr = next+1) {
	    lua_pushlstring(L, pathptr, next - pathptr);
	    lua_rawseti(L, -2, i);
	} 
	lua_pushstring(L, pathptr);
	lua_rawseti(L, -2, i);

	lua_rawset(L, -5);
    }
    lua_rawset(L, -3);
    return_items = 1;
    
done:
    elf_end(handle);
    close(fd);
    return return_items;

bugout:
    if (!errmsg)
	errmsg = elf_errmsg(-1);
    if (handle)
	elf_end(handle);
    if (fd >= 0)
	close(fd);
    lua_pushnil(L);
    lua_pushstring(L, errmsg);
    return 2;
}

#define DT_REG 8
#define DT_LNK 10

static void inode_in_table(lua_State *L, int dev, int inode)
{
    char buf[128];
    sprintf(buf, "%d,%d", dev, inode);
    lua_newtable(L);
    lua_pushstring(L, buf);
    lua_rawseti(L, -2, 1);
    return;
}

// candidate_table, prefix
LUAFN(get_candidates)
{
    char *curdir = NULL;

    if (lua_isnoneornil(L, 1) ||
	!(curdir = getcwd(NULL, 0)) ||
	chdir(lua_toboolean(L, 2) ? luaL_checkstring(L, 2) : "/") == -1) {
	free(curdir);
	lua_newtable(L);
	return 1;
    }

    // Single value becomes a one-entry table.
    if (lua_istable(L, 1))
	lua_pushvalue(L,1);
    else {
	lua_newtable(L);
	lua_pushvalue(L,1);
	lua_rawseti(L,-2,1);
    }

    // Stat results go here.
    lua_newtable(L);
	
    lua_pushnil(L);
    int place = 1;
    while (lua_next(L, -3)) {
	struct stat statb;
	const char *name = lua_tostring(L, -1);

	if (*name != '/' || stat(&name[1], &statb) == -1)
	    goto done;

	if (S_ISREG(statb.st_mode)) {
	    inode_in_table(L, statb.st_dev, statb.st_ino);
	    lua_pushstring(L, name);
	    lua_rawseti(L, -2, 2);
	    lua_rawseti(L, -4, place++);
	    goto done;
	}
	
	if (S_ISDIR(statb.st_mode)) {
	    DIR *dirp;
	    char *olddir = getcwd(NULL, 0);
	    if (chdir(&name[1]) == 0 && (dirp = opendir("."))) {
		struct dirent *dent;
		while (dent = readdir(dirp)) {
		    // Exclude some obviously wrong files.
		    if (dent->d_type != DT_REG && dent->d_type != DT_LNK)
			continue;
		    char *ext=strrchr(dent->d_name, '.');
		    if (ext && (!strcmp(ext, ".a") || !strcmp(ext, ".la")))
			continue;
		    if (stat(dent->d_name, &statb) == -1 ||
			!S_ISREG(statb.st_mode))
			continue;
		    inode_in_table(L, statb.st_dev, statb.st_ino);
		    lua_pushfstring(L, "%s/%s", name, dent->d_name);
		    lua_rawseti(L, -2, 2);
		    lua_rawseti(L, -4, place++);
		}
		closedir(dirp);
	    }
	    if (olddir)
		chdir(olddir);
	    free(olddir);
	}

    done:
	lua_pop(L, 1);
    }
    
    chdir(curdir);
    free(curdir);
    return 1;
	
}

// Look through a table of synonyms for a given file and yield the directories
// for which the synonym with an absolute path is a hardlink.
LUAFN(get_origins)
{
    char *curdir = NULL;
    if (!(curdir = getcwd(NULL, 0)) ||
	chdir(lua_toboolean(L, 2) ? luaL_checkstring(L, 2) : "/") == -1) {
	free(curdir);
	lua_newtable(L);
	return 1;
    }
    lua_newtable(L);
    lua_pushnil(L);
    while (lua_next(L, 1)) {
	struct stat statb;
	const char *filename = lua_tostring(L, -2);
	lua_pop(L, 1);
		
	if (*filename != '/' || lstat(&filename[1], &statb) != 0 ||
	    !S_ISREG(statb.st_mode)) {
	    continue;
	}

	char *dirend = strrchr(filename, '/');
	if (dirend) {
	    int len = dirend - filename;
	    lua_pushlstring(L, filename, len > 0 ? len : 1);
	} else
	    lua_pushstring(L, filename);
	lua_pushboolean(L, 1);
	lua_rawset(L, -4);
    }
    chdir(curdir);
    free(curdir);
    return 1;
}

LUAFN(canonicalize)
{
    char *path = realpath(lua_tostring(L, 1), NULL);

    if (path) {
        lua_pushstring(L, path);
        free(path);
    } else
        lua_pushnil(L);

    return 1;
}

typedef struct { const char *name; int value; } intconst;

LUALIB_API int luaopen_elfutil(lua_State *L)
{
    static const luaL_Reg funcptrs[] = {
	FN_ENTRY(filter_on_machine),
	FN_ENTRY(scan_elf),
	FN_ENTRY(get_candidates),
	FN_ENTRY(get_origins),
	FN_ENTRY(canonicalize),
	{NULL, NULL}
    };

    static intconst machines[] = {
	{"AMD64", 62},
	{"X86", 3},
	{NULL, 0}
    };

    luaL_register(L, "elfutil", funcptrs);
    for (int i = 0; machines[i].name; i++) {
        lua_pushstring(L, machines[i].name);
        lua_pushinteger(L, machines[i].value);
        lua_rawset(L, -3);
    }
    
    return 1;
}
