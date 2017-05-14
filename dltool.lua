local elfutil=elfutil

local file_extension='.dltool'
local file_pattern='%'..file_extension..'$'

-- This metatable provides for tables of tables where a new key
-- yields an empty table which is cached for future reference.
local populator = { __index = function(t,k) t[k] = {}; return t[k] end }

invoked=0

function resolve (directories, prefix, extralibs, cluster)

   local doreset = cluster and cluster.inode_to_elf
   local cluster = cluster or {}
   setmetatable(cluster, populator)
   local inode_to_elf = cluster.inode_to_elf
   local inode_to_synonyms = cluster.inode_to_synonyms
   local path_to_inode = cluster.path_to_inode
   local name_to_paths = cluster.name_to_paths
   local missing = cluster.missing
   setmetatable(cluster, nil)

   local queue = {}
   local stack = {}
   local slash = string.byte('/')
   local ldsocache = {}
   local defaultpaths = { '/lib', '/lib64', '/usr/lib', '/usr/lib64' }

   local function cleanuppath(path)
      local stack = {}
      local first,rest=path:match('([^/]*/?)(.*)')
      local anchored = first == '/'
      local backcount = 0
      if first == '..' or first == '../' then backcount = 1 end
      table.insert(stack, first)
      for part in string.gmatch(rest, '([^/]*/?)') do
	 if #part > 0 and part ~= '/' and part ~= './' then
	    if part ~= '..' and part ~= '../' then
	       table.insert(stack,part)
	    elseif anchored or #stack > backcount then
	       if #stack > 1 then table.remove(stack, #stack) end
	    else
	       table.insert(stack, '../')
	       backcount = backcount + 1
	    end
	 end
      end
      if #stack > 1 or #stack[1] > 1 then
	 local first=stack[#stack]:match('^(.*)/')
	 if first then stack[#stack] = first end
      end
      return table.concat(stack, '')
   end

   prefix = prefix and cleanuppath(prefix)
   do
      local cachefile = io.open(prefix and prefix..'/etc/ld.so.conf'
				   or '/etc/ld.so.conf')
      if cachefile then
	 for line in cachefile:lines() do
	    table.insert(ldsocache, cleanuppath(line))
	 end
	 cachefile:close()
      end

      local cleandirs = {}
      for _,path in ipairs(directories) do
	 table.insert(cleandirs, cleanuppath(path))
      end
      directories = cleandirs
      
      if extralibs then
	 cleandirs = {}
	 for _,path in ipairs(extralibs) do
	    table.insert(cleandirs, cleanuppath(path))
	 end
	 extralibs = cleandirs
      else
	 extralibs = {}
      end
   end

   if doreset then
      missing = {}
      cluster.missing = missing
      for inode, elf in pairs(inode_to_elf) do
	 if elf then
	    elf.dependents = {}
	    elf.supporters = {}
	    elf.needs_met = {}
	    table.insert(stack, inode)
	 end
      end
   end

   local function add_files(files)
      local function add_elf(filedescr)
	 local inode, name = unpack(filedescr)
	 if path_to_inode[name] then return end
	 local elfspec
	 if inode_to_elf[inode] == nil then
	    elfspec=elfutil.scan_elf(prefix and prefix..name or name) or false
	    if elfspec then
	       elfspec.path = name  -- One of many?
	       elfspec.inode = inode
	       elfspec.supporters = {}
	       elfspec.dependents = {}
	       elfspec.needs_met = {}
	       table.insert(stack, inode)
	    end
	    inode_to_elf[inode] = elfspec
	 end
	 if inode_to_elf[inode] then
	    path_to_inode[name] = inode
	    inode_to_synonyms[inode][name] = true
	    local dir,base = name:match '(.*)/([^/]*)'
	    name_to_paths[base][dir] = true
	 end
      end

      setmetatable(name_to_paths, populator)
      setmetatable(inode_to_synonyms, populator)
      local entries = elfutil.get_candidates(files, prefix)
      for _,filedescr in ipairs(entries) do add_elf(filedescr) end
      setmetatable(inode_to_synonyms, nil)
      setmetatable(name_to_paths, nil)
      return #entries > 0
   end

   add_files(defaultpaths)
   add_files(ldsocache)
   add_files(directories)
   add_files(extralibs)

   setmetatable(missing, populator)
   while #stack > 0 do
      while #stack > 0 do table.insert(queue, table.remove(stack)) end
      while #queue > 0 do
	 local inode = table.remove(queue)
	 local elf = inode_to_elf[inode]
	 local origin
	 local origins =
	    elfutil.get_origins(inode_to_synonyms[inode],prefix)
	 for k,_ in pairs(origins) do
	    k = cleanuppath(k)
	    if not origin then origin = k end
	    -- If there's more than one origin, we've got troubles.
	    if origin ~= k then
	       print('Multiple origins ignored: '..k..' ('..origin..')')
	    end
	 end
	 local rpath = {}
	 for _,path in ipairs(elf.runpath or elf.rpath or {}) do
	    if not origin then
	       table.insert(rpath, cleanuppath(path))
	    elseif path == '$ORIGIN' then
	       table.insert(rpath, origin)
	    else
	       path = path:gsub('^$ORIGIN/', origin..'/')
	       table.insert(rpath, cleanuppath(path))
	    end
	 end
	 function make_link(supporter_inode, path)
	    local supporter = inode_to_elf[supporter_inode]
	    if supporter.type == 'shared library'
	       and elf.class == supporter.class
	    and elf.machine == supporter.machine then
	       table.insert(supporter.dependents, { elf = elf, path = path })
	       table.insert(elf.supporters, { elf = supporter, path = path })
	       return true
	    end
	 end
	 
	 for _, needed in ipairs(elf.needed) do
	    if needed:byte() == slash then
	       -- Use hard wired library path.
	       if (path_to_inode[needed] or add_files(needed)) and
	       make_link(path_to_inode[needed], needed) then
		  elf.needs_met[needed] = true
	       else
		  table.insert(missing[needed], elf)
	       end
	    else
	       local paths = name_to_paths[needed]
	       if not paths then
		  add_files(rpath)
		  paths = name_to_paths[needed]
	       end
	       if paths then
		  local function search(pathtab)
		     for _, path in ipairs(pathtab) do
			if paths[path] then
			   local found = path..'/'..needed
			   if make_link(path_to_inode[found], found) then
			      elf.needs_met[needed] = true
			      return true
			   end
			end
		     end
		  end
		  if not search(rpath) and not search(ldsocache) and
		     not search(defaultpaths) and not search(extralibs) then
		     table.insert(missing[needed], elf)
		  end
	       else
		  table.insert(missing[needed], elf)
	       end
	    end
	 end
      end
   end
   setmetatable(missing, nil)

   local find, show
   do
      local skip = { find=true, show=true }

      show = function(paths, luastr)
	 if luastr then
	    local maxdir = 0
	    local split={}
	    for _,path in ipairs(paths) do
	       local dir,base = path:match '^(.*/)([^/]*)$'
	       table.insert(split, {dir,base})
	       if #dir > maxdir then maxdir = #dir end
	    end
	    local spaces = string.rep(' ', maxdir)
	    for i,split in ipairs(split) do
	       print(string.format(' \'%s\',%s \'%s\',',
				   split[1],spaces:sub(#split[1]), split[2]))
	    end
	    return
	 end
	 for i,path in ipairs(paths) do
	    print(string.format('    %-6d  %s',i,path))
	 end
      end

      find = function (paths, pattern, invert)
	 local matches = {}
	 sense = invert and function(bool) return not bool end
	    or function(bool) return bool end
	 for _,path in ipairs(paths) do
	    if sense(path:match(pattern)) and not skip[path] then
	       table.insert(matches, path)
	    end
	 end
	 matches.find = find
	 matches.show = show
	 return matches
      end
   end

   function cluster.find(self, pattern)
      local matches = {}
      for path,_ in pairs(self.path_to_inode) do
	 if path:match(pattern) then
	    table.insert(matches, path)
	 end
      end
      table.sort(matches)
      matches.find = find
      matches.show = show
      return matches
   end

   local function show_expand(self, path, header, field)
      local elf = self.inode_to_elf[self.path_to_inode[path]]
      if not elf then
	 print("No such item: "..path)
	 return
      end
      local seen = {}
      local stack = { elf }
      local expansion={}
      while #stack > 0 do
	 local top = table.remove(stack)
	 for _,this in ipairs(top[field]) do
	    local entry = this.elf
	    if not seen[entry] then
	       seen[entry] = true
	       table.insert(stack, entry)
	       table.insert(expansion, entry.path)
	    end
	 end
      end
      table.sort(expansion)
      expansion.find = find
      expansion.show = show
      if #expansion > 0 then
	 print(header..path..':')
	 expansion.show(expansion)
      else
	 print('No '..header:lower()..path..'.')
      end
      return expansion
   end

   function cluster.show_supported(self, path)
      return show_expand(self, path, "Dependents upon ", "dependents")
   end

   function cluster.show_needed(self, path)
      local expansion = show_expand(self, path, "Needed for ", "supporters")
      if not expansion then return end
      local unmet = {}
      local elf = self.inode_to_elf[self.path_to_inode[path]]
      for _, needed in ipairs(elf.needed) do
	 if not elf.needs_met[needed] then table.insert(unmet, needed) end
      end
      if #unmet > 0 then
	 print('\nUnmet needs:')
	 for _, needed in ipairs(unmet) do print('', needed) end
      end
      return expansion
   end

   function cluster.show_missing(self, verbose)
      local missing = self.missing
      if type(verbose) == 'string' then
	 local lib = missing[verbose]
	 if not lib then print('No such library: '..verbose); return end
	 missing = { [verbose]=lib }
      end
      print 'Missing shared libraries:'
      for lib,needers in pairs(missing) do
	 print('  '..lib)
	 if verbose then
	    for _, needer in ipairs(needers) do
	       local elf = self.inode_to_elf[needer.inode]
	       local first = '     M:'..elf.machine..' C:'..elf.class
	       local rest = string.rep(' ',#first)
	       for syn,_ in pairs(self.inode_to_synonyms[needer.inode]) do
		  print(first,syn)
		  first = rest
	       end
	    end
	 end
      end
   end

   function cluster.show_unneeded(self)
      local seen = {}
      local unneeded = {}
      for path,inode in pairs(self.path_to_inode) do
	 if not seen[inode] then
	    seen[inode] = true
	    local elf = inode_to_elf[path]
	    if elf and elf.type == 'shared library'
	    and #elf.dependents == 0 then
	       table.insert(unneeded, inode)
	    end
	 end
      end
      if #unneeded == 0 then
	 print 'No unneeded shared libraries'
      else
	 io.write 'Possibly unneeded libraries and their synonyms:'
	 for _, unneeded in ipairs(unneeded) do
	    print ''
	    local indent = ''
	    for path in pairs('  '..inode_to_synonyms[unneeded]) do
	       io.write(indent)
	       print(path)
	       indent = '  '
	    end
	 end
      end
   end

   function cluster.preserve(self, file)
      if not file:match(file_pattern) then file=file..file_extension end
      local handle, err = io.popen('xz -1 >'..file, 'w')
      if not handle then error(err) end
      handle:write(marshal.encode(self))
      handle:close()
   end

   return cluster
end


function reconstitute(file)
   local handle, err = io.popen('xzcat <'..file)
   if not handle then error(err) end
   local data = marshal.decode(handle:read '*a')
   handle:close()
   return data
end

function load_dlspec(file, prefix)
   local t = dofile(file)
   prefix = prefix or t.prefix
   local cluster = resolve(t.paths, prefix, t.extras)
   if t.default_name then cluster.default_name = t.default_name end
   return cluster
end

if (arg and arg[1]) then
   local cluster = load_dlspec(arg[1], arg[2])
   local name = cluster.default_name or 'NO_NAME'
   _G[name] = cluster
   print('\nCluster is in \''..name..'\'\n')
end
