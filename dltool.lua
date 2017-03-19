-- This metatable provides for tables of tables where a new key
-- yields an empty table which is cached for future reference.
local populator = { __index = function(t,k) t[k] = {}; return t[k] end }

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
      -- Elide superfluous '/'.
      path = path:gsub('/+', '/')
      -- Remove backtracks.
      local newpath
      while true do
	 local newpath = path:gsub('/[^/]+/%.%./', '/')
	 if newpath == path then break end
	 path = newpath
      end
      -- Remove trailing slash if present.
      return path[#path] == '/'  and path:sub(1,-2) or path
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
	 inode = table.remove(queue)
	 local elf = inode_to_elf[inode]
	 local origin
	 if elf.type == 'executable' then
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

   return cluster
end

function find(cluster, pattern)
   for path,_ in pairs(cluster.path_to_inode) do
      if path:match(pattern) then print(path) end
   end
end

function show_expand(cluster, path, header, field)
   local elf = cluster.inode_to_elf[cluster.path_to_inode[path]]
   if not elf then
      print("No such item: "..path)
      return
   end
   local seen = {}
   local stack = { elf }
   print(header..path..':')
   while #stack > 0 do
      local top = table.remove(stack)
      for _,this in ipairs(top[field]) do
         local entry = this.elf
         if not seen[entry] then
            seen[entry] = true
            table.insert(stack, entry)
            print('',entry.path)
         end
      end
   end
   return true
end

function show_supported(cluster, path)
   show_expand(cluster, path, "Dependents upon ", "dependents")
end

function show_needed(cluster, path)
   if not show_expand(cluster, path, "Needed for ", "supporters") then
      return
   end
   local unmet = {}
   local elf = cluster.inode_to_elf[cluster.path_to_inode[path]]
   for _, needed in ipairs(elf.needed) do
      if not elf.needs_met[needed] then table.insert(unmet, needed) end
   end
   if #unmet > 0 then
      print('\nUnmet needs:')
      for _, needed in ipairs(unmet) do print('', needed) end
   end
end

function show_missing(cluster, verbose)
   for lib,needers in pairs(cluster.missing) do
      print('Missing: '..lib)
      if verbose then
	 for _, needer in ipairs(needers) do
	    local elf = cluster.inode_to_elf[needer.inode]
	    local first = '   M:'..elf.machine..' C:'..elf.class
	    for syn,_ in pairs(cluster.inode_to_synonyms[needer.inode]) do
	       print(first,syn)
	       first = '         '
	    end
	 end
      end
   end
end

function save_cluster(cluster, file)
   local handle, err = io.open(file, 'w')
   if not handle then error(err) end
   local data = marshal.encode(cluster)
   handle:write(data)
   handle:close()
end

function load_cluster(file)
   local handle, err = io.open(file)
   if not handle then error(err) end
   local data = handle:read '*a'
   handle:close()
   return marshal.decode(data)
end

function load_spec(file, prefix)
   print(file)
   local t = loadfile(file)()
   prefix = prefix or t.prefix
   return resolve(t.paths, prefix, t.extras)
end

if (arg and arg[1]) then
   local name = arg[3] or 'c'
   _G[name] = load_spec(arg[1], arg[2])
   print('Cluster is in \''..name..'\'')
end
