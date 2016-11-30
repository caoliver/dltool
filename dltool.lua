local function table_keys(t)
   local list = {}
   for key in pairs(t) do
      table.insert(list, key)
   end
   return list
end

local function add_look_ahead(file)
   local pushback = nil
   local tbl = getmetatable(file)
   function tbl.ungetline(_, line)
      pushback = line
   end
   function tbl.getline()
      local old_pushback = pushback
      pushback = nil
      return old_pushback or file:read()
   end
end


local function expand_search_path(pathlist, origin)
   local result = {}
   pathlist = pathlist:match '%s*(.*[^%s])%s*'
   while pathlist do
      local path, rest = pathlist:match '^([^:]*):(.*)$'
      if not path then
	 path = pathlist
      end
      local is_origin = (path:match '^%$ORIGIN/') or (path:match '^%$ORIGIN$')
      if (is_origin) then
      -- FIGURE ORIGIN STUFF HERE
      end
      table.insert(result, path)
      pathlist = rest
   end
   return result
end


function resolve_system(cluster, default_path)
   if type(default_path) == string then
      default_path = expand_search_path(default_path)
   end
   local slash = string.byte('/', 1)
   cluster.dirty = nil
   cluster.missing = {}
   cluster.interp = nil
   cluster.interp_warning = nil
   for inode, entry in pairs(cluster.inode_to_entry) do
      entry.dependents = {}
      entry.supporters = {}
   end
   for inode, entry in pairs(cluster.inode_to_entry) do
      if entry.interp then
	 if not cluster.interp then
	    cluster.interp = entry.interp
	 elseif (not cluster.interp_warning
		 and entry.interp ~= cluster.interp) then
	    cluster.interp_warning = true
	    print "Warning: mixed elf interpreters"
	 end
      end
      local function make_link(supporter_inode, path)
	 local supporter = cluster.inode_to_entry[supporter_inode]
	 table.insert(supporter.dependents, { entry = entry, path = path })
	 table.insert(entry.supporters, { entry = supporter, path = path})
      end
      for _, needed in ipairs(entry.needed) do
	 local function note_missing()
	    if not cluster.missing[needed] then
	       cluster.missing[needed] = { entry }
	    else
	       table.insert(cluster.missing[needed], entry)
	    end
	 end

	 if needed:byte() == slash then
	    local inode = cluster.path_to_inode[needed]
	    if inode then
	       make_link(inode, needed)
	    else
	       note_missing(needed, entry)
	    end
	 else
	    local paths = cluster.name_to_paths[needed]
	    local found_path
	    if paths then
	       local function searchiftrue(cond, pathtab)
		  if cond then
		     for _, path in pairs(pathtab) do
			if paths[path] then
			   found_path = path..'/'..needed
			   return
			end
		     end
		  end
	       end
	       local rpath = entry.runpath or entry.rpath
	       searchiftrue(rpath, rpath)
	       searchiftrue(not found_path, default_path)
	    end
	    if found_path then
	       make_link(cluster.path_to_inode[found_path], found_path)
	    else
	       note_missing(needed, entry)
	    end
	 end
      end
   end
end


function find_set_closure(cluster, root_set)
   if cluster.dirty then error "Please resolve cluster first" end
   local supporter_set = {}
   local queue = {}
   local stack = {}
   local seen = {}
   for _, root in ipairs(root_set) do
      local inode = cluster.path_to_inode[root]
      if not inode then error("Can't find root: "..root) end
      table.insert(queue, cluster.inode_to_entry[inode])
      seen[root] = true
   end
   while #queue > 0 do
      local object = table.remove(queue)
      for _, item in ipairs(object.supporters) do
	 local entry = item.entry
	 if not seen[entry] then
	    supporter_set[entry] = {}
	    seen[entry] = true
	    table.insert(stack, entry)
	 end
	 supporter_set[entry][item.path] = true
      end
      if #queue == 0 then
	 while #stack > 0 do
	    table.insert(queue, table.remove(stack))
	 end
      end
   end
   for entry,paths in pairs(supporter_set) do
      supporter_set[entry] = table_keys(paths)
   end
   return supporter_set
end


function show_cpiospec(supporter_set, libpath)
   local function basename(path)
      return path:match '.*/([^/]*)' or path
   end

   for entry, used_paths in pairs(supporter_set) do
      local filename = entry.soname or basename(used_paths[1])
      io.write('file '..libpath..filename..' '..entry.path..' 0755 0 0')
      for _,path in ipairs(used_paths) do
	 local base = basename(path)
	 if base ~= filename then io.write(' '..libpath..base) end
      end
      io.write '\n'
   end
end


local function append_prefix(files, prefix)
   local prefix = prefix or ''
   local name_start = prefix and #prefix + 1 or 1
   if type(files) == 'table' then
      files = table.concat(files, ' '..prefix)
   end
   return prefix..files, name_start
end


function readelf(cluster, files, prefix)
   cluster.dirty = true
   local files, name_start = append_prefix(files, prefix)
   local proc =
      io.popen('readelf -dl / '..files..' 2>&-')
   add_look_ahead(proc)
   repeat
      local entry = { needed = {} }
      local state = 'start'
      local scanners = {
	 start = function(line)
	    return line and 'file' or nil
	 end,

	 file = function(line)
	    entry.path = string.sub(line:match '^File: (.*)', name_start, -1)
	    entry.file = entry.path:match '.*/(.*)'
	    return 'elftype'
	 end,

	 elftype = function(line)
	    if not line then return nil end
	    if line == '' then return 'elftype' end
	    local elftype = line:match 'Elf file type is ([^ ]*)'
	    if not elftype then
	       if line == 'There are no program headers in this file.' then
		  return 'start'
	       end
	       proc:ungetline(line)
	       return 'file'
	    end
	    entry.elftype = elftype
	    return 'interp'
	 end,
	    
	 interp = function(line)
	    if line == 'There is no dynamic section in this file.' then
	       return 'start'
	    end
	    if line:match '^Dynamic section' then return 'dyns' end
	    local interp =
	       line:match '%[Requesting program interpreter: (.*)%]'
	    if interp then entry.interp = interp end
	    return 'interp'
	 end,

	 dyns = function(line)
	    if line == '' or line == nil then
	       proc:ungetline(line)
	       return false;
	    end
	    local dyntype, value = line:match '%((.*)%).*%[(.*)%]'
	    if dyntype == 'SONAME' then
	       entry.soname = value
	    elseif dyntype == 'RPATH' and not entry.runpath then
	       entry.rpath = expand_search_path(value)
	    elseif dyntype == 'RUNPATH' then
	       entry.rpath = nil
	       entry.runpath = expand_search_path(value)
	    elseif dyntype == 'NEEDED' then
	       table.insert(entry.needed, value)
	    end
	    return 'dyns'
	 end
      }
      repeat
	 local line = proc:getline()
	 state = scanners[state](line)
      until not state
      if state == false then
	 cluster.inode_to_entry[cluster.path_to_inode[entry.path]] = entry
      end
   until state == nil
   proc:close()
end


function create_cluster()
   return { dirty = true,
	    path_to_inode = {},
	    name_to_paths = {},
	    inode_to_synonyms = {},
	    inode_to_entry = {},
	    inode_size = {}
   }
end


function add_files(cluster, files, prefix)
   cluster.dirty = true
   local files, name_start = append_prefix(files, prefix)
   local proc = io.popen('find 2>&- ' ..
			    files ..
			    ' -maxdepth 1 -mindepth 1' ..
			    ' -follow -type f -a ! -name \\*.a' ..
			    ' -printf "%D,%i %p %s\n"')
   for line in proc:lines() do
      local inode, name, size = line:match '^(.*) (.*) (.*)'
      name=name:sub(name_start,-1)
      local dir, base = name:match '(.*)/([^/]*)'
      if not cluster.name_to_paths[base] then
	 cluster.name_to_paths[base] = {}
      end
      cluster.name_to_paths[base][dir] = true
      cluster.path_to_inode[name] = inode
      local existing_ref = cluster.inode_to_synonyms[inode]
      cluster.inode_size[inode] = size
      if not existing_ref then
	 existing_ref = {}
	 cluster.inode_to_synonyms[inode] = existing_ref
      end
      existing_ref[name] = true
   end
   proc:close()

   cluster.representatives = {}
   for inode, synonyms in pairs(cluster.inode_to_synonyms) do
      local synonyms = table_keys(synonyms)
      cluster.inode_to_synonyms[inode] = synonyms
      table.insert(cluster.representatives, synonyms[1])
   end
end


function show_missing(cluster)
   for k,v in pairs(cluster.missing) do
      print(k..':')
      for _,ref in ipairs(v) do
	 print('',ref.path)
      end
   end
end


function show_supported(cluster, path)
   local seen = {}
   local stack = { cluster.inode_to_entry[cluster.path_to_inode[path]] }
   print("Dependents upon "..path)
   while #stack > 0 do
      local top = table.remove(stack)
      for _,dep in ipairs(top.dependents) do
	 local entry = dep.entry
	 if not seen[entry] then
	    seen[entry] = true
	    table.insert(stack, entry)
	    print('',entry.path)
	 end
      end
   end
end


function find(cluster, pattern)
   for path,_ in pairs(cluster.path_to_inode) do
      if path:match(pattern) then print(path) end
   end
end


function load_system(file, name, prefix)
   local t = loadfile(file)()
   prefix = prefix or t.prefix or ''
   strip = prefix:match '^(.*)/$'
   prefix = strip or prefix
   local new_cluster = create_cluster()
   add_files(new_cluster, t.candidates, prefix)
   readelf(new_cluster, new_cluster.representatives, prefix)
   resolve_system(new_cluster, t.search_path)
   if name then _G[name] = new_cluster end
   return new_cluster
end

if (arg[1]) then
   load_system(arg[1], 'c', arg[2])
   print("Cluster is in 'c'")
end
