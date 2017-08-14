-----------------------------------------------
-- Some small utilities for adjusting rpaths --
-- based on actual needs.		     --
-- 					     --
-- Christopher Oliver			     --
-----------------------------------------------
   
local function foreach_elf(cluster, fn)
   for _, elf in pairs(cluster.inode_to_elf) do
      if elf then fn(elf) end
   end
end

local function make_pred(set)
   if not set then return end
   local pred = {}
   for _, v in ipairs(set) do pred[v]=true end
   return function(elf)
      if not pred then return true end
      local short = elf.canonical:match '^(.*)/[^/]*$'
      if #short == 0 then short = '/' end
      return pred[short]
   end
end

function clear_rpaths(cluster, directory_set)
   local clear_this = make_pred(directory_set)
   local function clear(elf)
      if clear_this(elf) then
	 os.execute('patchelf --remove-rpath '..elf.path)
      end
   end
   foreach_elf(cluster, clear)
end

function canonicalize(cluster)
   foreach_elf(cluster,
		function (elf)
		   elf.canonical = elfutil.canonicalize(elf.path)
   end)
end

function rewrite(cluster, directory_set)
   local write_this = make_pred(directory_set)
   local function rewrite(elf)
      if write_this(elf) then
	 local rpath_string = table.concat(elf.runpath, ':')
	 os.execute('patchelf --set-rpath \''..rpath_string..'\' \''..
		       elf.path..'\'')
      end
   end
   
   foreach_elf(cluster, rewrite)
end

function knit(cluster, other_substitutions)
   local function recompute_rpath(elf)
      elf.new_rpath=nil
      rpath = {}
      for _, supporter in ipairs(elf.supporters) do
	 local shortened = supporter.path:match '^(.*)/[^/]*$'
	 if #shortened == 0 then shortened = '/' end
	 rpath[shortened] = true
	 elf.new_rpath=rpath
      end
   end

   local function substitute(elf)
      if elf.new_rpath then
	 local origin=elf.canonical:match '^(.*)/[^/]*$'
	 if #origin == 0 then origin = '/' end
	 if elf.new_rpath[origin] then
	    elf.new_rpath['$ORIGIN'] = true
	    elf.new_rpath[origin] = nil
	 end
	 if other_substitutions then
	    local replacements = {}
	    for path in pairs(elf.new_rpath) do
	       substitution = other_substitutions[origin] and
		  other_substitutions[origin][path]
	       replacements[substitution or path] = true
	    end
	    elf.new_rpath = replacements
	 end
      end
   end

   local function replace(elf)
      if elf.new_rpath then
	 local new_rpath = {}
	 for p in pairs(elf.new_rpath) do table.insert(new_rpath, p) end
	 elf.new_rpath = nil
	 elf.runpath = new_rpath
      else
	 elf.runpath = nil
      end
   end

   foreach_elf(cluster, recompute_rpath)
   foreach_elf(cluster, substitute)
   foreach_elf(cluster, replace)
end
