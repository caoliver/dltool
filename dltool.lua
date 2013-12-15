name_to_inode = {}
inode_to_synonyms = {}
execs = {}
dyns = {}
present = {}
pending_needed = {}

function new_entry()
   return { needed = {}, ancestors = {}, descendants = {} }
end

function resolve_pending(needed, entry)
   if pending_needed[needed] then
      for _, target in ipairs(pending_needed[needed]) do
	 table.insert(entry.descendants, target)
	 table.insert(target.ancestors, entry)
      end
      pending_needed[needed] = nil
   end
end

function add_entry(entry)
   local soname = entry.soname
   local file = entry.file
   if entry.type == 'EXEC' then
      if soname then
	 error('SONAME '..soname..' is an executable')
      end
      execs[(entry.dir or '')..entry.file] = entry
   elseif (soname) then
      if entry.type ~= 'DYN' then
	 error('SONAME '..soname..' but not a shared object')
      end
      local seen = present[soname]
      if seen then
	 entry = seen
	 present[file] = seen
	 resolve_pending(file, entry)
      else
	 entry.names = {}
	 present[soname] = entry
	 dyns[soname] = entry
	 resolve_pending(soname, entry)
	 if soname ~= file then
	    present[file] = entry
	    resolve_pending(file, entry)
	 end
      end
      entry.names[file] = true
   else
      present[file] = entry
      entry.names = {}
      entry.names[file] = true
      entry.soname = file
      dyns[file] = entry
      resolve_pending(file, entry)
   end
   for _, needed in ipairs(entry.needed) do
      if present[needed] then
	 table.insert(present[needed].descendants, entry)
	 table.insert(entry.ancestors, present[needed])
      else
	 if not pending_needed[needed] then
	    pending_needed[needed] = {}
	 end
	 table.insert(pending_needed[needed], entry)
      end
   end
end

scan = {}

function scan.start(line, result)
   local file = line:match '^File: (.*)'
   if not file then
      return 'start', result
   end
   result.dir, result.file = file:match '(.*/)(.*)'
   if not result.dir then
      result.file = file
   end
   return 'type', result
end

function scan.type(line, result)
   if line == '' then
      return 'type', result
   end
   type = line:match "Elf file type is ([^ ]*)"
   if not type then
      return 'start', new_entry()
   end
   result.type = type
   return 'interp', result
end

function scan.interp(line, result)
   if line:match '^Dynamic section' then
      return 'relocs', result
   end
   local interp = line:match '%[Requesting program interpreter: (.*)%]'
   if interp then
      result.interp = interp
   end
   return 'interp', result
end

function scan.relocs(line, result)
   if line == '' then
      add_entry(result)
      return 'start', new_entry();
   end
   local type, value = line:match '%((.*)%).*%[(.*)%]'
   if type == 'SONAME' then
      result.soname = value
   elseif type == 'RPATH' or type == 'RUNPATH' then
      result.has_path = true
   elseif type == 'NEEDED' then
      table.insert(result.needed, value)
   end
   return 'relocs', result
end

function readelf(files)
   local proc = io.popen('readelf -dl / '..table.concat(files, ' ')..' 2>&-')
   local state = 'start'
   local result = new_entry()
   while true do
      local line = proc:read '*l'
      if not line then break end
      state, result = scan[state](line, result)
   end
   if state == 'relocs' then
      add_entry(result)
   end
   proc:close()
end

function unresolved()
   for need, needers in pairs(pending_needed) do
      print('\n'..need..' is needed by:')
      for _, who_needs in ipairs(needers) do
	 print('    '..(who_needs.dir or '')..who_needs.file)
      end
   end
end

function unused()
   for name, entry in pairs(dyns) do
      if #entry.descendants == 0 then
	 print(name)
      end
   end
end

function get_soname(file)
   local proc = io.popen('readelf -dl / '..file..' 2>&-|grep SONAME')
   local line = proc:read "*l"
   proc:close();
   if line then
      local value = line:match '%[(.*)%]'
      return value
   end
   return nil
end

function trim_filelists(files)
   local proc = io.popen('find  2>&- '..
			    table.concat(files, ' ')..
			    '-maxdepth 0 -follow -type f -printf "%D,%i %p\n"')
   while true do
      line = proc:read "*l"
      if not line then break end
      inode, name = line:match "^(.*) (.*)"
      name_to_inode[name] = inode
      existing_ref = inode_to_synonyms[inode]
      if not existing_ref then
	 existing_ref = {}
	 inode_to_synonyms[inode] = existing_ref
      end
      existing_ref[name] = true
   end
end

trim_filelists {
   "/bin/* /sbin/* /usr/bin/* /usr/sbin/* /usr/local/bin/*",
   "/lib64/* /usr/lib64/* /usr/local/lib/*",
   "/usr/lib64/perl5/CORE/libperl.so",
   "/usr/lib64/expect5.44.1.15/libexpect5.44.1.15.so"
}

function representative_filelist()
   local representatives = {}
   for _, synonyms in pairs(inode_to_synonyms) do
      table.insert(representatives, synonyms[1])
   end
   return table.concat(representatives, ' ')
end
