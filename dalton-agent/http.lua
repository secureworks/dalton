function init (args)
    local needs = {}
    needs["protocol"] = "http"
	--needs["filter"] = "alerts"
    return needs
end

function setup (args)
    filename = SCLogPath() .. "/" .. "dalton-http-buffers.log"
    file, err = io.open(filename, "a")
    if file then
        SCLogInfo("HTTP OPENED Log Filename " .. filename)
    else
        SCLogNotice("Error opening Lua log:" .. err)
    end
    http = 0
end

function HexDump(buf)
	local s = {}
	s.output = ''
	for byte=1, #buf, 16 do
		local chunk = buf:sub(byte, byte+15)
		s.output = s.output .. string.format('%08X  ',byte-1)
		chunk:gsub('.', function (c) s.output = s.output .. string.format('%02X ',string.byte(c)) end)
		s.output = s.output .. string.rep(' ',3*(16-#chunk))
		s.output = s.output .. string.format("|%-16s|", chunk:gsub('%c','.')) .. "\n"
	end
	return s.output
end

function log(args)
    SCLogNotice("Pulling HTTP buffers");

    http_raw_uri = HttpGetRequestUriRaw()
    http_host = HttpGetRequestHost()
    http_ua = HttpGetRequestHeader("User-Agent")

    timestring = SCPacketTimeString()
    ip_version, src_ip, dst_ip, protocol, src_port, dst_port = SCFlowTuple()

	outstring = "=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n\n"
	outstring = outstring .. "Raw Packet:\n"
	outstring = outstring .. timestring .. " " .. src_ip .. ":" .. src_port .. " -> " .. dst_ip .. ":" .. dst_port .. "\n\n"

	if http_raw_uri != nil then
		outstring = outstring .. "RAW_URI_DUMP, " .. tostring(string.len(http_raw_uri)) .. "\n\n"
		outstring = outstring .. HexDump(http_raw_uri)
	end

    file:write (outstring)
    SCLogNotice("Output to file: ".. outstring)
    file:flush()

    http = http + 1
end

function deinit (args)
    SCLogInfo ("HTTP transactions logged: " .. http);
    file:close(file)
end
