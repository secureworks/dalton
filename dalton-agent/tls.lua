function init (args)
    local needs = {}
    needs["protocol"] = "tls"
	needs["filter"] = "alerts"
    return needs
end

function setup (args)
    filename = SCLogPath() .. "/" .. "dalton-tls-buffers.log"
    file, err = io.open(filename, "a")
    if file then
        SCLogInfo("TLS OPENED Log Filename " .. filename)
    else
        SCLogNotice("Error opening Lua log:" .. err)
    end
    tls = 0
end

function HexDump(buf)
	local s = {}
	s.output = ''
	for byte=1, #buf, 16 do
		local chunk = buf:sub(byte, byte+15)
		s.output = s.output .. string.format('%08X  ',byte-1)
		chunk:gsub('.', function (c) s.output = s.output .. string.format('%02X ',string.byte(c)) end)
		s.output = s.output .. string.rep(' ',3*(16-#chunk))
        s.output = s.output .. string.format("|%-16s|", chunk:gsub('[^\32-\126]','.')) .. "\n"
	end
	return s.output
end

function log(args)
    SCLogNotice("Pulling TLS buffers");

	tls_sni = TlsGetSNI()
	tls_version, tls_subject, tls_issuer, tls_fingerprint = TlsGetCertInfo()

    timestring = SCPacketTimeString()
    ip_version, src_ip, dst_ip, protocol, src_port, dst_port = SCFlowTuple()

	outstring = "=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n\n"
	outstring = outstring .. "Raw Packet:\n"
	outstring = outstring .. timestring .. " " .. src_ip .. ":" .. src_port .. " -> " .. dst_ip .. ":" .. dst_port .. "\n\n"

	if tls_sni then
		outstring = outstring .. "TLS_SNI_DUMP, " .. tostring(string.len(tls_sni)) .. "\n\n"
		outstring = outstring .. HexDump(tls_sni) .. "\n"
	end

	if tls_issuer then
		outstring = outstring .. "TLS_ISSUER_DUMP, " .. tostring(string.len(tls_issuer)) .. "\n\n"
		outstring = outstring .. HexDump(tls_issuer) .. "\n"
	end

	if tls_subject then
		outstring = outstring .. "TLS_SUBJECT_DUMP, " .. tostring(string.len(tls_subject)) .. "\n\n"
		outstring = outstring .. HexDump(tls_subject) .. "\n"
	end

    file:write (outstring)
    --SCLogNotice("Output to file: ".. outstring)
    file:flush()

    tls = tls + 1
end

function deinit (args)
    SCLogInfo ("TLS transactions logged: " .. tls);
    file:close(file)
end
