function init (args)
    local needs = {}
    needs["protocol"] = "dns"
	--needs["filter"] = "alerts"
    return needs
end

function setup (args)
    filename = SCLogPath() .. "/" .. "dalton-dns-buffers.log"
    file, err = io.open(filename, "a")
    if file then
        SCLogInfo("DNS OPENED Log Filename " .. filename)
    else
        SCLogNotice("Error opening Lua log:" .. err)
    end
    dns = 0
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
    --SCLogNotice("Pulling DNS buffers");

    dns_query = DnsGetQueries();
    dns_answers = DnsGetAnswers();
    dns_auth = DnsGetAuthorities();
    --p = SCPacketPayload();

    ip_version, src_ip, dst_ip, protocol, src_port, dst_port = SCFlowTuple()
    timestring = SCPacketTimeString()

	outstring = "=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n\n"
	outstring = outstring .. "Raw Packet:\n"
	outstring = outstring .. timestring .. " " .. src_ip .. ":" .. src_port .. " -> " .. dst_ip .. ":" .. dst_port .. "\n\n"

	if dns_query then
		outstring = outstring .. "DNS_QUERY_DUMP, " .. tostring(table.maxn(dns_query)+1) .. "\n\n"
        for n, t in pairs(dns_query) do
            rrname = t["rrname"]
            rrtype = t["type"]
            outstring = outstring .. rrname .. ":" .. rrtype .. "\n"
            if DnsGetRecursionDesired() == true then
                outstring = outstring .. "Recursion Desired\n"
            else
                outstring = outstring .. "No Recursion\n"
            end
		    
        end
	end

    if dns_answers then
        if dns_auth then
            for n, t in pairs(dns_auth) do
                rrname = t["rrname"]
                rrtype = t["type"]
                ttl = t["ttl"]
        
                print ("AUTHORITY: " .. timestring .. " " .. rrname .. " [**] " .. rrtype .. " [**] " ..
                       ttl .. " [**] " .. src_ip .. ":" .. src_port .. " -> " ..
                       dst_ip .. ":" .. dst_port)
            end
        end
        for n, t in pairs(dns_answers) do
            rrname = t["rrname"]
            rrtype = t["type"]
            ttl = t["ttl"]
    
            outstring = outstring .. "ANSWER: " .. timestring .. " " .. rrname .. " [**] " .. rrtype .. " [**] TTL:" ..
                   ttl .. " [**] " .. src_ip .. ":" .. src_port .. " -> " ..
                   dst_ip .. ":" .. dst_port
        end
    end

    --if p then
        --outstring = outstring .. tostring(p)
    --end

    file:write (outstring)
    SCLogNotice("Output to file: ".. outstring)
    file:flush()

    dns = dns + 1
end

function deinit (args)
    SCLogInfo ("DNS transactions logged: " .. dns);
    file:close(file)
end
