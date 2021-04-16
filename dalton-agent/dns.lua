function init (args)
    local needs = {}
    needs["protocol"] = "dns"
	needs["filter"] = "alerts"
    return needs
end

function setup (args)
    filename = SCLogPath() .. "/" .. "dalton-dns-buffers.log"
    --filename = "/tmp/dalton-dns-buffers.log"
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
    p = SCPacketPayload();

    ip_version, src_ip, dst_ip, protocol, src_port, dst_port = SCFlowTuple()
    timestring = SCPacketTimeString()

	outstring = "=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n\n"
	outstring = outstring .. "Raw Packet:\n"

    -- It has BOTH for every packet as request/response are always returned and not nil.
    --[[
    if dns_query ~= nil then
        outstring = outstring .. "Query Packet\n"
    end
    if dns_answers ~= nil then
        outstring = outstring .. "Response Packet\n"
    end--]]
    
    if dns_answers ~= nil then
        rcount = 0
        rstring = ""
        pairnames = ""
        --pairnames = "All response names:\n"
        for n, t in pairs(dns_answers) do
            --[[
            -- to inspect a table with undocumented values
            for tname, tval in pairs(t) do
                pairnames = pairnames .. tname .. "\n"
            end--]]
            rrname = t["rrname"]
            rrtype = t["type"]
            ttl = t["ttl"]
            addy = t["addr"] -- undocumented in Suricata Lua function docs

            rstring = rstring .. pairnames .. "\nADDRESS:\n" .. HexDump(addy)
            rcount = rcount + 1
        end
        if rcount > 0 then
            if dns_auth then
                --authnames = "All Auth names:\n"
                for n, t in pairs(dns_auth) do
                    --[[
                    -- inspect all auth value names
                    for aname, aval in pairs(t) do
                        authnames = authnames .. aname
                    end-
                    outstring = outstring .. authnames .. "\n"-]]
                    rrname = t["rrname"]
                    rrtype = t["type"]
                    ttl = t["ttl"]
            
                    outstring = outstring .. "AUTHORITY: " .. timestring .. " " .. rrname .. " [**] " .. rrtype .. " [**] TTL:" ..
                           ttl .. " [**] " .. src_ip .. ":" .. src_port .. " -> " ..
                           dst_ip .. ":" .. dst_port .. "\n"
                end
            end
            outstring = outstring .. timestring .. " " .. dst_ip .. ":" .. dst_port .. " -> " .. src_ip .. ":" .. src_port .. "\n\n"
            outstring = outstring .. "DNS_RESPONSE\n" .. rstring

            
        end
    end
    
    if (dns_query ~= nil and rcount == 0) then
        outstring = outstring .. timestring .. " " .. src_ip .. ":" .. src_port .. " -> " .. dst_ip .. ":" .. dst_port .. "\n\n"
        outstring = outstring .. "DNS_QUERY_DUMP, " .. tostring(table.maxn(dns_query)+1) .. "\n\n"


        --pairnames = "All request names:\n"
        for n, t in pairs(dns_query) do
            --[[
            for tname, tval in pairs(t) do
                pairnames = pairnames .. tname .. "\n"
            end--]]
            rrname = t["rrname"]
            rrtype = t["type"]
            outstring = outstring .. pairnames .. "REQUEST:" .. rrname .. ":" .. rrtype .. "\n"
            if DnsGetRecursionDesired() == true then
                outstring = outstring .. "Recursion Desired\n"
            else
                outstring = outstring .. "No Recursion\n"
            end
		    
        end
	end


    
    outstring = outstring .. "\n"
    if p then
        --outstring = outstring .. HexDump(p)
    end

    file:write (outstring)
    --SCLogNotice("Output to file: ".. outstring)
    file:flush()

    dns = dns + 1
end

function deinit (args)
    SCLogInfo ("DNS transactions logged: " .. dns);
    file:close(file)
end
