local dalton
do
    local ok, mod = pcall(require, "dalton-suricata")
    if ok then
        dalton = mod
    else
        local chunk = loadfile("dalton-suricata.lua")
        if chunk == nil then
            chunk = loadfile("/opt/dalton-agent/dalton-suricata.lua")
        end
        if chunk then
            dalton = chunk()
        end
    end
end
if dalton == nil then
    error("failed to load dalton-suricata compatibility layer")
end

function init (args)
    local needs = {}
    needs["protocol"] = "dns"
    needs["filter"] = "alerts"
    return needs
end

local LOG_NAME = "dalton-dns-buffers.log"

function setup (args)
    -- File is opened on first log(); see comment in dalton-suricata.lua / agent README.
    file = nil
    dns_count = 0
end

function ensure_file()
    if file == nil then
        file, err = dalton.open_log(LOG_NAME)
        if file then
            dalton.info("DNS OPENED Log Filename " .. dalton.log_path() .. "/" .. LOG_NAME)
        else
            dalton.notice("Error opening Lua log: " .. tostring(err))
        end
    end
end

function HexDump(buf)
    if buf == nil or #buf == 0 then
        return ""
    end
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
    ensure_file()

    local tx, err = nil, nil
    if dalton.suri8 then
        tx, err = require("suricata.dns").get_tx()
        if not dalton.is_tx(tx) then
            dalton.notice("DNS log skipped: " .. tostring(err or tx))
            return
        end
    end

    dns_query = dalton.dns_queries()
    dns_answers = dalton.dns_answers()
    dns_auth = dalton.dns_authorities()

    ip_version, src_ip, dst_ip, protocol, src_port, dst_port = dalton.flow_tuple()
    timestring = dalton.packet_timestring()

    outstring = "=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n\n"
    outstring = outstring .. "Raw Packet:\n"

    rcount = 0
    if dns_answers ~= nil then
        rstring = ""
        pairnames = ""
        for n, t in pairs(dns_answers) do
            rrname = t["rrname"]
            rrtype = t["type"]
            ttl = t["ttl"]
            addy = t["addr"] -- undocumented in Suricata Lua function docs

            rstring = rstring .. pairnames .. "\nADDRESS:\n" .. HexDump(addy)
            rcount = rcount + 1
        end
        if rcount > 0 then
            if dns_auth then
                for n, t in pairs(dns_auth) do
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
        outstring = outstring .. "DNS_QUERY_DUMP, " .. tostring(dalton.dns_query_count(dns_query)) .. "\n\n"

        for n, t in pairs(dns_query) do
            rrname = t["rrname"]
            rrtype = t["type"]
            outstring = outstring .. pairnames .. "REQUEST:" .. rrname .. ":" .. rrtype .. "\n"
            if dalton.dns_recursion_desired() then
                outstring = outstring .. "Recursion Desired\n"
            else
                outstring = outstring .. "No Recursion\n"
            end
        end
    end

    outstring = outstring .. "\n"

    if file then
        file:write (outstring)
        file:flush()
    end

    dns_count = dns_count + 1
end

function deinit (args)
    dalton.info ("DNS transactions logged: " .. dns_count)
    if file then
        file:close()
        file = nil
    end
end
