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
    needs["protocol"] = "tls"
    needs["filter"] = "alerts"
    return needs
end

local LOG_NAME = "dalton-tls-buffers.log"

function setup (args)
    file = nil
    tls_count = 0
end

function ensure_file()
    if file == nil then
        file, err = dalton.open_log(LOG_NAME)
        if file then
            dalton.info("TLS OPENED Log Filename " .. dalton.log_path() .. "/" .. LOG_NAME)
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
    dalton.notice("Pulling TLS buffers")
    ensure_file()

    if dalton.suri8 then
        local tx, err = require("suricata.tls").get_tx()
        if not dalton.is_tx(tx) then
            dalton.notice("TLS log skipped: " .. tostring(err or tx))
            return
        end
    end

    tls_sni = dalton.tls_sni()
    tls_version, tls_subject, tls_issuer, tls_fingerprint = dalton.tls_cert_info()

    ip_version, src_ip, dst_ip, protocol, src_port, dst_port = dalton.flow_tuple()
    timestring = dalton.packet_timestring()

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

    if file then
        file:write (outstring)
        file:flush()
    end

    tls_count = tls_count + 1
end

function deinit (args)
    dalton.info ("TLS transactions logged: " .. tls_count)
    if file then
        file:close()
        file = nil
    end
end
