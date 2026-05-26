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
    needs["protocol"] = "http"
    needs["filter"] = "alerts"
    return needs
end

local LOG_NAME = "dalton-http-buffers.log"

function setup (args)
    file = nil
    http_count = 0
end

function ensure_file()
    if file == nil then
        file, err = dalton.open_log(LOG_NAME)
        if file then
            dalton.info("HTTP OPENED Log Filename " .. dalton.log_path() .. "/" .. LOG_NAME)
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
    dalton.notice("Pulling HTTP buffers")
    ensure_file()

    if dalton.suri8 then
        local tx, err = require("suricata.http").get_tx()
        if not dalton.is_tx(tx) then
            dalton.notice("HTTP log skipped: " .. tostring(err or tx))
            return
        end
    end

    http_req_line = dalton.http_request_line()
    http_raw_uri = dalton.http_request_uri_raw()
    http_req_headers = dalton.http_request_headers_raw()
    http_resp_headers = dalton.http_response_headers_raw()
    http_req_body = dalton.http_request_body()
    http_resp_body = dalton.http_response_body()
    http_uri = dalton.http_request_uri_normalized()
    http_ua = dalton.http_request_header("User-Agent")
    http_cookie = dalton.http_request_header("Cookie")

    ip_version, src_ip, dst_ip, protocol, src_port, dst_port = dalton.flow_tuple()
    timestring = dalton.packet_timestring()

    outstring = "=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n\n"
    outstring = outstring .. "Raw Packet:\n"
    outstring = outstring .. timestring .. " " .. src_ip .. ":" .. src_port .. " -> " .. dst_ip .. ":" .. dst_port .. "\n\n"

    if http_req_line then
        outstring = outstring .. "REQ_LINE_DUMP, " .. tostring(string.len(http_req_line)) .. "\n\n"
        outstring = outstring .. HexDump(http_req_line) .. "\n"
    end

    if http_raw_uri then
        outstring = outstring .. "RAW_URI_DUMP, " .. tostring(string.len(http_raw_uri)) .. "\n\n"
        outstring = outstring .. HexDump(http_raw_uri) .. "\n"
    end

    if http_req_headers then
        outstring = outstring .. "REQ_HEADERS_DUMP, " .. tostring(string.len(http_req_headers)) .. "\n\n"
        outstring = outstring .. HexDump(http_req_headers) .. "\n"
    end

    if http_resp_headers then
        outstring = outstring .. "RESP_HEADERS_DUMP, " .. tostring(string.len(http_resp_headers)) .. "\n\n"
        outstring = outstring .. HexDump(http_resp_headers) .. "\n"
    end

    if http_req_body then
        outstring = outstring .. "REQ_BODY_DUMP, " .. tostring(string.len(http_req_body)) .. "\n\n"
        outstring = outstring .. HexDump(http_req_body) .. "\n"
    end

    if http_resp_body then
        outstring = outstring .. "RESP_BODY_DUMP, " .. tostring(string.len(http_resp_body)) .. "\n\n"
        outstring = outstring .. HexDump(http_resp_body) .. "\n"
    end

    if http_uri then
        outstring = outstring .. "URI_DUMP, " .. tostring(string.len(http_uri)) .. "\n\n"
        outstring = outstring .. HexDump(http_uri) .. "\n"
    end

    if http_ua then
        outstring = outstring .. "USER_AGENT_DUMP, " .. tostring(string.len(http_ua)) .. "\n\n"
        outstring = outstring .. HexDump(http_ua) .. "\n"
    end

    if http_cookie then
        outstring = outstring .. "COOKIE_DUMP, " .. tostring(string.len(http_cookie)) .. "\n\n"
        outstring = outstring .. HexDump(http_cookie) .. "\n"
    end

    if file then
        file:write (outstring)
        file:flush()
    end

    http_count = http_count + 1
end

function deinit (args)
    dalton.info ("HTTP transactions logged: " .. http_count)
    if file then
        file:close()
        file = nil
    end
end
