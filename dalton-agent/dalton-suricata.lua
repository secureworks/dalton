-- Compatibility helpers for Suricata 7 (legacy globals) and Suricata 8 (suricata.* libraries).
-- Suricata 8: https://docs.suricata.io/en/suricata-8.0.5/output/lua-output.html
-- Suricata 7: https://docs.suricata.io/en/suricata-7.0.2/lua/lua-functions.html

local M = {}

local suri8 = false
local config, logger, flow_mod, packet_mod

do
    local ok, cfg = pcall(require, "suricata.config")
    if ok then
        suri8 = true
        config = cfg
        logger = require("suricata.log")
        flow_mod = require("suricata.flow")
        packet_mod = require("suricata.packet")
    end
end

M.suri8 = suri8

function M.log_path()
    if suri8 then
        local path, err = config.log_path()
        if path == nil then
            M.notice("config.log_path() failed: " .. tostring(err))
            return nil
        end
        return path
    end
    return SCLogPath()
end

function M.is_tx(tx)
    return type(tx) == "userdata"
end

function M.open_log(name)
    local path = M.log_path()
    if path == nil then
        return nil, "no log path"
    end
    return io.open(path .. "/" .. name, "a")
end

function M.info(msg)
    if suri8 then
        logger.info(msg)
    else
        SCLogInfo(msg)
    end
end

function M.notice(msg)
    if suri8 then
        logger.notice(msg)
    else
        SCLogNotice(msg)
    end
end

function M.flow_tuple()
    if suri8 then
        local f = flow_mod.get()
        return f:tuple()
    end
    return SCFlowTuple()
end

function M.packet_timestring()
    if suri8 then
        local p = packet_mod.get()
        return p:timestring_legacy()
    end
    return SCPacketTimeString()
end

local function table_len(t)
    if t == nil then
        return 0
    end
    local n = 0
    for _ in pairs(t) do
        n = n + 1
    end
    return n
end

-- DNS -----------------------------------------------------------------------

local dns_mod

local function dns_tx()
    if not dns_mod then
        dns_mod = require("suricata.dns")
    end
    return dns_mod.get_tx()
end

function M.dns_queries()
    if suri8 then
        local tx = dns_tx()
        if tx == nil then
            return nil
        end
        return tx:queries()
    end
    return DnsGetQueries()
end

function M.dns_answers()
    if suri8 then
        local tx = dns_tx()
        if tx == nil then
            return nil
        end
        return tx:answers()
    end
    return DnsGetAnswers()
end

function M.dns_authorities()
    if suri8 then
        local tx = dns_tx()
        if tx == nil then
            return nil
        end
        return tx:authorities()
    end
    return DnsGetAuthorities()
end

function M.dns_recursion_desired()
    if suri8 then
        local tx = dns_tx()
        if tx == nil then
            return false
        end
        return tx:recursion_desired() == true
    end
    return DnsGetRecursionDesired() == true
end

function M.dns_query_count(queries)
    if suri8 then
        return table_len(queries)
    end
    if queries == nil then
        return 0
    end
    if table.maxn then
        return table.maxn(queries) + 1
    end
    return table_len(queries)
end

-- HTTP ----------------------------------------------------------------------

local http_mod

local function http_tx()
    if not http_mod then
        http_mod = require("suricata.http")
    end
    return http_mod.get_tx()
end

local function http_body_first(body)
    if body == nil then
        return nil
    end
    if type(body) == "table" then
        return body[1]
    end
    return body
end

function M.http_request_line()
    if suri8 then
        local tx = http_tx()
        if tx == nil then
            return nil
        end
        return tx:request_line()
    end
    return HttpGetRequestLine()
end

function M.http_request_uri_raw()
    if suri8 then
        local tx = http_tx()
        if tx == nil then
            return nil
        end
        return tx:request_uri_raw()
    end
    return HttpGetRequestUriRaw()
end

function M.http_request_headers_raw()
    if suri8 then
        local tx = http_tx()
        if tx == nil then
            return nil
        end
        return tx:request_headers_raw()
    end
    return HttpGetRawRequestHeaders()
end

function M.http_response_headers_raw()
    if suri8 then
        local tx = http_tx()
        if tx == nil then
            return nil
        end
        return tx:response_headers_raw()
    end
    return HttpGetRawResponseHeaders()
end

function M.http_request_body()
    if suri8 then
        local tx = http_tx()
        if tx == nil then
            return nil
        end
        return http_body_first(tx:request_body())
    end
    return http_body_first(HttpGetRequestBody())
end

function M.http_response_body()
    if suri8 then
        local tx = http_tx()
        if tx == nil then
            return nil
        end
        return http_body_first(tx:response_body())
    end
    return http_body_first(HttpGetResponseBody())
end

function M.http_request_uri_normalized()
    if suri8 then
        local tx = http_tx()
        if tx == nil then
            return nil
        end
        return tx:request_uri_normalized()
    end
    return HttpGetRequestUriNormalized()
end

function M.http_request_header(name)
    if suri8 then
        local tx = http_tx()
        if tx == nil then
            return nil
        end
        return tx:request_header(name)
    end
    return HttpGetRequestHeader(name)
end

-- TLS -----------------------------------------------------------------------

local tls_mod

local function tls_tx()
    if not tls_mod then
        tls_mod = require("suricata.tls")
    end
    return tls_mod.get_tx()
end

function M.tls_sni()
    if suri8 then
        local tx = tls_tx()
        if tx == nil then
            return nil
        end
        return tx:get_client_sni()
    end
    return TlsGetSNI()
end

function M.tls_cert_info()
    if suri8 then
        local tx = tls_tx()
        if tx == nil then
            return nil, nil, nil, nil
        end
        return tx:get_server_cert_info()
    end
    return TlsGetCertInfo()
end

return M
