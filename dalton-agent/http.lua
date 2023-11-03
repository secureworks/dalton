function init (args)
    local needs = {}
    needs["protocol"] = "http"
    needs["filter"] = "alerts"
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
        s.output = s.output .. string.format("|%-16s|", chunk:gsub('[^\32-\126]','.')) .. "\n"
    end
    return s.output
end

function log(args)
    SCLogNotice("Pulling HTTP buffers");

    http_req_line = HttpGetRequestLine()
    http_raw_uri = HttpGetRequestUriRaw()
	http_req_headers = HttpGetRawRequestHeaders()
	http_resp_headers = HttpGetRawResponseHeaders()
	http_req_body, o, e = HttpGetRequestBody()
	http_resp_body, o, e = HttpGetResponseBody()
	http_uri = HttpGetRequestUriNormalized()
    http_ua = HttpGetRequestHeader("User-Agent")
    http_cookie = HttpGetRequestHeader("Cookie")

    timestring = SCPacketTimeString()
    ip_version, src_ip, dst_ip, protocol, src_port, dst_port = SCFlowTuple()

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
        outstring = outstring .. "REQ_BODY_DUMP, " .. tostring(string.len(http_req_body[1])) .. "\n\n"
		outstring = outstring .. HexDump(http_req_body[1]) .. "\n"
    end

	if http_resp_body then
        outstring = outstring .. "RESP_BODY_DUMP, " .. tostring(string.len(http_resp_body[1])) .. "\n\n"
		outstring = outstring .. HexDump(http_resp_body[1]) .. "\n"
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

    file:write (outstring)
    --SCLogNotice("Output to file: ".. outstring)
    file:flush()

    http = http + 1
end

function deinit (args)
    SCLogInfo ("HTTP transactions logged: " .. http);
    file:close(file)
end
