function init (args)
    local needs = {}
    needs["protocol"] = "http"
    return needs
end

function setup (args)
    filename = SCLogPath() .. "/" .. "httpluaoutput.txt"
    file, err = io.open(filename, "a")
    if file then
        SCLogInfo("HTTP OPENED Log Filename " .. filename)
        file:write("Initial data")
    else
        SCLogNotice("Error opening Lua log:" .. err)
    end
    http = 0
end

function log(args)
    SCLogNotice("Lua looking at packet and wrote test data...");
    file:write ("Something ANYTHING!");
    http_uri = HttpGetRequestUriRaw()
    if http_uri == nil then
        http_uri = "<unknown>"
    end
    http_uri = string.gsub(http_uri, "%c", ".")

    http_host = HttpGetRequestHost()
    if http_host == nil then
        http_host = "<hostname unknown>"
    end
    http_host = string.gsub(http_host, "%c", ".")

    http_ua = HttpGetRequestHeader("User-Agent")
    if http_ua == nil then
        http_ua = "<useragent unknown>"
    end
    http_ua = string.gsub(http_ua, "%g", ".")

    timestring = SCPacketTimeString()
    ip_version, src_ip, dst_ip, protocol, src_port, dst_port = SCFlowTuple()

    outstring = timestring .. " " .. http_host .. " [**] " .. http_uri .. " [**] " ..
    http_ua .. " [**] " .. src_ip .. ":" .. src_port .. " -> " ..
    dst_ip .. ":" .. dst_port .. "DC was here.\n"
    file:write (outstring)
    SCLogNotice("Output to file: ".. outstring)
    file:flush()

    http = http + 1
end

function deinit (args)
    SCLogNotice("File written to");
    SCLogInfo ("HTTP transactions logged: " .. http);
    file:close(file)
end