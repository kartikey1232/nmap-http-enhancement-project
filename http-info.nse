local http = require "http"
local shortport = require "shortport"

description = [[
Retrieves basic HTTP response information,
including the status code and selected headers.
]]

author = "Kartikey Chamoli"
license = "Same as Nmap"
categories = {"discovery", "safe"}

portrule = shortport.http

action = function(host, port)
    local response = http.get(host, port, "/")

    if not response then
        return "Failed to retrieve HTTP response"
    end

    local output = {}

    output[#output + 1] = "HTTP Information"
    output[#output + 1] = "Status: " .. tostring(response.status)

    local server = response.header["server"]
    local content_type = response.header["content-type"]
    local content_length = response.header["content-length"]

    if server then
        output[#output + 1] = "Server: " .. server
    end

    if content_type then
        output[#output + 1] = "Content-Type: " .. content_type
    end

    if content_length then
        output[#output + 1] = "Content-Length: " .. content_length
    end

    return table.concat(output, "\n")
end
