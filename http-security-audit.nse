local http = require "http"
local shortport = require "shortport"

description = [[
Audits selected HTTP security headers,
evaluates basic configuration rules, and
provides remediation recommendations.
]]

author = "Kartikey Chamoli"
license = "Same as Nmap"
categories = {"discovery", "safe"}

portrule = shortport.http


-- Retrieve a header value.
local function getHeaderValue(response, headerName)
    return response.header[headerName]
end


-- Validate Strict-Transport-Security.
local function validateHSTS(value)
    if not value then
        return false, "Header is missing"
    end

    local max_age = value:match("[Mm][Aa][Xx]%-[Aa][Gg][Ee]%s*=%s*(%d+)")

    if not max_age then
        return false, "max-age directive is missing or invalid"
    end

    if tonumber(max_age) <= 0 then
        return false, "max-age must be greater than zero"
    end

    return true, "A positive max-age directive is present"
end


-- Validate Content-Security-Policy.
local function validateCSP(value)
    if not value then
        return false, "Header is missing"
    end

    if value:match("^%s*$") then
        return false, "Header value is empty"
    end

    if value:lower():match("default%-src%s+[^;]*'unsafe%-eval'") then
        return false, "default-src contains unsafe-eval"
    end

    return true, "Basic checks passed; policy requires deeper review"
end


-- Validate X-Frame-Options.
local function validateXFrameOptions(value)
    if not value then
        return false, "Header is missing"
    end

    local normalized = value:upper():match("^%s*(.-)%s*$")

    if normalized == "DENY" or normalized == "SAMEORIGIN" then
        return true, "Recognized framing restriction"
    end

    return false, "Unrecognized or insecure configuration"
end


-- Validate X-Content-Type-Options.
local function validateXContentTypeOptions(value)
    if not value then
        return false, "Header is missing"
    end

    if value:lower():match("^%s*nosniff%s*$") then
        return true, "nosniff is configured"
    end

    return false, "Expected nosniff"
end


-- Validate Referrer-Policy.
local function validateReferrerPolicy(value)
    if not value then
        return false, "Header is missing"
    end

    local normalized = value:lower():match("^%s*(.-)%s*$")

    local accepted = {
        ["no-referrer"] = true,
        ["no-referrer-when-downgrade"] = true,
        ["origin"] = true,
        ["origin-when-cross-origin"] = true,
        ["same-origin"] = true,
        ["strict-origin"] = true,
        ["strict-origin-when-cross-origin"] = true,
    }

    if accepted[normalized] then
        return true, "Recognized policy"
    end

    return false, "Unrecognized or unsupported policy"
end


-- Data-driven security-check definitions.
local securityChecks = {
    {
        header = "strict-transport-security",
        name = "Strict-Transport-Security",
        severity = "High",
        recommendation = "Configure HSTS with an appropriate max-age.",
        validator = validateHSTS,
    },
    {
        header = "content-security-policy",
        name = "Content-Security-Policy",
        severity = "High",
        recommendation = "Define a restrictive Content Security Policy.",
        validator = validateCSP,
    },
    {
        header = "x-frame-options",
        name = "X-Frame-Options",
        severity = "Medium",
        recommendation = "Configure DENY or SAMEORIGIN if appropriate.",
        validator = validateXFrameOptions,
    },
    {
        header = "x-content-type-options",
        name = "X-Content-Type-Options",
        severity = "Medium",
        recommendation = "Configure X-Content-Type-Options: nosniff.",
        validator = validateXContentTypeOptions,
    },
    {
        header = "referrer-policy",
        name = "Referrer-Policy",
        severity = "Low",
        recommendation = "Choose a policy that limits unnecessary referrer disclosure.",
        validator = validateReferrerPolicy,
    },
}


-- Audit all configured security headers.
local function auditHeaders(response)
    local results = {}
    local score = 0

    for _, check in ipairs(securityChecks) do
        local value = getHeaderValue(response, check.header)
        local passed, reason = check.validator(value)

        if passed then
            score = score + 1
        end

        results[#results + 1] = {
            name = check.name,
            severity = check.severity,
            present = value ~= nil,
            passed = passed,
            reason = reason,
            recommendation = check.recommendation,
        }
    end

    return results, score
end


-- Build the human-readable report.
local function buildReport(results, score)
    local output = {
        "HTTP Security Audit",
        "===================",
        "",
    }

    for _, result in ipairs(results) do
        local status = result.passed and "PASS" or "FAIL"

        output[#output + 1] = string.format(
            "[%s] %s",
            status,
            result.name
        )

        output[#output + 1] = "  Severity: " .. result.severity
        output[#output + 1] = "  Present: " .. tostring(result.present)
        output[#output + 1] = "  Reason: " .. result.reason

        if not result.passed then
            output[#output + 1] =
                "  Recommendation: " .. result.recommendation
        end

        output[#output + 1] = ""
    end

    output[#output + 1] = string.format(
        "Score: %d/%d",
        score,
        #results
    )

    return table.concat(output, "\n")
end


-- NSE entry point.
action = function(host, port)
    local response = http.get(host, port, "/")

    if not response then
        return "HTTP Security Audit: Unable to retrieve HTTP response"
    end

    local results, score = auditHeaders(response)

    return buildReport(results, score)
end
