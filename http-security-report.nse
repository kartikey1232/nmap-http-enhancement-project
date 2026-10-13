local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enhancement option 2 -- Structured HTTP security-header reporting.

Builds on the same HTTP foundation as the reference script
(http-info.nse) and the enhancement-1 audit (http-security-audit.nse),
but instead of a flat PASS/FAIL list it produces a STRUCTURED report:

  * a Summary section (headers checked, how many passed, how many
    failed, how many were missing, and an overall posture label);
  * Findings grouped by severity (High, Medium, Low), each listing the
    header, its PASS/FAIL status, whether it was present, and the
    reason;
  * a Recommendations section listing remediation only for the headers
    that failed.

The report is returned through stdnse.output_table(), so the same data
renders as readable text in normal output and as nested
<table>/<elem> elements in XML output (-oX). Missing headers are
reported explicitly rather than skipped.

This script only inspects HTTP response headers already returned by the
server. It performs no exploitation and makes no claim that a server is
vulnerable; a FAIL means a recommended hardening header is absent or
misconfigured and should be reviewed.

Intended for use only against localhost or an explicitly authorised
target.
]]

---
-- @usage
-- nmap -p 80 --script ./http-security-report.nse <target>
--
-- @args http-security-report.path  Path to request when auditing
--       headers. Defaults to "/".
--
-- @output
-- | http-security-report:
-- |   Summary:
-- |     headers_checked: 5
-- |     passed: 2
-- |     failed: 3
-- |     missing: 3
-- |     posture: Needs attention (2/5 recommended headers in place)
-- |   High:
-- |     Strict-Transport-Security: FAIL (present=false) -- Header is missing
-- |     Content-Security-Policy: PASS (present=true) -- Basic checks passed
-- |   ...
--
-- @author Kartikey Chamoli
-- @license Same as Nmap

author = "Kartikey Chamoli"
license = "Same as Nmap"
categories = {"discovery", "safe"}

portrule = shortport.http


-- ---- Validators (shared logic with the enhancement-1 audit) ----

local function validateHSTS(value)
    if not value then return false, "Header is missing" end
    local max_age = value:match("[Mm][Aa][Xx]%-[Aa][Gg][Ee]%s*=%s*(%d+)")
    if not max_age then
        return false, "max-age directive is missing or invalid"
    end
    if tonumber(max_age) <= 0 then
        return false, "max-age must be greater than zero"
    end
    return true, "A positive max-age directive is present"
end

local function validateCSP(value)
    if not value then return false, "Header is missing" end
    if value:match("^%s*$") then return false, "Header value is empty" end
    if value:lower():match("default%-src%s+[^;]*'unsafe%-eval'") then
        return false, "default-src contains unsafe-eval"
    end
    return true, "Basic checks passed; policy requires deeper review"
end

local function validateXFrameOptions(value)
    if not value then return false, "Header is missing" end
    local normalized = value:upper():match("^%s*(.-)%s*$")
    if normalized == "DENY" or normalized == "SAMEORIGIN" then
        return true, "Recognized framing restriction"
    end
    return false, "Unrecognized or insecure configuration"
end

local function validateXContentTypeOptions(value)
    if not value then return false, "Header is missing" end
    if value:lower():match("^%s*nosniff%s*$") then
        return true, "nosniff is configured"
    end
    return false, "Expected nosniff"
end

local function validateReferrerPolicy(value)
    if not value then return false, "Header is missing" end
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
    if accepted[normalized] then return true, "Recognized policy" end
    return false, "Unrecognized or unsupported policy"
end


-- Data-driven security-check definitions.
local securityChecks = {
    { header = "strict-transport-security", name = "Strict-Transport-Security",
      severity = "High", recommendation = "Configure HSTS with an appropriate max-age.",
      validator = validateHSTS },
    { header = "content-security-policy", name = "Content-Security-Policy",
      severity = "High", recommendation = "Define a restrictive Content Security Policy.",
      validator = validateCSP },
    { header = "x-frame-options", name = "X-Frame-Options",
      severity = "Medium", recommendation = "Configure DENY or SAMEORIGIN if appropriate.",
      validator = validateXFrameOptions },
    { header = "x-content-type-options", name = "X-Content-Type-Options",
      severity = "Medium", recommendation = "Configure X-Content-Type-Options: nosniff.",
      validator = validateXContentTypeOptions },
    { header = "referrer-policy", name = "Referrer-Policy",
      severity = "Low", recommendation = "Choose a policy that limits unnecessary referrer disclosure.",
      validator = validateReferrerPolicy },
}

local SEVERITY_ORDER = { "High", "Medium", "Low" }


-- Run every check against the response.
local function auditHeaders(response)
    local results = {}
    local passed, missing = 0, 0
    for _, check in ipairs(securityChecks) do
        local value = response.header[check.header]
        local ok, reason = check.validator(value)
        if ok then passed = passed + 1 end
        if value == nil then missing = missing + 1 end
        results[#results + 1] = {
            name = check.name,
            severity = check.severity,
            present = value ~= nil,
            passed = ok,
            reason = reason,
            recommendation = check.recommendation,
        }
    end
    return results, passed, missing
end


action = function(host, port)
    local path = stdnse.get_script_args("http-security-report.path") or "/"
    local response = http.get(host, port, path)

    if not response then
        return "http-security-report: unable to retrieve HTTP response from " .. path
    end

    local results, passed, missing = auditHeaders(response)
    local total = #results
    local failed = total - passed

    local posture
    if passed == total then
        posture = string.format("Good (%d/%d recommended headers in place)", passed, total)
    elseif passed == 0 then
        posture = string.format("Poor (0/%d recommended headers in place)", total)
    else
        posture = string.format("Needs attention (%d/%d recommended headers in place)", passed, total)
    end

    local out = stdnse.output_table()

    local summary = stdnse.output_table()
    summary.headers_checked = total
    summary.passed = passed
    summary.failed = failed
    summary.missing = missing
    summary.posture = posture
    out.Summary = summary

    -- Group findings by severity, preserving a stable order.
    for _, sev in ipairs(SEVERITY_ORDER) do
        local bucket = stdnse.output_table()
        local any = false
        for _, r in ipairs(results) do
            if r.severity == sev then
                any = true
                bucket[r.name] = string.format("%s (present=%s) -- %s",
                    r.passed and "PASS" or "FAIL", tostring(r.present), r.reason)
            end
        end
        if any then out[sev] = bucket end
    end

    -- Recommendations only for failed checks.
    local recs = stdnse.output_table()
    local any_rec = false
    for _, r in ipairs(results) do
        if not r.passed then
            any_rec = true
            recs[r.name] = r.recommendation
        end
    end
    if any_rec then
        out.Recommendations = recs
    else
        out.Recommendations = "All recommended headers passed basic checks."
    end

    stdnse.debug1("http-security-report: %d/%d passed, %d missing", passed, total, missing)
    return out
end
