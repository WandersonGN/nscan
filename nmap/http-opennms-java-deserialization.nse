local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local comm = require "comm"
local vulns = require "vulns"

description = [[
Java Deserialization vulnerability scanner for OpeNMS webserver.

Detects vulnerabilities in versions prior to version 18.
]]

author = "Kendrick Lam"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "vuln"}

---
-- @usage
-- nmap -sV --script http-opennms-java-deserialization <host>
--
-- @output
-- 1099/tcp open  rmiregistry
-- | http-opennms-java-deserialization: 
-- |   VULNERABLE:
-- |   OpenNMS Java Object Unserialization Remote Code Execution
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2015-8103
-- |     Risk factor: High  CVSS: 10.0 (HIGH)
-- |       There is a vulnerability in the OpenNMS Java object which allows an unauthenticated attacker to run arbitrary code against the system. 
-- |     Disclosure date: 2015-11-9
-- |     References:
-- |       https://www.rapid7.com/db/modules/exploit/linux/misc/opennms_java_serialize
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8103
-- |_       a vulnerability in the OpenNMS Java object which allows an unauthenticated attacker to run arbitrary code against the system. 
--


portrule = function(host, port)
	return (port.number == 1099 or port.service == "rmiregistry" or port.version.product == "Java RMI") and port.state == "open"
end

local function check_vuln(opts)
	local vuln = opts.vuln
	local data = string.format("\x4a\x52\x4d\x49\x00\x02\x4b\x00\x00\x00\x00\x00\x00")
	local output = stdnse.output_table()
	local socket, response = comm.exchange(opts.host.ip, opts.port.number, data)
	if string.find(response, "N\x00\x0e") then
		vuln.state = vulns.STATE.VULN
		return true
	end
	vuln.state = vulns.STATE.NOT_VULN
	return false
end

action = function(host, port)
	local opts = {
		host = host,
		port = port,
		vuln = {
			title = 'OpenNMS Java Object Unserialization Remote Code Execution',
			IDS = {CVE = 'CVE-2015-8103'},
			risk_factor = "High",
			scores = {
				CVSS = "10.0 (HIGH)",
			},
			description = [[There is a vulnerability in the OpenNMS Java object which allows an unauthenticated attacker to run arbitrary code against the system. ]],
			references = {
				'https://www.rapid7.com/db/modules/exploit/linux/misc/opennms_java_serialize',
				' a vulnerability in the OpenNMS Java object which allows an unauthenticated attacker to run arbitrary code against the system. '},
				dates = {
					disclosure = {year = 2015, month = 11, day = 09},
				},
			}
		}
		local report = vulns.Report:new(SCRIPT_NAME, host, port)

		local status, err = check_vuln(opts)
		if not status then
			stdnse.debug1("%s", err)
			return nil
		end
		return report:make_output(opts.vuln)
	end
