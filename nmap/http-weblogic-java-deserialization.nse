local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local comm = require "comm"
local vulns = require "vulns"

description = [[
Java Deserialization vulnerability scanner for Oracle WebLogic Server.

Detects vulnerabilities in versions 12c and older.
]]

author = "Kendrick Lam"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "vuln"}

---
-- @usage
-- nmap -sV --script http-weblogic-java-deserialization <host>
--
-- @output
-- PORT	STATE SERVICE
-- 7001/tcp open  afs3-callback syn-ack ttl 128
-- | http-weblogic-java-deserialization: 
-- |   VULNERABLE:
-- |   Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components).
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2018-2628
-- |     Risk factor: High  CVSS: 10.0 (HIGH)
-- |       Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.2 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).
-- |     Disclosure date: 2017-12-15
-- |     References:
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-2628
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=2018-2628
-- |       https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/#exploitdev
-- |_      https://www.rapid7.com/db/vulnerabilities/oracle-weblogic-cve-2018-2628

portrule = function(host, port)
	return (port.number == 7001 or port.service == "afs3-callback" or port.service == "http" or port.version.product == "Oracle WebLogic admin httpd" or port.service == "http-proxy" or port.number == 5432 ) and port.state == "open"
end


local function check_vulns(opts)
	local vuln = opts.vuln
	local data = string.format("t3 12.2.1\nAS:255\nHL:19\nMS:10000000\nPU:t3://us-l-breens:%s\n\n", opts.port.number)
	local output = stdnse.output_table()
	local socket, response = comm.exchange(opts.host.ip, opts.port.number, data)
	if string.find(response, "HELO") then 
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
			title = 'Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components).',
			IDS = {CVE = 'CVE-2018-2628'},
			risk_factor = "High",
			scores = {
				CVSS = "10.0 (HIGH)",
			},
			description = [[Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.2 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).]],
			references = {
				'https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/#exploitdev',
				'https://www.rapid7.com/db/vulnerabilities/oracle-weblogic-cve-2018-2628',
				'https://cve.mitre.org/cgi-bin/cvename.cgi?name=2018-2628'},
				dates = {
					disclosure = {year = 2017, month = 12, day = 15},
				},
			}
		}
		local report = vulns.Report:new(SCRIPT_NAME, host, port)

		local status, err = check_vulns(opts)
		if not status then
			stdnse.debug1("%s", err)
			return nil
		end
		return report:make_output(opts.vuln)
	end

