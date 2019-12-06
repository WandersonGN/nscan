local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local comm = require "comm"
local vulns = require "vulns"

description = [[
Java Deserialization vulnerability scanner for Jenkins webserver.

Detects vulnerabilities in versions prior to 1.638 and 1.625.2.
]]

author = "Kendrick Lam"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "vuln"}

---
-- @usage
-- nmap -sV --script http-jenkins-java-deserialization <host>
--
-- @output
-- PORT     STATE SERVICE
-- 8080/tcp open  http-proxy
-- | http-jenkins-java-deserialization: 
-- |   VULNERABLE:
-- |   Jenkins CLI HTTP Java Deserialization Vulnerability
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2016-9299
-- |     Risk factor: High
-- |       The remoting module in Jenkins before 2.32 and LTS before 2.19.3 allows remote attackers to execute arbitrary code via a crafted serialized Java object, which triggers an LDAP query to a third-party server.
-- |     Disclosure date: 2016-11-14
-- |     References:
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-9299
-- |       https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/#jenkins
-- |_      https://nvd.nist.gov/vuln/detail/CVE-2016-9299
--

portrule = function (host, port)
	return (port.number == 8080 or port.service == "http" or port.service == "http-proxy" or port.version.product == "Jetty") and port.state == "open"
end

-- Checks for vuln
local function check_vuln(opts)
	local vuln = opts.vuln
	local header = "\x00\x14\x50\x72\x6F\x74\x6F\x63\x6F\x6C\x3A\x43\x4C\x49\x2D\x63\x6F\x6E\x6E\x65\x63\x74"
	-- Replicate Jenkins CLI request
	local data = string.format(
	"GET / HTTP/1.1\n"  .. 
	"Host: %s:%s\n" ..
	"User Agent: Java/1.8.0_45-internal\n" ..
	"Content-Length: 164\n\n" ..
	"Cookie: JSESSIONID.538d6690=node01d0507a13952daqv1qyjkjqk18.node0; JSESSIONID.4c8cbccd=tf2hgf07w6ei8ynx6zsillrp; screenResolution=1920x1019 \n" ..
	"Connection: close", opts.host.ip, opts.port.number)
	local output = stdnse.output_table()
	local socket, response = comm.exchange(opts.host.ip, opts.port.number, data)
	-- Check if target responds with Jenkins CLI header
	if string.match(response, "X%-%Jenkins%-%CLI%-%Port: %d*" ) ~= nil then
		i = string.match(response, "X%-%Jenkins%-%CLI%-%Port: %d*" )
		local cli_port = string.match(i, "%d+")
		local sock, resp = comm.exchange(opts.host.ip, cli_port, header, {lines=2})
		-- Check response for Serialized Header
		if string.find(resp, "rO0AB") then
			vuln.state = vulns.STATE.VULN
			return true
		end
		vuln.state = vulns.STATE.NOT_VULN
		return false
	end
end
action = function(host, port)
	local opts = {
		host = host,
		port = port,
		vuln = {
			title = 'Jenkins CLI HTTP Java Deserialization Vulnerability',
			IDS = {CVE = 'CVE-2016-9299'},
			risk_factor = "High",
			description = [[The remoting module in Jenkins before 2.32 and LTS before 2.19.3 allows remote attackers to execute arbitrary code via a crafted serialized Java object, which triggers an LDAP query to a third-party server.]],
			references = {
				'https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/#jenkins',
				'https://nvd.nist.gov/vuln/detail/CVE-2016-9299'},
				dates = {
					disclosure = {year = 2016, month = 11, day = 14},
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

