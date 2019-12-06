local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local vulns = require "vulns"

description = [[
Java Deserialization vulnerability scanner for JBoss webserver.

Detects vulnerabilities in versions prior to version 7.
]]

author = "Kendrick Lam"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "vuln"}

---
-- @usage 
-- nmap -sV --script http-jboss-java-deserialization <host>
--
-- @output
-- PORT     STATE SERVICE
-- 8080/tcp open  http-proxy
-- | http-jboss-java-deserialization: 
-- |   VULNERABLE:
-- |   Red Hat JBoss Java Deserialization vulnerability via JMXInvokerServlet/EJBInvokerServlet
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2015-7501
-- |     Risk factor: High  CVSS: 10.0 (HIGH)
-- |       Red Hat JBoss A-MQ 6.x; BPM Suite (BPMS) 6.x; BRMS 6.x and 5.x; Data Grid (JDG) 6.x; Data Virtualization (JDV) 6.x and 5.x; Enterprise Application Platform 6.x, 5.x, and 4.3.x; Fuse 6.x; Fuse Service Works (FSW) 6.x; Operations Network (JBoss ON) 3.x; Portal 6.x; SOA Platform (SOA-P) 5.x; Web Server (JWS) 3.x; Red Hat OpenShift/xPAAS 3.x; and Red Hat Subscription Asset Manager 1.3 allow remote attackers to execute arbitrary commands via a crafted serialized Java object, related to the Apache Commons Collections (ACC) library. 
-- |     Disclosure date: 2017-11-9
-- |     References:
-- |       https://www.cvedetails.com/cve/CVE-2015-7501/
-- |       https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/#jboss
-- |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7501
--

portrule = function(host, port)
	return (port.number == 8080 or port.service == "http" or port.service == "http-proxy" or port.version.product == "Apache Tomcat/Coyote JSP engine") and port.state == "open"
end

local function check_vuln(opts)
	local vuln = opts.vuln
	local url2 = '/invoker/JMXInvokerServlet'
	local res = http.get(opts.host, opts.port, url2)
	if string.find(res.body, "^\xAC\xED\x00\x05") then
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
			title = 'Red Hat JBoss Java Deserialization vulnerability via JMXInvokerServlet/EJBInvokerServlet',
			IDS = {CVE = 'CVE-2015-7501'},
			risk_factor = "High",
			scores = {
				CVSS = "10.0 (HIGH)",
			},
			description = [[Red Hat JBoss A-MQ 6.x; BPM Suite (BPMS) 6.x; BRMS 6.x and 5.x; Data Grid (JDG) 6.x; Data Virtualization (JDV) 6.x and 5.x; Enterprise Application Platform 6.x, 5.x, and 4.3.x; Fuse 6.x; Fuse Service Works (FSW) 6.x; Operations Network (JBoss ON) 3.x; Portal 6.x; SOA Platform (SOA-P) 5.x; Web Server (JWS) 3.x; Red Hat OpenShift/xPAAS 3.x; and Red Hat Subscription Asset Manager 1.3 allow remote attackers to execute arbitrary commands via a crafted serialized Java object, related to the Apache Commons Collections (ACC) library. ]],
			references = {
				'https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/#jboss',
				'https://www.cvedetails.com/cve/CVE-2015-7501/'},
				dates = {
					disclosure = {year = 2017, month = 11, day = 09},
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

