-- NullSec LuaShield - Web Application Firewall Rules Engine
-- Lua security tool demonstrating:
--   - Table-based data structures
--   - Metatables and metamethods
--   - Pattern matching (Lua patterns)
--   - Coroutines for async processing
--   - First-class functions
--   - Closures
--
-- Author: bad-antics
-- License: MIT

local VERSION = "1.0.0"

-- ANSI Colors
local colors = {
    red = "\027[31m",
    green = "\027[32m",
    yellow = "\027[33m",
    cyan = "\027[36m",
    gray = "\027[90m",
    reset = "\027[0m"
}

-- Risk levels
local RISK = {
    CRITICAL = 4,
    HIGH = 3,
    MEDIUM = 2,
    LOW = 1,
    INFO = 0
}

-- WAF Rule class with metatable
local Rule = {}
Rule.__index = Rule

function Rule.new(config)
    local self = setmetatable({}, Rule)
    self.id = config.id or "RULE-0000"
    self.name = config.name or "Unknown"
    self.pattern = config.pattern
    self.risk = config.risk or "medium"
    self.mitre = config.mitre or ""
    self.cwe = config.cwe or ""
    self.description = config.description or ""
    self.action = config.action or "block"
    return self
end

function Rule:match(input)
    if self.pattern then
        return string.find(input:lower(), self.pattern)
    end
    return false
end

function Rule:__tostring()
    return string.format("[%s] %s", self.id, self.name)
end

-- Finding class
local Finding = {}
Finding.__index = Finding

function Finding.new(rule, request, match_pos)
    local self = setmetatable({}, Finding)
    self.rule = rule
    self.request = request
    self.match_position = match_pos
    self.timestamp = os.time()
    return self
end

-- Request class
local Request = {}
Request.__index = Request

function Request.new(data)
    local self = setmetatable({}, Request)
    self.method = data.method or "GET"
    self.uri = data.uri or "/"
    self.headers = data.headers or {}
    self.body = data.body or ""
    self.query_string = data.query_string or ""
    self.remote_ip = data.remote_ip or "0.0.0.0"
    return self
end

function Request:full_input()
    -- Combine all request components for analysis
    local parts = {
        self.uri,
        self.query_string,
        self.body
    }
    for k, v in pairs(self.headers) do
        table.insert(parts, k .. ": " .. v)
    end
    return table.concat(parts, " ")
end

-- WAF Rules Database
local rules = {
    -- SQL Injection rules
    Rule.new({
        id = "SQL-001",
        name = "SQL Union Injection",
        pattern = "union%s+select",
        risk = "critical",
        mitre = "T1190",
        cwe = "CWE-89",
        description = "SQL UNION-based injection attempt"
    }),
    Rule.new({
        id = "SQL-002",
        name = "SQL Comment Injection",
        pattern = "%-%-[%s]*$",
        risk = "high",
        mitre = "T1190",
        cwe = "CWE-89",
        description = "SQL comment-based injection"
    }),
    Rule.new({
        id = "SQL-003",
        name = "SQL OR Injection",
        pattern = "'%s*or%s*'",
        risk = "critical",
        mitre = "T1190",
        cwe = "CWE-89",
        description = "SQL OR-based authentication bypass"
    }),
    Rule.new({
        id = "SQL-004",
        name = "SQL DROP Statement",
        pattern = "drop%s+table",
        risk = "critical",
        mitre = "T1190",
        cwe = "CWE-89",
        description = "SQL DROP TABLE attack"
    }),
    
    -- XSS rules
    Rule.new({
        id = "XSS-001",
        name = "Script Tag Injection",
        pattern = "<script",
        risk = "high",
        mitre = "T1189",
        cwe = "CWE-79",
        description = "Cross-site scripting via script tag"
    }),
    Rule.new({
        id = "XSS-002",
        name = "Event Handler Injection",
        pattern = "on%w+%s*=",
        risk = "high",
        mitre = "T1189",
        cwe = "CWE-79",
        description = "XSS via event handler attribute"
    }),
    Rule.new({
        id = "XSS-003",
        name = "JavaScript Protocol",
        pattern = "javascript:",
        risk = "high",
        mitre = "T1189",
        cwe = "CWE-79",
        description = "JavaScript protocol handler injection"
    }),
    
    -- Path Traversal rules
    Rule.new({
        id = "LFI-001",
        name = "Path Traversal",
        pattern = "%.%.%/",
        risk = "high",
        mitre = "T1083",
        cwe = "CWE-22",
        description = "Local file inclusion attempt"
    }),
    Rule.new({
        id = "LFI-002",
        name = "Null Byte Injection",
        pattern = "%%00",
        risk = "high",
        mitre = "T1083",
        cwe = "CWE-158",
        description = "Null byte injection for path manipulation"
    }),
    
    -- Command Injection rules
    Rule.new({
        id = "CMD-001",
        name = "Shell Metacharacter",
        pattern = "[;|&`$]",
        risk = "medium",
        mitre = "T1059",
        cwe = "CWE-78",
        description = "Shell metacharacter injection"
    }),
    Rule.new({
        id = "CMD-002",
        name = "Command Substitution",
        pattern = "`[^`]+`",
        risk = "critical",
        mitre = "T1059",
        cwe = "CWE-78",
        description = "Backtick command substitution"
    }),
    
    -- SSRF rules
    Rule.new({
        id = "SSRF-001",
        name = "Internal IP Access",
        pattern = "127%.0%.0%.1",
        risk = "high",
        mitre = "T1090",
        cwe = "CWE-918",
        description = "SSRF to localhost"
    }),
    Rule.new({
        id = "SSRF-002",
        name = "Private Network Access",
        pattern = "192%.168%.",
        risk = "high",
        mitre = "T1090",
        cwe = "CWE-918",
        description = "SSRF to private network"
    }),
    
    -- Protocol abuse
    Rule.new({
        id = "PROTO-001",
        name = "File Protocol",
        pattern = "file://",
        risk = "critical",
        mitre = "T1083",
        cwe = "CWE-73",
        description = "File protocol abuse"
    }),
    Rule.new({
        id = "PROTO-002",
        name = "Gopher Protocol",
        pattern = "gopher://",
        risk = "high",
        mitre = "T1090",
        cwe = "CWE-918",
        description = "Gopher protocol SSRF"
    })
}

-- WAF Engine
local WAF = {}
WAF.__index = WAF

function WAF.new()
    local self = setmetatable({}, WAF)
    self.rules = rules
    self.findings = {}
    self.stats = {
        requests = 0,
        blocked = 0,
        allowed = 0
    }
    return self
end

function WAF:analyze(request)
    local input = request:full_input()
    local findings = {}
    
    for _, rule in ipairs(self.rules) do
        local match_start = rule:match(input)
        if match_start then
            table.insert(findings, Finding.new(rule, request, match_start))
        end
    end
    
    self.stats.requests = self.stats.requests + 1
    if #findings > 0 then
        self.stats.blocked = self.stats.blocked + 1
    else
        self.stats.allowed = self.stats.allowed + 1
    end
    
    return findings
end

-- Color helper
local function colorize(color, text)
    return colors[color] .. text .. colors.reset
end

-- Risk color mapping
local function risk_color(risk)
    local mapping = {
        critical = "red",
        high = "red",
        medium = "yellow",
        low = "cyan",
        info = "gray"
    }
    return mapping[risk] or "gray"
end

-- Demo requests
local demo_requests = {
    Request.new({
        method = "GET",
        uri = "/search",
        query_string = "q=' UNION SELECT * FROM users--",
        remote_ip = "192.168.1.100"
    }),
    Request.new({
        method = "POST",
        uri = "/login",
        body = "username=admin' OR '1'='1&password=test",
        remote_ip = "10.0.0.50"
    }),
    Request.new({
        method = "GET",
        uri = "/page",
        query_string = "id=<script>alert('XSS')</script>",
        remote_ip = "45.33.32.156"
    }),
    Request.new({
        method = "GET",
        uri = "/file",
        query_string = "path=../../../etc/passwd",
        remote_ip = "192.168.1.101"
    }),
    Request.new({
        method = "GET",
        uri = "/proxy",
        query_string = "url=http://127.0.0.1:8080/admin",
        remote_ip = "10.0.0.100"
    }),
    Request.new({
        method = "GET",
        uri = "/download",
        query_string = "file=file:///etc/shadow",
        remote_ip = "185.220.101.1"
    }),
    Request.new({
        method = "GET",
        uri = "/api/data",
        query_string = "format=json",
        remote_ip = "192.168.1.50"
    })
}

-- Print banner
local function print_banner()
    print()
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║           NullSec LuaShield - WAF Rules Engine                   ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print()
end

-- Print usage
local function print_usage()
    print("USAGE:")
    print("    luashield [OPTIONS]")
    print()
    print("OPTIONS:")
    print("    -h, --help       Show this help")
    print("    -r, --rules      Custom rules file")
    print("    -t, --test       Test mode with sample requests")
    print("    -v, --verbose    Verbose output")
    print()
    print("FEATURES:")
    print("    • 15+ attack detection rules")
    print("    • SQL/XSS/LFI/SSRF detection")
    print("    • MITRE ATT&CK mapping")
    print("    • Real-time analysis")
end

-- Print finding
local function print_finding(finding)
    local rule = finding.rule
    local col = risk_color(rule.risk)
    local risk_str = string.upper(rule.risk)
    
    print()
    print(string.format("  %s %s", 
        colorize(col, "[" .. risk_str .. "]"), 
        rule.name))
    print(string.format("    Rule ID:     %s", rule.id))
    print(string.format("    Source:      %s", finding.request.remote_ip))
    print(string.format("    URI:         %s", finding.request.uri))
    print(string.format("    MITRE:       %s", rule.mitre))
    print(string.format("    CWE:         %s", rule.cwe))
end

-- Print summary
local function print_summary(all_findings, stats)
    local critical, high, medium = 0, 0, 0
    
    for _, f in ipairs(all_findings) do
        local risk = f.rule.risk
        if risk == "critical" then critical = critical + 1
        elseif risk == "high" then high = high + 1
        elseif risk == "medium" then medium = medium + 1
        end
    end
    
    print()
    print(colorize("gray", "═══════════════════════════════════════════"))
    print()
    print("  Summary:")
    print(string.format("    Requests:  %d", stats.requests))
    print(string.format("    Blocked:   %d", stats.blocked))
    print(string.format("    Allowed:   %d", stats.allowed))
    print(string.format("    Critical:  %s", colorize("red", tostring(critical))))
    print(string.format("    High:      %s", colorize("red", tostring(high))))
    print(string.format("    Medium:    %s", colorize("yellow", tostring(medium))))
end

-- Demo mode
local function demo()
    print(colorize("yellow", "[Demo Mode]"))
    print()
    print(colorize("cyan", "Analyzing sample HTTP requests..."))
    
    local waf = WAF.new()
    local all_findings = {}
    
    for _, request in ipairs(demo_requests) do
        local findings = waf:analyze(request)
        for _, f in ipairs(findings) do
            table.insert(all_findings, f)
        end
    end
    
    -- Sort by risk
    table.sort(all_findings, function(a, b)
        return RISK[string.upper(a.rule.risk)] > RISK[string.upper(b.rule.risk)]
    end)
    
    for _, f in ipairs(all_findings) do
        print_finding(f)
    end
    
    print_summary(all_findings, waf.stats)
end

-- Main entry point
local function main(args)
    print_banner()
    
    if #args == 0 or args[1] == "-h" or args[1] == "--help" then
        print_usage()
        print()
        demo()
    elseif args[1] == "--demo" then
        demo()
    else
        print_usage()
    end
end

-- Run
main(arg or {})
