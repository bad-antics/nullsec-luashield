# NullSec LuaShield

**Web Application Firewall Rules Engine** written in Lua

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/bad-antics/nullsec-luashield/releases)
[![Language](https://img.shields.io/badge/language-Lua-blue.svg)](https://www.lua.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> Part of the **NullSec** offensive security toolkit  
> Twitter: [x.com/AnonAntics](https://x.com/AnonAntics)  
> Portal: [bad-antics.github.io](https://bad-antics.github.io)

## Overview

LuaShield is a lightweight WAF rules engine that detects web application attacks including SQL injection, XSS, path traversal, and SSRF. Built with Lua's powerful metatables and pattern matching, perfect for embedding in web servers like nginx/OpenResty.

## Lua Features Showcased

- **Metatables**: Object-oriented design patterns
- **Pattern Matching**: Lua-native regex alternative
- **Tables**: Flexible data structures
- **First-class Functions**: Functional programming
- **Closures**: State encapsulation
- **Metamethods**: `__index`, `__tostring` customization
- **Coroutines**: Async-ready architecture

## Attack Detection

| Category | Rule ID | Pattern | MITRE |
|----------|---------|---------|-------|
| SQL Injection | SQL-001 | UNION SELECT | T1190 |
| SQL Injection | SQL-002 | SQL Comments | T1190 |
| SQL Injection | SQL-003 | OR Bypass | T1190 |
| SQL Injection | SQL-004 | DROP TABLE | T1190 |
| XSS | XSS-001 | Script Tags | T1189 |
| XSS | XSS-002 | Event Handlers | T1189 |
| XSS | XSS-003 | javascript: | T1189 |
| Path Traversal | LFI-001 | ../ Traversal | T1083 |
| Path Traversal | LFI-002 | Null Byte | T1083 |
| Command Injection | CMD-001 | Shell Meta | T1059 |
| Command Injection | CMD-002 | Backticks | T1059 |
| SSRF | SSRF-001 | Localhost | T1090 |
| SSRF | SSRF-002 | Private Net | T1090 |
| Protocol | PROTO-001 | file:// | T1083 |
| Protocol | PROTO-002 | gopher:// | T1090 |

## Installation

```bash
# Clone
git clone https://github.com/bad-antics/nullsec-luashield.git
cd nullsec-luashield

# Run (requires Lua 5.3+)
lua luashield.lua
```

### OpenResty Integration

```lua
-- nginx.conf
access_by_lua_file /path/to/luashield.lua;
```

## Usage

```bash
# Run demo mode
lua luashield.lua --demo

# Show help
lua luashield.lua --help

# Test with custom rules
lua luashield.lua -r custom_rules.lua
```

### Options

```
USAGE:
    luashield [OPTIONS]

OPTIONS:
    -h, --help       Show help
    -r, --rules      Custom rules file
    -t, --test       Test mode with sample requests
    -v, --verbose    Verbose output
```

## Sample Output

```
╔══════════════════════════════════════════════════════════════════╗
║           NullSec LuaShield - WAF Rules Engine                   ║
╚══════════════════════════════════════════════════════════════════╝

[Demo Mode]

Analyzing sample HTTP requests...

  [CRITICAL] SQL Union Injection
    Rule ID:     SQL-001
    Source:      192.168.1.100
    URI:         /search
    MITRE:       T1190
    CWE:         CWE-89

  [CRITICAL] SQL OR Injection
    Rule ID:     SQL-003
    Source:      10.0.0.50
    URI:         /login
    MITRE:       T1190
    CWE:         CWE-89

  [CRITICAL] File Protocol
    Rule ID:     PROTO-001
    Source:      185.220.101.1
    URI:         /download
    MITRE:       T1083
    CWE:         CWE-73

═══════════════════════════════════════════

  Summary:
    Requests:  7
    Blocked:   6
    Allowed:   1
    Critical:  4
    High:      6
    Medium:    2
```

## Code Highlights

### Metatable-based Classes
```lua
local Rule = {}
Rule.__index = Rule

function Rule.new(config)
    local self = setmetatable({}, Rule)
    self.id = config.id or "RULE-0000"
    self.name = config.name
    self.pattern = config.pattern
    self.risk = config.risk
    return self
end

function Rule:match(input)
    return string.find(input:lower(), self.pattern)
end
```

### Request Object
```lua
local Request = {}
Request.__index = Request

function Request.new(data)
    local self = setmetatable({}, Request)
    self.method = data.method
    self.uri = data.uri
    self.headers = data.headers or {}
    self.body = data.body or ""
    return self
end

function Request:full_input()
    return table.concat({self.uri, self.query_string, self.body}, " ")
end
```

### WAF Engine
```lua
function WAF:analyze(request)
    local input = request:full_input()
    local findings = {}
    
    for _, rule in ipairs(self.rules) do
        if rule:match(input) then
            table.insert(findings, Finding.new(rule, request))
        end
    end
    
    return findings
end
```

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                    LuaShield Architecture                      │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│    │  Request    │───▶│   Parser    │───▶│   Request   │      │
│    │  (HTTP)     │    │             │    │   Object    │      │
│    └─────────────┘    └─────────────┘    └──────┬──────┘      │
│                                                  │             │
│                                                  ▼             │
│    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│    │   Action    │◀───│   Rules     │◀───│   WAF       │      │
│    │ (Block/Log) │    │   Engine    │    │   Engine    │      │
│    └─────────────┘    └─────────────┘    └─────────────┘      │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

## Why Lua?

| Requirement | Lua Advantage |
|-------------|---------------|
| Embeddable | nginx/OpenResty ready |
| Lightweight | ~200KB interpreter |
| Fast | LuaJIT performance |
| Flexible | Metatables for OOP |
| Pattern Matching | Built-in support |
| Scripting | Easy configuration |

## License

MIT License - See [LICENSE](LICENSE) for details.

## Related Tools

- [nullsec-shelltrace](https://github.com/bad-antics/nullsec-shelltrace) - Shell auditor (Tcl)
- [nullsec-tainttrack](https://github.com/bad-antics/nullsec-tainttrack) - Taint analysis (OCaml)
- [nullsec-certscan](https://github.com/bad-antics/nullsec-certscan) - TLS scanner (D)
