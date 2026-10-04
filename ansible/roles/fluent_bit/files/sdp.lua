-- sdp.lua: the one filter every SIEM record passes before it leaves the host (ADR 0034, siem
-- contract P2). It projects each record onto the allow-list of its source (siem/fields/<source>.yaml,
-- rendered by the role into sdp_fields.lua), pseudonymises people and addresses with HMAC-SHA256
-- under a key that never leaves this host (F3), keeps only the audit events F2 allows, keeps only
-- Hubble flow records (F13), and sets the record time from the event's own time (Fluent Bit's
-- opensearch output writes it as @timestamp).
--
-- Fail closed: a missing or short key, a broken HMAC (known-answer test below) or an unknown
-- transform stops Fluent Bit at start-up; an error while handling one record drops that record.
-- Nothing is forwarded that was not built here field by field, so a client-sent event.overwrite or
-- event.ingested (F1) and every unlisted key are gone by construction.
--
-- Tags are sdp.<source>.<input>: "hb" is the per-stream heartbeat, "journal" journald, "auditd" the
-- audit log, "osaudit" the OpenSearch security audit log (siem01), "log" a file of JSON lines.

local bit = require("bit")
local band, bor, bxor, bnot = bit.band, bit.bor, bit.bxor, bit.bnot
local rshift, lshift, ror, tobit = bit.rshift, bit.lshift, bit.ror, bit.tobit
local sbyte, schar, srep, sfmt = string.byte, string.char, string.rep, string.format

-- SHA-256 (FIPS 180-4) on LuaJIT's 32-bit bit operations; additions wrap through tobit.
local K = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}
for i = 1, 64 do K[i] = tobit(K[i]) end
local H0 = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }
for i = 1, 8 do H0[i] = tobit(H0[i]) end

local function be32(n)
  return schar(band(rshift(n, 24), 255), band(rshift(n, 16), 255), band(rshift(n, 8), 255), band(n, 255))
end

local function sha256(msg)
  local len = #msg
  local bits = len * 8
  msg = msg .. "\128" .. srep("\0", (64 - (len + 9) % 64) % 64)
    .. be32(math.floor(bits / 4294967296)) .. be32(bits % 4294967296)
  local H = { H0[1], H0[2], H0[3], H0[4], H0[5], H0[6], H0[7], H0[8] }
  local w = {}
  for i = 1, #msg, 64 do
    for j = 1, 16 do
      local p = i + (j - 1) * 4
      local b1, b2, b3, b4 = sbyte(msg, p, p + 3)
      w[j] = bor(lshift(b1, 24), lshift(b2, 16), lshift(b3, 8), b4)
    end
    for j = 17, 64 do
      local v15, v2 = w[j - 15], w[j - 2]
      local s0 = bxor(ror(v15, 7), ror(v15, 18), rshift(v15, 3))
      local s1 = bxor(ror(v2, 17), ror(v2, 19), rshift(v2, 10))
      w[j] = tobit(w[j - 16] + s0 + w[j - 7] + s1)
    end
    local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
    for j = 1, 64 do
      local S1 = bxor(ror(e, 6), ror(e, 11), ror(e, 25))
      local ch = bxor(band(e, f), band(bnot(e), g))
      local t1 = tobit(h + S1 + ch + K[j] + w[j])
      local S0 = bxor(ror(a, 2), ror(a, 13), ror(a, 22))
      local maj = bxor(band(a, b), band(a, c), band(b, c))
      local t2 = tobit(S0 + maj)
      h, g, f, e, d, c, b, a = g, f, e, tobit(d + t1), c, b, a, tobit(t1 + t2)
    end
    H[1], H[2], H[3], H[4] = tobit(H[1] + a), tobit(H[2] + b), tobit(H[3] + c), tobit(H[4] + d)
    H[5], H[6], H[7], H[8] = tobit(H[5] + e), tobit(H[6] + f), tobit(H[7] + g), tobit(H[8] + h)
  end
  local out = {}
  for i = 1, 8 do out[i] = be32(H[i]) end
  return table.concat(out)
end

-- HMAC (RFC 2104) over SHA-256, block size 64.
local function hmac_sha256(key, msg)
  if #key > 64 then key = sha256(key) end
  key = key .. srep("\0", 64 - #key)
  local ipad, opad = {}, {}
  for i = 1, 64 do
    local k = sbyte(key, i)
    ipad[i] = schar(bxor(k, 0x36))
    opad[i] = schar(bxor(k, 0x5c))
  end
  return sha256(table.concat(opad) .. sha256(table.concat(ipad) .. msg))
end

local function tohex(s)
  return (s:gsub(".", function(c) return sfmt("%02x", sbyte(c)) end))
end

-- Known-answer test, RFC 4231 test case 2: a broken digest must never pseudonymise anything.
if tohex(hmac_sha256("Jefe", "what do ya want for nothing?"))
    ~= "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" then
  error("sdp.lua: HMAC-SHA256 known-answer test failed; refusing to start")
end

-- The host's pseudonym key: 32 random bytes made by the role, root-only, handed to the unit by
-- systemd's LoadCredential (readable only through $CREDENTIALS_DIRECTORY).
local function read_key()
  local dir = os.getenv("CREDENTIALS_DIRECTORY")
  if not dir or dir == "" then error("sdp.lua: CREDENTIALS_DIRECTORY is not set; refusing to start") end
  local f = io.open(dir .. "/hmac.key", "rb")
  if not f then error("sdp.lua: no hmac.key credential; refusing to start") end
  local k = f:read("*a")
  f:close()
  if not k or #k ~= 32 then error("sdp.lua: hmac.key is not 32 bytes; refusing to start") end
  return k
end
local HMAC_KEY = read_key()

-- Hex HMAC for the CI vectors (tests/siem/lua-hmac.sh loads this file into its own Lua state); the
-- filter itself never exposes the key.
function sdp_hmac_hex(key, msg)
  return tohex(hmac_sha256(key, msg))
end

local function pseudonym(v)
  return "hm1:" .. tohex(hmac_sha256(HMAC_KEY, v)):sub(1, 16)
end

-- Event time: RFC 3339 with optional fraction and offset -> epoch seconds (no local time zone).
local function days_from_civil(y, m, d)
  if m <= 2 then y = y - 1 end
  local era = math.floor(y / 400)
  local yoe = y - era * 400
  local doy = math.floor((153 * ((m + 9) % 12) + 2) / 5) + d - 1
  local doe = yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy
  return era * 146097 + doe - 719468
end

local function parse_time(s)
  if type(s) ~= "string" then return nil end
  local Y, M, D, h, mi, sec, rest = s:match("^(%d%d%d%d)%-(%d%d)%-(%d%d)[Tt ](%d%d):(%d%d):(%d%d)(.*)$")
  if not Y then return nil end
  local frac = 0
  local f, after = rest:match("^[.,](%d+)(.*)$")
  if f then
    frac = tonumber("0." .. f)
    rest = after
  end
  local off = 0
  if rest ~= "Z" and rest ~= "z" then
    local sign, oh, om = rest:match("^([+-])(%d%d):?(%d%d)$")
    if not sign then return nil end
    off = (tonumber(oh) * 3600 + tonumber(om) * 60) * (sign == "+" and 1 or -1)
  end
  return days_from_civil(tonumber(Y), tonumber(M), tonumber(D)) * 86400
    + tonumber(h) * 3600 + tonumber(mi) * 60 + tonumber(sec) + frac - off
end

local function nonempty(v)
  return type(v) == "string" and v ~= ""
end

local function in_sandbox(ns)
  return nonempty(ns) and ns:sub(1, 7) == "sandbox"
end

-- The join key (S0-#1): <namespace>_<pod>. Neither part can contain "_", so the API's split at the
-- first "_" is unambiguous; anything else is not a ref and is not shipped.
local REF_PATTERN = "^[a-z0-9][a-z0-9%-]*_[a-z0-9][a-z0-9.%-]*$"
local function pod_ref(ns, pod)
  if not (nonempty(ns) and nonempty(pod)) then return nil end
  local ref = ns .. "_" .. pod
  if ref:match(REF_PATTERN) then return ref end
  return nil
end

-- Hubble: the sandbox side of a flow - the source pod when it is in sandbox*, else the destination.
local function sandbox_side(v)
  if type(v) ~= "table" then return nil, nil end
  if in_sandbox(v[1]) and nonempty(v[2]) then return v[1], v[2] end
  if in_sandbox(v[3]) and nonempty(v[4]) then return v[3], v[4] end
  return nil, nil
end

-- Transforms named in siem/fields (README). Each gets the raw value (a list for multi-path fields),
-- the record context and the field; parsed host fields come from the context's derived values.
local function derived(_, ctx, f) return ctx.derived[f.name] end

local TRANSFORMS = {
  slug = function(v)
    if type(v) ~= "string" then return nil end
    local s = v:lower():gsub("[^a-z0-9]+", "-"):gsub("^%-+", ""):gsub("%-+$", "")
    return s
  end,
  lower = function(v) return type(v) == "string" and v:lower() or nil end,
  pod_ref = function(v) return type(v) == "table" and pod_ref(v[1], v[2]) or nil end,
  hmac = function(v, ctx)
    if not nonempty(v) then return nil end
    if ctx.verbatim and ctx.verbatim[v] then return v end
    return pseudonym(v)
  end,
  hmac_unless_system = function(v)
    if not nonempty(v) then return nil end
    if v:sub(1, 7) == "system:" then return v end
    return pseudonym(v)
  end,
  epoch_us = function(v)
    local n = tonumber(v)
    return n and n / 1e6 or nil
  end,
  epoch_ns = function(v)
    local n = tonumber(v)
    return n and n / 1e9 or nil
  end,
  int = function(v) return v end,
  bool = function(v) return v end,
  audit_dry_run = function(v)
    if type(v) ~= "string" then return nil end
    return v:find("dryRun=All", 1, true) ~= nil
  end,
  l4_protocol = function(v)
    if type(v) ~= "table" then return nil end
    for k, _ in pairs(v) do
      if type(k) == "string" then return k:lower() end
    end
    return nil
  end,
  l4_destination_port = function(v)
    if type(v) ~= "table" then return nil end
    for _, p in pairs(v) do
      if type(p) == "table" then return p.destination_port end
    end
    return nil
  end,
  sandbox_ns = function(v) local ns = sandbox_side(v); return ns end,
  sandbox_pod = function(v) local _, pod = sandbox_side(v); return pod end,
  sandbox_pod_ref = function(v) return pod_ref(sandbox_side(v)) end,
  ssh_event = derived, ssh_method = derived, sudo_result = derived,
  nft_proto = derived, nft_dpt = derived,
  audit_type = derived, audit_key = derived, audit_syscall = derived, audit_success = derived,
  audit_exe = derived, audit_comm = derived,
}

-- Allow-lists rendered from siem/fields by the role (same directory as this script).
local FIELDS = dofile("/etc/fluent-bit/sdp/sdp_fields.lua")
local DATASET = {}
for source, spec in pairs(FIELDS) do
  local seen = {}
  for _, f in ipairs(spec) do
    if f.transform and not TRANSFORMS[f.transform] then
      error("sdp.lua: unknown transform " .. f.transform .. " for " .. source .. "/" .. f.name)
    end
    if f.name == "event.dataset" then DATASET[source] = f.value end
    -- A name may not be both a leaf and the parent of another (a.b and a.b.c).
    for other, _ in pairs(seen) do
      if other:sub(1, #f.name + 1) == f.name .. "." or f.name:sub(1, #other + 1) == other .. "." then
        error("sdp.lua: fields " .. other .. " and " .. f.name .. " of " .. source .. " collide")
      end
    end
    seen[f.name] = true
  end
  if not DATASET[source] then error("sdp.lua: " .. source .. " has no event.dataset value") end
end

local function get_path(r, path)
  local v = r
  for _, k in ipairs(path) do
    if type(v) ~= "table" then return nil end
    v = v[k]
  end
  return v
end

local function convert(v, typ)
  if v == nil then return nil end
  if typ == "keyword" then
    if type(v) == "table" then
      local out = {}
      for _, x in ipairs(v) do
        local t = type(x)
        if (t == "string" and x ~= "") or t == "number" or t == "boolean" then out[#out + 1] = tostring(x) end
      end
      if #out == 0 then return nil end
      return out
    end
    if type(v) == "number" then
      if v == math.floor(v) then return sfmt("%d", v) end
      return tostring(v)
    end
    if type(v) ~= "string" and type(v) ~= "boolean" then return nil end
    v = tostring(v)
    if v == "" then return nil end
    return v
  elseif typ == "integer" or typ == "long" then
    local n = tonumber(v)
    if not n then return nil end
    n = math.floor(n)
    if typ == "integer" and (n > 2147483647 or n < -2147483648) then return nil end
    return n
  elseif typ == "boolean" then
    if v == true or v == "true" then return true end
    if v == false or v == "false" then return false end
    return nil
  end
  return nil
end

local function set_nested(out, name, v)
  local node = out
  local parts = {}
  for p in name:gmatch("[^.]+") do parts[#parts + 1] = p end
  for i = 1, #parts - 1 do
    local p = parts[i]
    if type(node[p]) ~= "table" then node[p] = {} end
    node = node[p]
  end
  node[parts[#parts]] = v
end

-- Projection: a new record built only from the source's allow-list.
local function project(source, rec, ctx)
  local out = {}
  local ts = ctx.ts
  for _, f in ipairs(FIELDS[source]) do
    if not (ctx.skip and ctx.skip[f.name]) then
      local raw = ctx.derived[f.name]
      if raw == nil then
        if f.value ~= nil then
          raw = f.value
        elseif f.from then
          if #f.from == 1 then
            raw = get_path(rec, f.from[1])
          else
            raw = {}
            for i, p in ipairs(f.from) do raw[i] = get_path(rec, p) end
          end
        end
      end
      local v = raw
      if f.transform then v = TRANSFORMS[f.transform](raw, ctx, f) end
      if f.name == "@timestamp" then
        if ts == nil then ts = (type(v) == "number") and v or parse_time(v) end
      else
        v = convert(v, f.type)
        if f.name == "k8s.pod.ref" and v ~= nil and not v:match(REF_PATTERN) then v = nil end
        if v ~= nil then set_nested(out, f.name, v) end
      end
    end
  end
  if ctx.kind then set_nested(out, "event.kind", ctx.kind) end
  return out, ts
end

-- F2: which audit events leave k3s01. Verbs other than get/list/watch on objects in sandbox*, or by
-- Talon's or the API's ServiceAccount; any refusal (code >= 400); any exec/attach/portforward.
-- Everything else (kyverno's reviews, controllers' and Argo's writes outside sandbox*) stays.
local READ_VERBS = { get = true, list = true, watch = true }
local RESPONDERS = {
  ["system:serviceaccount:falco-response:falco-talon"] = true,
  ["system:serviceaccount:portfolio-api:portfolio-api"] = true,
}
local INTERACTIVE = { exec = true, attach = true, portforward = true }

local function audit_keep(rec)
  local ref = type(rec.objectRef) == "table" and rec.objectRef or {}
  local status = type(rec.responseStatus) == "table" and rec.responseStatus or {}
  local user = type(rec.user) == "table" and rec.user.username or nil
  local code = tonumber(status.code)
  if code and code >= 400 then return true end
  if INTERACTIVE[ref.subresource] then return true end
  if type(rec.verb) == "string" and not READ_VERBS[rec.verb] then
    if in_sandbox(ref.namespace) or RESPONDERS[user] then return true end
  end
  return false
end

-- Host logs (sdp-host on k3s01, sdp-siem01 on siem01): one parsed value per allow-listed field.
local function parse_ssh(msg, d)
  local m, u, ip = msg:match("^Accepted (%S+) for (.-) from (%S+) port %d+")
  if m then d["ssh.event"], d["ssh.method"], d["user.name"], d["source.ip"] = "accepted", m, u, ip return true end
  m, u, ip = msg:match("^Failed (%S+) for invalid user (.-) from (%S+) port %d+")
  if not m then m, u, ip = msg:match("^Failed (%S+) for (.-) from (%S+) port %d+") end
  if m then d["ssh.event"], d["ssh.method"], d["user.name"], d["source.ip"] = "failed", m, u, ip return true end
  u, ip = msg:match("^Invalid user (.-) from (%S+) port %d+")
  if u then d["ssh.event"], d["user.name"], d["source.ip"] = "invalid-user", u, ip return true end
  u, ip = msg:match("^Connection closed by invalid user (.-) (%S+) port %d+ %[preauth%]")
  if not u then u, ip = msg:match("^Connection closed by authenticating user (.-) (%S+) port %d+ %[preauth%]") end
  if u then d["ssh.event"], d["user.name"], d["source.ip"] = "closed-preauth", u, ip return true end
  ip = msg:match("^Connection closed by (%S+) port %d+ %[preauth%]")
  if ip then d["ssh.event"], d["source.ip"] = "closed-preauth", ip return true end
  return false
end

local function parse_sudo(msg, d)
  local u, rest = msg:match("^%s*(%S+) : (.*)$")
  if not u then return false end
  if rest:find("incorrect password attempt", 1, true) then
    d["sudo.result"] = "incorrect-password"
  elseif rest:find("NOT in sudoers", 1, true) or rest:find("command not allowed", 1, true) then
    d["sudo.result"] = "not-allowed"
  elseif rest:find("COMMAND=", 1, true) then
    d["sudo.result"] = "command"
  else
    return false
  end
  d["user.name"] = u
  d["user.effective"] = rest:match("USER=(%S+)")
  return true
end

local function parse_nft(msg, d)
  d["nft.protocol"] = (msg:match("PROTO=(%S+)") or ""):lower()
  d["nft.destination_port"] = msg:match("DPT=(%d+)")
  d["source.ip"] = msg:match("SRC=(%S+)")
  return true
end

local function parse_journal(rec, ctx)
  local msg = rec.MESSAGE
  if type(msg) ~= "string" then return false end
  local d = ctx.derived
  local ident = rec.SYSLOG_IDENTIFIER
  if ident == "sudo" then
    d["host.log"] = "sudo"
    return parse_sudo(msg, d)
  end
  if rec._TRANSPORT == "kernel" then
    if msg:sub(1, 10) ~= "nft-drop: " then return false end
    d["host.log"] = "nft"
    return parse_nft(msg, d)
  end
  if ident == "sshd" or ident == "sshd-session" or rec._SYSTEMD_UNIT == "ssh.service" then
    d["host.log"] = "ssh"
    return parse_ssh(msg, d)
  end
  return false
end

-- auditd's enriched format, optionally prefixed "node=<host> " (the prefix is dropped): raw fields,
-- then 0x1d, then the interpreted ones (SYSCALL=, AUID=, EUID=). Only keyed records are shipped (the
-- rules' hits); PATH, PROCTITLE, EXECVE and PAM records carry command lines and no key.
local function parse_auditd(line, ctx)
  if type(line) ~= "string" then return false end
  line = line:gsub("^node=%S+ ", "")
  local raw, enriched = line:match("^([^\29]*)\29?(.*)$")
  local key = raw:match(' key="([^"]*)"')
  if not key or key == "" then return false end
  local d = ctx.derived
  local sec, ms = raw:match("msg=audit%((%d+)%.(%d+):%d+%)")
  if sec then ctx.ts = tonumber(sec) + tonumber(ms) / 1000 end
  d["host.log"] = "auditd"
  d["audit.type"] = raw:match("^type=(%S+)")
  d["audit.key"] = key
  d["audit.success"] = raw:match(" success=(%S+)")
  d["process.exe"] = raw:match(' exe="([^"]*)"')
  d["process.name"] = raw:match(' comm="([^"]*)"')
  d["audit.syscall"] = enriched:match("SYSCALL=(%S+)")
  d["user.name"] = enriched:match('AUID="([^"]*)"')
  d["user.effective"] = enriched:match('EUID="([^"]*)"')
  -- "unset" is the kernel's word for no login user, not a name: kept as it is.
  ctx.verbatim = { unset = true }
  return true
end

local function parse_osaudit(rec, ctx)
  if type(rec.audit_category) ~= "string" then return false end
  ctx.derived["host.log"] = "opensearch-audit"
  ctx.derived["source.ip"] = rec.audit_request_remote_address
  ctx.ts = parse_time(rec["@timestamp"])
  return true
end

-- Per source: return false to drop the record. May set ctx.derived, ctx.ts, ctx.kind, ctx.skip.
local SOURCES = {}

SOURCES["falco"] = function(rec, ctx)
  if type(rec.rule) ~= "string" then return false end
  if rec.rule == "Falco internal: metrics snapshot" then
    -- F12: the snapshot proves Falco itself is alive; its counters, host name and host addresses
    -- are not needed for that and are not shipped.
    ctx.kind = "metric"
    return { rule = rec.rule, priority = rec.priority, source = rec.source, time = rec.time }
  end
  return true
end

SOURCES["talon"] = function(rec)
  return rec.message == "action" and type(rec.rule) == "string"
end

SOURCES["api"] = function(rec)
  return rec.msg == "siem.run" or rec.msg == "siem.command"
end

SOURCES["k8s-audit"] = function(rec, ctx)
  if not audit_keep(rec) then return false end
  local ref = type(rec.objectRef) == "table" and rec.objectRef or {}
  if ref.resource ~= "pods" then ctx.skip = { ["k8s.pod.name"] = true, ["k8s.pod.ref"] = true } end
  return true
end

SOURCES["hubble"] = function(rec)
  return type(rec.flow) == "table"
end

local function host_source(rec, ctx, input)
  if input == "journal" then return parse_journal(rec, ctx) end
  if input == "auditd" then return parse_auditd(rec.log, ctx) end
  if input == "osaudit" then return parse_osaudit(rec, ctx) end
  return false
end
SOURCES["host"] = host_source
SOURCES["siem01"] = host_source

local dropped_errors = 0

local function handle(tag, ts, record)
  local source, input = tag:match("^sdp%.([^.]+)%.([^.]+)$")
  if not source or not FIELDS[source] or not SOURCES[source] then return -1, ts, record end
  if input == "hb" then
    return 1, ts, { event = { kind = "heartbeat", dataset = DATASET[source] } }
  end
  local ctx = { derived = {} }
  local keep = SOURCES[source](record, ctx, input)
  if not keep then return -1, ts, record end
  if type(keep) == "table" then record = keep end
  local out, event_ts = project(source, record, ctx)
  return 1, event_ts or ts, out
end

-- Entry point (filter lua, call sdp_filter). Protected mode alone would pass a failing record on
-- unchanged; here a failure drops it instead and is counted in Fluent Bit's log.
function sdp_filter(tag, ts, record)
  local ok, code, nts, out = pcall(handle, tag, ts, record)
  if ok then return code, nts, out end
  dropped_errors = dropped_errors + 1
  print("[sdp.lua] record dropped after an error (" .. dropped_errors .. " so far): " .. tostring(code))
  return -1, ts, record
end
