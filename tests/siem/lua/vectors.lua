-- Test-only filter (tests/siem/lua-hmac.sh): loads the shipped sdp.lua into this filter's own Lua
-- state and reports its HMAC for the RFC 4231 vectors and the project vector the test computes with
-- Python's hmac. The key file here is the test's, never a host key.
dofile("/etc/fluent-bit/sdp/sdp.lua")

local function key()
  local f = assert(io.open(os.getenv("CREDENTIALS_DIRECTORY") .. "/hmac.key", "rb"))
  local k = f:read("*a")
  f:close()
  return k
end

function vectors(tag, ts, record)
  return 1, ts, {
    vector = "hmac",
    rfc4231_2 = sdp_hmac_hex("Jefe", "what do ya want for nothing?"),
    rfc4231_6 = sdp_hmac_hex(string.rep("\170", 131), "Test Using Larger Than Block-Size Key - Hash Key First"),
    rfc4231_7 = sdp_hmac_hex(string.rep("\170", 131),
      "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."),
    project_operator = sdp_hmac_hex(key(), "operator"),
    project_empty = sdp_hmac_hex(key(), ""),
  }
end
