-- Тестирование производительности алгоритмов сжатия (zstd, br, gzip, identity)
-- Поочередно запрашивает разные кодировки, симулируя различные возможности клиентов

local encodings = {"zstd", "br", "gzip", "identity"}
local counter = 0

setup = function(thread)
    math.randomseed(os.time() + thread.addr)
end

request = function()
    counter = counter + 1
    local enc = encodings[(counter % #encodings) + 1]
    
    local ip = string.format("10.0.%d.%d", math.random(1, 254), math.random(1, 254))
    
    local headers = {}
    headers["X-Forwarded-For"] = ip
    headers["X-Real-IP"] = ip
    headers["Accept-Encoding"] = enc
    headers["User-Agent"] = "wrk-compression-agent"
    
    return wrk.format("GET", "/", headers)
end
