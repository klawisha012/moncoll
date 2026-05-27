-- Тестирование накладных расходов ModSecurity (WAF) под атаками
-- Симулирует POST-запросы со смесью легитимного трафика и вредоносных сигнатур (SQLi, XSS, Path Traversal)

local payloads = {
    "username=admin&password=normal_password",                           -- Обычный легитимный запрос
    "username=admin' OR '1'='1&password=something",                       -- Попытка SQL-инъекции
    "content=<script>alert('xss_attack')</script>&id=12",                 -- Попытка XSS-атаки
    "file=/etc/passwd&action=read",                                        -- Попытка LFI/Path Traversal
}

local thread_counter = 0

setup = function(thread)
    thread_counter = thread_counter + 1
    thread:set("thread_id", thread_counter)
end

init = function(meta)
    math.randomseed(os.time() + thread_id)
    math.random(); math.random(); math.random()
end

request = function()
    local payload = payloads[math.random(1, #payloads)]
    
    local ip = string.format("192.168.%d.%d", math.random(1, 254), math.random(1, 254))
    
    local headers = {}
    headers["X-Forwarded-For"] = ip
    headers["X-Real-IP"] = ip
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    headers["User-Agent"] = "wrk-attack-agent"
    
    return wrk.format("POST", "/api/auth/login", headers, payload)
end
