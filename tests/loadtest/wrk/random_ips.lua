-- Рандомизация IP-адресов клиентов через заголовки X-Forwarded-For и X-Real-IP
-- Позволяет обойти простые блокировки по одному IP и симулировать реальный трафик из множества источников

setup = function(thread)
    -- Инициализируем генератор случайных чисел для каждого потока
    math.randomseed(os.time() + thread.addr)
end

request = function()
    local ip = string.format("%d.%d.%d.%d", 
        math.random(1, 254), 
        math.random(1, 254), 
        math.random(1, 254), 
        math.random(1, 254)
    )
    
    local headers = {}
    headers["X-Forwarded-For"] = ip
    headers["X-Real-IP"] = ip
    headers["User-Agent"] = "wrk-loadtest-agent"
    
    return wrk.format("GET", "/", headers)
end
