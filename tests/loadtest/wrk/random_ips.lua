-- Рандомизация IP-адресов клиентов через заголовки X-Forwarded-For и X-Real-IP
-- Позволяет обойти простые блокировки по одному IP и симулировать реальный трафик из множества источников

local thread_counter = 0

setup = function(thread)
    thread_counter = thread_counter + 1
    thread:set("thread_id", thread_counter)
end

init = function(meta)
    -- Инициализируем генератор случайных чисел для каждого потока уникальным сидом
    math.randomseed(os.time() + thread_id)
    -- Делаем несколько холостых вызовов для прогрева генератора
    math.random(); math.random(); math.random()
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
