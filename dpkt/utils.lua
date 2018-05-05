return {
    hex = function(data)
        local repl = function(b)
            return string.format("%02x",string.byte(b))
        end
        return string.gsub(data, ".", repl)
    end,

    ntohs = function(n)
        return ((n >> 8) & 0x00ff) | ((n << 8) & 0xff00)
    end,

    ntohl = function(n)
        return ((n << 8) & 0x00ff00ff) | ((n >> 8) & 0xff00ff00)
    end,

    ntohls = function(n)
        local a = (n << 24) & 0xff000000
        local b = (n << 8) & 0x00ff0000
        local c = (n >> 8) & 0x0000ff00
        local d = (n >> 24) & 0x000000ff
        return a | b | c | d
    end,

    mac2str = function(n)
        local a = n & 0xff
        local b = (n >> 8) & 0xff
        local c = (n >> 16) & 0xff
        local d = (n >> 24) & 0xff
        local e = (n >> 32) & 0xff
        local f = (n >> 40) & 0xff
        return string.format("%02x:%02x:%02x:%02x:%02x:%02x", a, b, c, d, e, f)
    end,

    ip2str = function(n)
        local a = n & 0xff
        local b = (n >> 8) & 0xff
        local c = (n >> 16) & 0xff
        local d = (n >> 24) & 0xff
        return string.format("%d.%d.%d.%d", a, b, c, d)
    end
}
