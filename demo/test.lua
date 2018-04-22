package.path = package.path .. ";../?/?.lua;../?/init.lua;../?.lua;"
local dpkt = require("dpkt")

p = dpkt.pcap.PcapReader("ethernet.pcap")

while true do
    data, ts, len = p:next()
    if data == nil then break end
    print("#", ts, len, #data)
    local eth = dpkt.Ethernet(data)
    print("etheret", eth.src, eth.dst)
    if eth.subtype == dpkt.Ethernet.ETH_TYPE_IP then
        local ip = dpkt.IP(eth.data)
        print("ip", ip.src, ip.dst)
        if ip.proto == dpkt.IP.IP_PROTO_UDP then
            local udp = dpkt.UDP(ip.data)
            print("udp", udp.sport, udp.dport)
        elseif ip.proto == dpkt.IP.IP_PROTO_TCP then
            local tcp = dpkt.TCP(ip.data)
            print("tcp", tcp.sport, tcp.dport)
        end
    end
end
