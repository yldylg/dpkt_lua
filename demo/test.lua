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
    elseif eth.subtype == dpkt.Ethernet.ETH_TYPE_ARP then
        local arp = dpkt.ARP(eth.data)
    end
end

-----------
p = dpkt.pcap.PcapReader('80211.pcap')

while true do
    data, ts, len = p:next()
    if data == nil then break end
    local rt = dpkt.Radiotap(data)
    print(rt.channel, rt.ant_sig)
    local dot11 = dpkt.Dot11(rt.data)
    if dot11.src ~= nil then
        print('src', dot11.src)
    end
    if dot11.dst ~= nil then
        print('dst', dot11.dst)
    end
    if dot11.bssid ~= nil then
        print('bssid', dot11.bssid)
    end
    if dot11.ssid ~= nil then
        print('ssid', dot11.ssid.info)
    end
end
