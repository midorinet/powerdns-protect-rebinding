pdnslog("pdns-recursor Lua script starting!", pdns.loglevels.Warning)
  
rfc1918 = newNMG()
rfc1918:addMask("0.0.0.0/8")
rfc1918:addMask("10.0.0.0/8")
rfc1918:addMask("127.0.0.0/8")
rfc1918:addMask("172.16.0.0/12")
rfc1918:addMask("192.168.0.0/16")

whitelistDomain = newDS()
whitelistDomain:add("domain1.com")
whitelistDomain:add("domain2.com")

function postresolve(dq)
        local records = dq:getRecords()
        for k,v in pairs(records) do
                if whitelistDomain:check(dq.qname) then
                        pdnslog("Not blocking whitelisted domain: "..dq.qname:toString())
                        return false
                end
                if v.type == pdns.A and rfc1918:match(newCA(v:getContent()))
                then
                        dq.appliedPolicy.policyKind = pdns.policykinds.NODATA
                        v.ttl=1
                end
        end
        dq:setRecords(records)
        return true
end
