-- Cung ba chuc nang cua ban thung, viet lai cho dung.

local _M = {}

local DICH_CHO_PHEP = {
    chinh = "https://api.noi-bo/健",
    phu = "https://api-phu.noi-bo/",
}

function _M.chuyen_tiep()
    local args = ngx.req.get_uri_args()
    -- Tra bang anh xa: gia tri di ra luon la mot hang viet san o tren.
    local dich = DICH_CHO_PHEP[args.dich]
    if not dich then
        return ngx.exit(400)
    end
    return ngx.location.capture("/proxy")
end

function _M.chay_bo_loc()
    local args = ngx.req.get_uri_args()
    -- Khong bien dich gi ca: chon mot bo loc da viet san.
    local so = tonumber(args.bo_loc)
    return so
end

function _M.doc_ho_so()
    local args = ngx.req.get_uri_args()
    local ma = tonumber(args.ten)
    if not ma then
        return ngx.exit(400)
    end
    local fd = io.open("/var/data/ho-so.dat", "r")
    return fd:read("*a")
end

return _M
