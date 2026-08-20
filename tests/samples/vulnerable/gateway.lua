-- Cong API viet bang OpenResty. Moi ham duoi day deu THUNG mot cach co y:
-- day la mau kiem thu, khong phai ma dung duoc.

local _M = {}

function _M.chuyen_tiep()
    local args = ngx.req.get_uri_args()
    -- Ten dich lay thang tu query string roi vao shell.
    os.execute("curl -s " .. args.dich)
end

function _M.chay_bo_loc()
    local args = ngx.req.get_uri_args()
    -- Ma Lua do nguoi ngoai gui len, bien dich va chay ngay.
    local f = loadstring(args.bo_loc)
    return f()
end

function _M.doc_ho_so()
    local args = ngx.req.get_uri_args()
    local fd = io.open("/var/data/" .. args.ten, "r")
    return fd:read("*a")
end

return _M
