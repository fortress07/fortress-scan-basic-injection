# Script trien khai. Ca hai duong duoi day deu thung mot cach co y.

$muc_tieu = $args[0]

# Chuoi noi thang roi dua cho bo thong dich cua PowerShell chay.
Invoke-Expression "ping $muc_tieu"

$lenh = $env:QUERY_STRING
Invoke-Expression $lenh
