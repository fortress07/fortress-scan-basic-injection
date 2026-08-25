# Cung chuc nang cua ban thung, viet lai cho dung.

# Ep ve so nguyen: khong con ky tu dac biet nao song sot.
$so_lan = [int]$args[0]

# Tao tien trinh voi danh sach doi so, khong di qua bo thong dich nao.
Start-Process -FilePath ping -ArgumentList @('-n', $so_lan, '127.0.0.1')
