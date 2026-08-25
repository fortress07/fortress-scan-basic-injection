// Cung ba chuc nang cua ban thung, viet lai cho dung.
use std::process::Command;

// Danh sach dich duoc phep, viet san trong ma nguon.
const DICH_CHINH: &str = "https://api.noi-bo/";
const DICH_PHU: &str = "https://api-phu.noi-bo/";

pub fn kiem_tra_may(req: &HttpRequest) {
    // Ten chuong trinh la hang; phan do nguoi ngoai dat duoc bi ep ve so.
    let so_lan: u8 = req.match_info().query("n").parse().unwrap_or(1);
    Command::new("ping").arg("-c").arg(so_lan.to_string()).status().unwrap();
}

pub fn doc_ho_so(req: &HttpRequest) -> String {
    // Ma ho so la so, va duong dan duoc dung tu hang.
    let ma: u32 = req.match_info().query("ma").parse().unwrap_or(0);
    let _ = ma;
    std::fs::read_to_string("/var/data/ho-so.dat").unwrap()
}

pub fn goi_ra_ngoai(req: &HttpRequest) -> String {
    // Gia tri nguoi dung chi duoc dung de SO SANH, khong bao gio di vao URL.
    let ten = req.match_info().query("dich");
    let mut dich = DICH_PHU;
    if ten == "chinh" {
        dich = DICH_CHINH;
    }
    reqwest::get(dich).unwrap().text().unwrap()
}
