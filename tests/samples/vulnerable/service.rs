// Dich vu HTTP viet bang actix. Ca ba duong duoi day deu thung mot cach co y.
use std::process::Command;

pub fn kiem_tra_may(req: &HttpRequest) {
    let host = req.match_info().query("host");
    // Chinh TEN CHUONG TRINH do nguoi ngoai quyet dinh.
    Command::new(host).status().unwrap();
}

pub fn doc_ho_so(req: &HttpRequest) -> String {
    let ten = req.match_info().query("ten");
    std::fs::read_to_string(ten).unwrap()
}

pub fn goi_ra_ngoai(req: &HttpRequest) -> String {
    let url = req.match_info().query("url");
    reqwest::get(url).unwrap().text().unwrap()
}
