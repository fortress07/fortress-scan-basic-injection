#!/usr/bin/perl
# Handler CGI kieu cu. Ca ba duong duoi day deu thung mot cach co y.
use strict;
use warnings;
use CGI;

my $q = CGI->new;

sub ping_may {
    my $host = $q->param('host');
    # Chuoi noi thang vao shell.
    system("ping -c 1 $host");
}

sub tinh_bieu_thuc {
    my $bieu_thuc = $q->param('e');
    return eval $bieu_thuc;
}

sub doc_nhat_ky {
    my $ten = $q->param('ten');
    # open() hai doi so: chuoi ket thuc bang ong dan thi day la mot cau lenh.
    open(my $fh, "/var/log/$ten");
    return <$fh>;
}

1;
