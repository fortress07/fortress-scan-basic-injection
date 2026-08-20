#!/usr/bin/perl
# Cung ba chuc nang cua ban thung, viet lai cho dung.
use strict;
use warnings;
use CGI;
use String::ShellQuote;

my $q = CGI->new;

sub ping_may {
    # shell_quote() boc gia tri lai nen shell khong con ranh gioi nao de pha.
    my $host = shell_quote($q->param('host'));
    system("ping -c 1 $host");
}

sub tinh_bieu_thuc {
    # Khong bao gio dem du lieu ra chay: ep ve so.
    my $so = int($q->param('e'));
    return $so * 2;
}

sub doc_nhat_ky {
    # Ten tep co dinh, va open() ba doi so khong bao gio chay shell.
    open(my $fh, '<', '/var/log/ung-dung.log');
    return <$fh>;
}

1;
