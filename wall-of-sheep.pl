#!/usr/bin/perl
# Simple Wall of Sheep/Shame written in Perl.
# (C) Kost (kost.com.hr). Distributed under GPL. 
# 
# Uses ettercap for actual sniffing
# Should be used with care. It's still DoS vulnerable...

use strict;
use Socket;
use Getopt::Long;

my $lookupdns=0;
my $mode=2;  # 0 - <write HTML file>, 1 - cgi, 2 - web server
my $lhost="127.0.0.1";
my $lport="8081";
my $refresh=10;
my ($html,$cgi,$webserver,$help,$uniq,$logfile);
my $rurl="http://127.0.0.1:8081";
my $title="Wall of sheep";
my $subtitle="Look at those sheeps coming fast :)";

sub parse_line {
	my $line=shift;
	my $ret;

	my ($protocol,$rest)=split(" \:\ ", $line);
	my ($hostip,$rest)=split(" \-\> ",$rest);
	my ($host,$port)=split("\:",$hostip);
 	my $dns=gethostbyaddr(inet_aton($host), AF_INET) if ($lookupdns);
	my @fields=split("\ \ ", $rest);
	my $user="";
	my $pass="";
	my $info="";
	foreach my $j (0 .. $#fields) {
		$_=$fields[$j];
		if (/USER\: /) {
			(undef,$user,undef)=split("USER\: ");
		}
		if (/PASS\: /) {
			(undef,$pass,undef)=split("PASS\: ");
		}
		if (/COMMUNITY\: /) {
			(undef,$pass,undef)=split("COMMUNITY\: ");
		}
		if (/HASH\: /) {
			(undef,$pass,undef)=split("HASH\: ");
		}
		if (/INFO\: /) {
			(undef,$info,undef)=split("INFO\: ");
		}
	}
	my $pass1=substr($pass,0,3);
	my $pass2=substr($pass,3);
#	$pass2 =~ s/.*/\*/ig;
	$pass2 = "...";
	$pass=$pass1.$pass2;

	$user =~ s/\</&lt/ig;
	$user =~ s/\>/&gt/ig;
	$pass =~ s/\</&lt/ig;
	$pass =~ s/\>/&gt/ig;
	$info =~ s/\</&lt/ig;
	$info =~ s/\>/&gt/ig;

#	print $protocol.";".$host.";".$port.";".$user.";".$pass.";".$info.";\n";
	$ret="<TR><TD>$protocol</TD><TD>$host</TD><TD>$port</TD><TD>$user</TD><TD>$pass</TD><TD>$info</TD></TR>\n";
	return $ret;
}

sub parselog {
my $output;
my %saw;
my @out;

open(FILE,"<$logfile") or die "cannot open log file $!";

my @lines=<FILE>;

close(FILE);

chomp @lines;

# make them unique
if ($uniq) {
	@out = reverse(grep(!$saw{$_}++, @lines));
} else {
	@out = @lines;
}

$output .= "Content-type: text/html\n\n" if ($mode==1);

$output .= <<END;
<HTML>
<HEAD>
	<META HTTP-EQUIV="Refresh" Content = "$refresh;URL=$rurl">
	<TITLE>$title</TITLE>
</HEAD>
<BODY BGCOLOR="#FFFFF">
<CENTER>
<H1>$title</H1>
<H3>$subtitle</H3>
<TABLE WIDTH="99%" BORDER="1">
<TR>
<TD>Protocol</TD>
<TD>Host</TD>
<TD>Port</TD>
<TD>User</TD>
<TD>Password</TD>
<TD>Info</TD>
</TR>
</CENTER>
END
foreach my $i (0 .. $#out) {
	$_=$out[$i];
	if ((/\ \-\>\ /)) {
		$output .= parse_line ($_);
	} 
}

$output .= <<END;
</TABLE>
<HR>
<CENTER>Script by <a href="http://kost.com.hr">Kost</a>. It's GPL and <a href="http://kost.com.hr/wos.php">here</a>. </CENTER>
</BODY>
</HTML>
END
	return $output;
}

### MAIN ###
my $output;

my $allopts = GetOptions (
	"l|log=s" => \$logfile,
	"p|port=s" => \$lport,
	"i|ip=s" => \$lhost,
	"d|dns" => \$lookupdns,
	"s|server" => \$webserver,
	"h|html" => \$html,
	"c|cgi" => \$cgi,
	"t|time=i" => \$refresh,
	"r|url=s" => \$rurl,
	"u|uniq" => \$uniq,
	"h|help" => \$help
	);

$mode=0 if ($html);
$mode=1 if ($cgi);
$mode=2 if ($webserver);

if (($help) || !defined($logfile)) {
	print "$0: Wall of shame. (C) Kost. Distributed under GPL.\n\n";
	print "You need to feed this script with ettercap log file. Few examples:\n";
	print "ettercap -Tq -m sniff.log\n";
	print "ettercap -Tq -m sniff.log -M arp /gateway-IP/ //.\n";
	print "\nParameters:\n";
	print "--help\t\tthis help message\n";
	print "--log <file>\tettercap log\n";
	print "--time <time>\trefresh time in seconds (default: $refresh)\n";
	print "--dns\t\tresolve IP into DNS names (off by default, can be slow!)\n";
	print "--uniq\t\tdisplay only uniq ones (remove duplicates!)\n";
	print "--server\tstart in web server mode (web server mode - default)\n";
	print "--html\t\tspits out HTML to stdout and exits (HTML mode)\n";
	print "--cgi\t\tspits out CGI output to stdout and exits (CGI mode)\n";
	print "--port <port>\tport to listen(default: $lport) - web server mode only\n";
	print "--ip <ip>\tIP to listen(default: $lhost) - web server mode only\n";
	print "--url <url>\tRefresh URL (useful in CGI/HTML mode)\n";
	print "\nExamples (first one is server mode and the second is HTML mode):\n";
	print "$0 --host 192.168.0.1 --log sniff.log\n";
	print "while true; do ($0 --html --url http://192.168.0.1/wos.html > /var/www/wos.html) ; sleep 10; done\n";
	exit 0;
}

if ($mode == 2 ) {
	use HTTP::Daemon;
	use HTTP::Status;

	my $d = HTTP::Daemon->new (LocalAddr=>$lhost, LocalPort=> $lport) || die;
	$rurl=$d->url;
	print "Please contact me at: <URL:", $d->url, ">\n";
	while (my $c = $d->accept) {
	    while (my $r = $c->get_request) {
		if ($r->method eq 'GET') {
		my $bla=parselog;
		      $c->send_basic_header(200);
		$c->send("Content-length: ".length($bla)."\r\n");
		      $c->send_crlf;
		      $c->send($bla);
		      $c->close;
		}
		else {
		    $c->send_error(RC_FORBIDDEN)
		}
	    }
	    $c->close;
	    undef($c);
	}
}
else {
	$output=parselog;
	print $output;
}
