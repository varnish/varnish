#!/usr/bin/perl

# turn some vsl lines from vtest into an exact match logexpect
# this is just a tool, it can not guess what you intend and it
# does not handle special cases

my @r;
my $first = 1;
my $txid;
while (<STDIN>) {
	chomp;
	my (undef, undef, undef, $xid, $tag, $bc, $val) = split(/\s+/, $_, 7);
	my $skip = "0";
	if ($first) {
		$skip = "*";
		$txid = $xid;
	} else {
		$xid = "=";
	}
	$first = 0;

	$tab = "\t";
	if (length($tag) < 8) {
		$tab = "\t\t";
	}

	push @r, (sprintf("\texpect %s %s\t%s%s{^%s\$}\n",
	    $skip, $xid, $tag, $tab, $val));
}

unshift @r, (<<EOS);
logexpect lX -v v1 -q "vxid == $txid" {
	fail add *	End
EOS

push @r, (<<EOS);
	fail clear
} -start
EOS

print join("", @r);
