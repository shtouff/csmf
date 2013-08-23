#!/usr/bin/env perl

use strict;
use warnings;

use Getopt::Long qw(:config gnu_getopt);
use Data::Dumper;
use Net::SNMP;

$Data::Dumper::Sortkeys = 1;
 
# get vlans
#snmpwalk -On -v1 -c public 192.168.32.35 .1.3.6.1.4.1.9.9.46.1.3.1.1.2.1
#[...]
#.1.3.6.1.4.1.9.9.46.1.3.1.1.2.1.33 = INTEGER: 1

# get macs learnt on this vlan (33)
#snmpwalk -On -v1 -c public@33 192.168.32.35 .1.3.6.1.2.1.17.4.3.1.1 <= mind the vlan in community
#[...]
#.1.3.6.1.2.1.17.4.3.1.1.104.163.196.239.201.18 = Hex-STRING: 68 A3 C4 EF C9 12
#.1.3.6.1.2.1.17.4.3.1.1.108.98.109.57.250.165 = Hex-STRING: 6C 62 6D 39 FA A5  <= let's search this one
#.1.3.6.1.2.1.17.4.3.1.1.208.87.76.163.240.18 = Hex-STRING: D0 57 4C A3 F0 12

# bridge number
#snmpwalk -On -v1 -c public@33 192.168.32.35 .1.3.6.1.2.1.17.4.3.1.2.   108.98.109.57.250.165 <= mind spaces !
#.1.3.6.1.2.1.17.4.3.1.2.108.98.109.57.250.165 = INTEGER: 19 <= bridge number 19

# port number
#snmpwalk -On -v1 -c public@33 2960g-1 .1.3.6.1.2.1.17.1.4.1.2.  19 <= mind spaces !
#.1.3.6.1.2.1.17.1.4.1.2.19 = INTEGER: 10119 <= port number 10119

# port name
#snmpwalk -On -v1 -c public 192.168.32.35 .1.3.6.1.2.1.31.1.1.1.1.  10119 <= mind spaces !
#.1.3.6.1.2.1.31.1.1.1.1.10119 = STRING: "Gi0/19" <= port name

my $oidVLANs = ".1.3.6.1.4.1.9.9.46.1.3.1.1.2.1";
my $oidMACs  = ".1.3.6.1.2.1.17.4.3.1.2";

my $cache = {};
my $run   = {
	"community" => "priv",
	"hosts"     => [ "2960g-1", "2960g-3", "2960g-2" ],
	"filter"    => ""
};

my ( $opt_filter, $opt_hosts, $opt_verbose, $opt_community );

sub isSubOid {
	my $rootOid  = shift;
	my $otherOid = shift;

	return 0 if length($otherOid) < length($rootOid);

	my $comOid = substr( $otherOid, 0, length($rootOid) );

	return 1 if $comOid eq $rootOid;

	0;
}

sub mac_beautify {
	my $mac = shift;

	my ( $f1, $f2, $f3, $f4, $f5, $f6 ) = split /\./, $mac;

	return
	  sprintf( "%02x:%02x:%02x:%02x:%02x:%02x", $f1, $f2, $f3, $f4, $f5, $f6 );
}

sub snmpwalk {
	my $community = shift;
	my $host      = shift;
	my $oid       = shift;
	
	my %table;     
	my $rootOid   = $oid;    # saves the wanted oid

	my ( $session, $error ) = Net::SNMP->session(
		-hostname    => $host,
		-version     => 1,
		-community   => $community,
		-nonblocking => 0
	);
	if ( !defined $session ) {
		printf "ERROR: Failed to create session for host '%s': %s.\n",
		  $host, $error;
	}

  OID:
	while ( my $result = $session->get_next_request( -varbindlist => [$oid] ) )
	{

		if ( defined $result ) {
			foreach my $key ( keys($result) ) {
				last OID if ( ! isSubOid( $rootOid, $key ) );
				$table{$key} = $result->{$key};
				$oid = $key;
			}
		}
	}

	# if table is empty, try a simple get on wanted oid
	if (scalar keys (%table) == 0) {
		my $result = $session->get_request( -varbindlist => [$rootOid] );
		if ( defined $result ) {
			foreach my $key ( keys($result) ) {
				$table{$key} = $result->{$key};
			}
		}
	}
	
	return \%table;
}
#print Dumper(snmpwalk("public", "2960g-1", ".1.3.6.1.4.1.9.5.1.4.1.1.12.1"));
#print Dumper(snmpwalk("public", "2960g-1", ".1.3"));

# get a bridge number for a MAC in a VLAN, for a host
sub get_bridge_number {
	my $host = shift;
	my $vlan = shift;
	my $mac  = shift;

	my $walk =
	  snmpwalk( $run->{community} . "\@$vlan", $host, $oidMACs . ".$mac" );

	foreach ( values($walk) ) {
		return $_;
	}
}

# get a port number for a bridge in a VLAN, for a host
sub get_port_number {
	my $host   = shift;
	my $vlan   = shift;
	my $bridge = shift;

	my $walk = snmpwalk( $run->{community} . "\@$vlan",
		$host, ".1.3.6.1.2.1.17.1.4.1.2" . ".$bridge" );

	foreach ( values($walk) ) {
		return $_;
	}
}

# get a port name for a port, for a host
sub get_port_name {
	my $host = shift;
	my $port = shift;

	my $walk =
	  snmpwalk( $run->{community}, $host,
		".1.3.6.1.2.1.31.1.1.1.1" . ".$port" );

	foreach ( values($walk) ) {
		return $_;
	}
}

# GET VLANS
sub get_vlans {

	my $host = shift;
	print "entering get_vlans $host\n" if defined $opt_verbose;

	my $walk = snmpwalk( $run->{community}, $host, $oidVLANs );
	my @vlans;

	foreach my $oid ( keys($walk) ) {
		push @vlans, substr( $oid, length($oidVLANs) + 1 );
	}

	return @vlans;
}

# GET MACS learnt on a VLAN
sub get_macs {

	my $host = shift;
	my $vlan = shift;

	print "entering get_macs $host, $vlan\n" if defined $opt_verbose;

	my $walk = snmpwalk( $run->{community} . "\@$vlan", $host, $oidMACs );
	my %macs;

	foreach my $oid ( keys($walk) ) {
		$macs{ substr( $oid, length($oidMACs) + 1 ) } = $walk->{$oid};
	}

	return \%macs;
}

# get a port name for a bridge number, using cache
sub get_port_name_for_a_bridge {

	my $host   = shift;
	my $vlan   = shift;
	my $bridge = shift;

	print "entering get_port_name_for_a_bridge $host, $vlan, $bridge\n"
	  if defined $opt_verbose;

	if ( defined $cache->{ $host . ":" . $vlan . ":" . $bridge } ) {
		return $cache->{ $host . ":" . $vlan . ":" . $bridge };
	}

	my $port = get_port_number( $host, $vlan, $bridge );
	my $pname = get_port_name( $host, $port );

	$cache->{ $host . ":" . $vlan . ":" . $bridge } = $pname;

	return $pname;
}

if (
	!GetOptions(
		"filter=s"    => \$opt_filter,
		'f=s'         => \$opt_filter,
		"hosts=s"     => \$opt_hosts,
		'h=s'         => \$opt_hosts,
		"verbose"     => \$opt_verbose,
		"v"           => \$opt_verbose,
		"community=s" => \$opt_community,
		"c=s"         => \$opt_community
	)
  )
{
	die "getopt failed";
}

$run->{community} = $opt_community if defined $opt_community;
$run->{hosts} = [ split /,/, $opt_hosts ] if defined $opt_hosts;
$run->{filter} = $opt_filter if defined $opt_filter;

foreach my $host ( @{ $run->{hosts} } ) {

	my @vlans = get_vlans $host;

	foreach my $vlan (@vlans) {
		my $addresses = get_macs( $host, $vlan );

		foreach my $address ( keys($addresses) ) {
			my $beauty = mac_beautify($address);

			if ( $beauty !~ /$run->{filter}/ ) {
				delete $addresses->{$address};
			}
		}

		foreach my $address ( keys($addresses) ) {
			my $bridge = $addresses->{$address};

			my $pname = get_port_name_for_a_bridge( $host, $vlan, $bridge );
			$address = mac_beautify($address);

			print "$host\t$vlan\t$address\t$pname\n";
		}
	}
}
