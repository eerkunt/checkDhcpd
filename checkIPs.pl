#!/usr/bin/perl
#
# checkIPs    -  This scripts connects to DHCPd Servers via SSH, parses DHCPd config 
#                and leases file to identify IP Usage problems on multiple subnets. 
#
# Author            Emre Erkunt
#                   (emre.erkunt@superonline.net)
#
# History :
# ---------------------------------------------------------------------------------------------
# Version               Editor          Date            Description
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# 0.0.1_AR              EErkunt         20150225        Initial ALPHA Release
# 0.0.1                 EErkunt         20150227        Initial LIVE Release
# 0.0.2                 EErkunt         20150227        Threshold changes
# 0.0.3                 EErkunt         20150305        Implemented logging facility
#                                                       Ensured one copy run at a time
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

use strict;
use POSIX;
use Term::ANSIColor qw(:constants);
use Time::Piece;
use Fcntl ':flock';
$Term::ANSIColor::AUTORESET = 1;

#
# Configuration
my $version = "0.0.3";
my $dhcpdConfFile  = "/replicated/etc/dhcpd.conf";
my $leasefile = '/replicated/var/state/dhcp/dhcpd.leases';
my $warningThreshold = 70.0;		               # Should be floating number
my $problemThreshold = 80.0;		               # Should be floating number
our $defaultLogLevel = "WARN";		               # Keep 't as DEBUG if you're unsure.
our $logFilename = "/var/log/checkIPs.log";        # Logfile

print color "reset";
print "checkIPs v".$version."\n";
logMe("info", "checkIPs v".$version." initiated.");

our $swirlCount = 1;
my $swirlTime  = time();
my $processStartTime = time();
$| = 1;

#
# MAIN LOOP BELOW HERE.
# HERE BE DRAGONS, GO AWAY IF YOU'RE UNSURE WHAT YOU'RE DOING !
# 
# Ensures only 1 copy runs at a time
INIT {
        open  LH, $0 or logMe("FATAL", "Can't open $0 for locking!\nError: $!\n");
        flock LH, LOCK_EX|LOCK_NB or die "$0 is already running!\n";
    }
	
#
# First read the dhcpdConfFile and parse related configurations for IP Ranges
print "Parsing subnet configurations..";
open CONF, $dhcpdConfFile or logMe("fatal", "Can not open $dhcpdConfFile for reading.");
my $stepIn = 0;
our %subnetTree;
my $sharedNetworkName = '';
my $subnet;
my $netmask;
while(<CONF>) {
		if ( $_ =~ /\s*shared-network "(.*)"/ and $stepIn eq 0 ) {
			# print "LINE: $_";
			$stepIn = 1;
			$sharedNetworkName = $1;
			# print "READ : $sharedNetworkName\n";
		} elsif ( $_ =~ /\s*subnet (\d*\.\d*\.\d*\.\d*) netmask (\d*\.\d*\.\d*\.\d*)/ and $stepIn eq 1 ) {
			# print "LINE: $_";
			$subnet = $1;
			$netmask = netmask2cidr($2, $subnet);
			$stepIn = 3;
			# print " EAD : $subnet / $netmask\n";
		} elsif ( $_ =~ /\s*range (\d*\.\d*\.\d*\.\d*) (\d*\.\d*\.\d*\.\d*)/ and $stepIn eq 3 ) {
			# print "LINE: $_";
			my $tmpName = "$subnet/$netmask";
			$subnetTree{$sharedNetworkName}{$tmpName}{start} 	= $1;
			$subnetTree{$sharedNetworkName}{$tmpName}{end} 		= $2;
			$subnetTree{$sharedNetworkName}{$tmpName}{capacity} = findCapacity( $subnetTree{$sharedNetworkName}{$tmpName}{start}, $subnetTree{$sharedNetworkName}{$tmpName}{end} );
			# $stepIn = 1;
			# print "  AD : START: $1\tEND: $2\n";
		} elsif ( $_ =~ /}/ and $stepIn > 0 ) {
			# print "LINE: $_";
			# print "<- $stepIn to (".($stepIn-1).")\n";
			$stepIn--;
		} 
}
close CONF;

print "Done.\nParsing IP Usages, this will take a while.. ";
$stepIn = 0;
my $startTime;
my $endTime;
my $state;
my $currentIP;
my $totalActives = 0;
my $notInTheList = 0;
my $notation = 0;
my $currentTime = time();
# my $output;
open LEASE, $leasefile or logMe("fatal", "Can not open $leasefile for reading.");
while(<LEASE>) {
	if ( $_ =~ /lease\s(\d+\.\d+\.\d+\.\d+)/) {
		$currentIP = $1;
		$stepIn = 1;
		# $output = "";
	} elsif ( $_ =~ /starts\s\d\s(\d+\/\d+\/\d+\s\d+:\d+:\d+)\;/ and $stepIn eq 1 ) {
		$startTime = date2timeStamp($1) + 7200;
		# $output .= "Current: $currentTime ( $startTime [$1] <=>";
	} elsif ( $_ =~ /ends\s\d\s(\d+\/\d+\/\d+\s\d+:\d+:\d+)\;/ and $stepIn eq 1 ) {
		$endTime = date2timeStamp($1) + 7200;
		# $output .= " $endTime [$1] )";
	} elsif ( $_ =~ /^\s+binding\sstate\sactive\;/ and $stepIn eq 1 ) {
		if ( $currentTime > $startTime and $currentTime < $endTime ) {
			if ( SetIPasActive($currentIP) ) {
				# $output .= "==> Found!\n";
				# print $output;
				$totalActives++;
			} else {
				# $output .= "==> Not Found!\n";
				# print $output;
				$notInTheList++;
			}
		# } else {
			# $output .= "==> Out of bounds!\n";
			# print $output;
		}
	}
	&swirl();
}
close(LEASE);
print "Done!\n";

print color 'bold yellow';
printf("%30s  %18s  %15s  %15s  %6s  %6s %5s\n", "IP Pool", "Subnet", "Start Range", "End Range", "Usable", "Used", "%");
print "--------------------------------------------------------------------------------------------------------------\n";
print color 'reset';
my $totalCapacity = 0;
my $totalUsed = 0;
foreach my $name ( keys %subnetTree ) {
	#print "-> $name\n";
	my $capacity = 0;
	my $used = 0;
	my $subnetElementsCount = 0;
	my $subnetWARNINGThreshold = 0;
	my $subnetFATALThreshold = 0;
	my @aboveThresholds;
	foreach my $subnets ( keys %{$subnetTree{$name}} ) {
		my $percentage = sprintf("%.1f", ($subnetTree{$name}{$subnets}{used}/$subnetTree{$name}{$subnets}{capacity})*100 );
		#
		# Just to keep the problematic subnets in an array and logging purpose.
		if ( $percentage > $warningThreshold ) {
			logMe("info", "$subnets ( ".$subnetTree{$name}{$subnets}{start}." - ".$subnetTree{$name}{$subnets}{end}." ) is %".$percentage." full.");
			push(@aboveThresholds, $subnets);
		}
		$Term::ANSIColor::AUTORESET = 0;
		if ( $percentage > $problemThreshold ) {
			print color "bold red";
			$subnetFATALThreshold++;
		} elsif ( $percentage > $warningThreshold ) {
			print color "bold yellow";
			$subnetWARNINGThreshold++;
		}
	
		$percentage = $percentage." %";
		printf("%30s  %18s  %15s  %15s  %6s  %6s %8s\n", $name, $subnets, $subnetTree{$name}{$subnets}{start}, $subnetTree{$name}{$subnets}{end}, $subnetTree{$name}{$subnets}{capacity}, $subnetTree{$name}{$subnets}{used}, $percentage);
		print color "reset";
		$capacity += $subnetTree{$name}{$subnets}{capacity};
		$used += $subnetTree{$name}{$subnets}{used};
		$subnetElementsCount++;
	}
	$subnetTree{$name}{capacity} = $capacity;
	$subnetTree{$name}{used} = $used;
	$totalCapacity += $capacity;
	$totalUsed += $used;
	my $subpercentage = sprintf("%.1f", ($subnetTree{$name}{used}/$subnetTree{$name}{capacity})*100 );
	# if ( $subpercentage > $problemThreshold ) {
		# print color "bold red";
	# } elsif ( $subpercentage > $warningThreshold ) {
		# print color "bold yellow";
	# }
	$Term::ANSIColor::AUTORESET = 1;
	$subpercentage = $subpercentage." %";
	my $output = sprintf("%30s  %18s  %15s  %15s  %6s  %6s %8s", $name, "", "", "", $subnetTree{$name}{capacity}, $subnetTree{$name}{used},$subpercentage );
	if ( $subnetElementsCount eq $subnetFATALThreshold ) {
		# FATAL
		print BOLD WHITE ON_RED $output." <-- PROBLEM ! IMMEDIATE ACTION NEEDED !";
		logMe("warn", "All subnets related to $name ( ".join(@aboveThresholds, ", ")." ) are above CRITICAL levels. Immediate action needed!");
	} elsif ( $subnetElementsCount eq $subnetWARNINGThreshold ) {
		# WARNING
		print BOLD YELLOW $output." <-- WARNING !";
		logMe("warn", "All subnets related to $name ( ".join(@aboveThresholds, ", ")." ) are above warning levels. Further action may need soon.");
	} elsif ( $subnetElementsCount eq ( $subnetFATALThreshold + $subnetWARNINGThreshold ) ) {
		# WARNING
		print BOLD YELLOW $output." <-- WARNING !";
		logMe("warn", "All subnets related to $name ( ".join(@aboveThresholds, ", ")." ) are above warning and CRITICAL levels. Immediate action will be needed very soon!");
	} else { 
		# Everything is OK
		print BOLD GREEN $output;
	}
	print "\n\n";
	
}
print color 'bold yellow';
print "--------------------------------------------------------------------------------------------------------------\n";
print color 'bold white';
my $totalPercentage = sprintf("%.1f", (($totalUsed/$totalCapacity) * 100) );
if ( $totalPercentage > $problemThreshold ) {
	print color "bold red";
} elsif ( $totalPercentage > $warningThreshold ) {
	print color "bold yellow";
}
$totalPercentage = $totalPercentage." %";
printf("%30s  %18s  %15s  %15s  %6s  %6s %8s\n", "", "", "", "", $totalCapacity, $totalUsed, $totalPercentage );
print "--------------------------------------------------------------------------------------------------------------\n";
print color 'reset';

print "\n\nThere is also $notInTheList IPs active but not in the subnets above.\n";
print "Process took ".(time()-$processStartTime)." seconds to complete\n";
logMe("info", "checkIPs v".$version." finished in ".(time()-$processStartTime)." seconds.");

sub logMe( $ $ ) {
	my $logLevel = shift;
    my $logMessage = shift;
    my $now = POSIX::strftime("%Y-%d-%m %T", localtime);
    
    my $level = 5;
    my $quit  = 0;
	
	if    ( $logLevel =~ /debug/i ) 	{ $level = 10; }
	elsif ( $logLevel =~ /info/i ) 		{ $level = 5; }
	elsif ( $logLevel =~ /warn/i ) 	    { $level = 1; }
	elsif ( $logLevel =~ /err/i ) 		{ $level = 0; }
	elsif ( $logLevel =~ /fatal/i ) 	{ $level = -1; }
	else 								{ die $logLevel." can not be found in logLevels!!\n"; }
    
    if ( $level >= $defaultLogLevel ) {
        open(LOGFILE, ">> ".$logFilename) or die ("Can not open log file $logFilename for writing!");
        my @lines = split("\n", $logMessage);
        foreach my $msg ( @lines ) {
            chomp($msg);
            if ( $msg ) {
                print LOGFILE "[".$now."] ".$logLevel." ".$msg."\n";
				# print "[".$now."] ".$logLevel." ".$msg."\n";
                print "\n\nFATAL ERROR :" if($level < 0);
                print $msg."\n" if ($level < 0 );
            }
        }
        close(LOGFILE);
        exit if ($level < 0);
    }
}

sub uniq {
    my %seen;
    grep !$seen{$_}++, @_;
}

sub in_array {
     my ($arr,$search_for) = @_;
     my %items = map {$_ => 1} @$arr; 
     return (exists($items{$search_for}))?1:0;
}

sub findCapacity {
	my $start = shift;
	my $end = shift;
	
	my @startOctets = split(/\./, $start);
	my @endOctets = split(/\./, $end);
	my $debugOut = "";
	
	my $pointer = 0;
	my $outcome = 1;
	while ( $pointer < 4 ) {
		my $octet = 3-$pointer;
		# $debugOut .= "[$pointer -> $octet ($endOctets[$pointer]-$startOctets[$pointer] (".($endOctets[$pointer] - $startOctets[$pointer]).") * ".(256**$octet)." = ";
		my $diff = (($endOctets[$pointer] - $startOctets[$pointer]) * 256**$octet);
		$debugOut .= $diff.")] ";
		$outcome += $diff;
		$pointer++;		
	}
	return $outcome;
	# "[[SUM:$outcome]] ".$debugOut;
}

sub dec2bin {
  my $str = unpack("B32", pack("N", shift));
  return $str;
}
 
sub netmask2cidr {
    my ($mask, $network) = @_;
    my @octet = split (/\./, $mask);
    my @bits;
    my $binmask;
    my $binoct;
    my $bitcount=0;
 
    foreach (@octet) {
      $binoct = dec2bin($_);
      $binmask = $binmask . substr $binoct, -8;
    }
 
    # let's count the 1s
    @bits = split (//,$binmask);
    foreach (@bits) {
      if ($_ eq "1") {
        $bitcount++;
      }
    }
 
    return $bitcount;
}

sub swirl() {
	
	my $diff = 1;
	my $now = time();	
	
	if ( ( $now - $swirlTime ) gt 1 ) {
		if    ( $swirlCount%8 eq 0 ) 	{ print "\b|"; $swirlCount++; }
		elsif ( $swirlCount%8 eq 1 ) 	{ print "\b/"; $swirlCount++; }
		elsif ( $swirlCount%8 eq 2 ) 	{ print "\b-"; $swirlCount++; }
		elsif ( $swirlCount%8 eq 3 ) 	{ print "\b\\"; $swirlCount++; }
		elsif ( $swirlCount%8 eq 4 ) 	{ print "\b|"; $swirlCount++; }
		elsif ( $swirlCount%8 eq 5 ) 	{ print "\b/"; $swirlCount++; }
		elsif ( $swirlCount%8 eq 6 ) 	{ print "\b-"; $swirlCount++; }
		elsif ( $swirlCount%8 eq 7 ) 	{ print "\b\\"; $swirlCount++; }

		$swirlTime = $now;
	}
	return;
	
}

sub SetIPasActive {
	my $IP = shift;
	# print "Checking $IP in tree.";
	my @octets = split(/\./, $IP);
	my $IPnumber = ($octets[0] * 256**3) + ($octets[1] * 256**2) + ($octets[2] * 256) + ($octets[3]);
	# my $errorOut = "";
	foreach my $name ( keys %subnetTree ) {
		# $errorOut = "";
		foreach my $subnets ( keys %{$subnetTree{$name}} ) {
			my @startOctets = split(/\./, $subnetTree{$name}{$subnets}{start});
			my @endOctets = split(/\./, $subnetTree{$name}{$subnets}{end});
			my $startIPNumber = ($startOctets[0] * 256**3) + ($startOctets[1] * 256**2) + ($startOctets[2] * 256) + ($startOctets[3]);
			my $endIPNumber = ($endOctets[0] * 256**3) + ($endOctets[1] * 256**2) + ($endOctets[2] * 256) + ($endOctets[3]);
			#print "CHECKING : $IPnumber vs $startIPNumber <=> $endIPNumber\n";
			if ( $IPnumber >= $startIPNumber and $IPnumber <= $endIPNumber ) {
				# print "MATCH: $IP is in ".$subnetTree{$name}{$subnets}{start}." <=> ".$subnetTree{$name}{$subnets}{end}." range!\n";
				if ( $subnetTree{$name}{$subnets}{used} ) {
					$subnetTree{$name}{$subnets}{used}++;
				} else {
					$subnetTree{$name}{$subnets}{used} = 1;
				}
				return 1;
			} else {
				# print "NO MATCH: $IP is NOT in ".$subnetTree{$name}{$subnets}{start}." <=> ".$subnetTree{$name}{$subnets}{end}." range!\n";
				# $errorOut = "NO MATCH: $IP is NOT in ".$subnetTree{$name}{$subnets}{start}." <=> ".$subnetTree{$name}{$subnets}{end}." range!\n";
			}
		}
	}
	return 0;
}

sub date2timeStamp {
	my $datetime = shift;
	
	my $t = Time::Piece->strptime($datetime,"%Y/%m/%d %H:%M:%S");
	return $t->epoch;
}