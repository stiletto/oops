#!/usr/bin/perl

#
# This works only under Solaris
#
# How to use:
#
# 1. start oops as you usually do
# 2. start prex -o tnfdump.out -p `cat oops.pid`
#    in prex prompt:
#
#    prex> enable $all
#    prex> continue
#    
#    apply load to oops during some time
#    then press ^C. In prex prompt
#    prex> quit
#    Then prex will quit, but oops will run without interrupt.
#    To analyze:
#    tnfdump tnfdump.out | ./tnfanalyze.pl

while ($line = <>) {
    if ( $line =~ /----/ ) {last;}
}

while ($line = <>) {
    if ( $line =~ /----/ ) {last;}
}


while (<>) {
    ($etime, $delta, $pid, $lwpid, $tid, $_cpu, $probe_name, $descr) =
	split(" ");
#    print $probe_name, "\n";
    if ( $probe_name =~ /.*_start$/ ) {
	$resource_name = substr($probe_name, 0, (length $probe_name) -6);
	$resource_id = $resource_name."#".$tid;
	$resource_start_time{$resource_id} = $etime;
	$contention{$resource_name} += 1;
    };
    if ( $probe_name =~ /.*_stop$/ ) {
	$resource_name = substr($probe_name, 0, (length $probe_name) -5);
	$resource_id = $resource_name."#".$tid;
	$delta_usage = $etime - $resource_start_time{$resource_id};
	if (!defined($max_latency{$resource_name}) ) {
	    $max_latency{$resource_name} = $delta_usage;
	    $max_latency_tid{$resource_name} = $tid;
	    $sum_latency{$resource_name} = $delta_usage;
	    $num_latency{$resource_name} = 1;
	} else {
	    if ( $delta_usage > $max_latency{$resource_name} ) {
		$max_latency{$resource_name} = $delta_usage;
		$max_latency_tid{$resource_name} = $tid;
	    };
	    $sum_latency{$resource_name} += $delta_usage;
	    $num_latency{$resource_name} += 1;
	};

	# here we can count contention level
	$contention{$resource_name} -= 1;
	if ( !defined($max_contention{$resource_name}) ) {
	    $max_contention{$resource_name} = $contention{$resource_name};
	} else {
	    if ( $contention{$resource_name} > $max_contention{$resource_name} ) {
		$max_contention{$resource_name} = $contention{$resource_name};
		$max_contention_tid{$resource_name} = $tid;
	    }
	}
    };
}

foreach $resource_name (keys %max_latency) {
    print ">>> $resource_name\n";
    printf "max latency(ms) : %10.3f on thread $max_latency_tid{$resource_name}\n", $max_latency{$resource_name};
    printf "ave latency(ms) : %10.3f\n", $sum_latency{$resource_name}/$num_latency{$resource_name};
    printf "max contention  : %10d on thread $max_contention_tid{$resource_name}\n", $max_contention{$resource_name};
}
