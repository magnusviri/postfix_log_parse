#!/usr/bin/perl -w

use strict;
use Data::Dumper;
use Getopt::Std;

my $onsite_regex = '^10\.0\.0\.';
my $my_double_bounce_email = 'double-bounce@example.com'

my %options;
getopts("d:e:pr:s:vx",\%options);

usage() if $#ARGV < 0;

my $debug = $options{'d'} || 0;
my $dns_ip_pattern = "(.*)\\[([^\\[]+)\\]";
my $ip_port_pattern = "\\[([^\\[]+)\\]:(\\d+)";
my $email_pattern = "([^>]*)";

for my $file ( @ARGV ) {
	if ( -f $file ) {
		my $stats = process_log_file( $file );
		global_stats( $stats );
		print Dumper( $stats ) if $debug == 1;
		print_stuff( $stats );
	} else {
		print STDERR "Missing file: $file.\n";
	}
}

sub usage {
	my $name = $0;
	$name =~ s/.*\///;
	print<<EOF;
$name file [..file]

	-r regular expression to search for

	-s start on line
	-e end on line

	-v verbose output
	-x statistical output

	-p save as plist
	-d <NUM> print debugging text (1 = all stats, 2 = message groups, 3 = parsed log lines, 4 = full log lines, 5 lines that have links, 6 lines that don't have links
EOF
	exit;
}

sub process_log_file {
	my ( $file ) = @_;
	my $message_ids = {};
	my $process_pid_logs = {};
	my $process_pid_stack = {};
	my $queue_links = {};
	my $line_counter = 1;
	my $message_order = {};
	my $stats = { 'file' => $file };
	open FILE, "<", $file or die "Can't open $file $!";

	my $last_line = "";
	while ( <FILE> ) {
		$line_counter++;

		# Decide if I should process the line

		next if $options{'s'} and $line_counter <= $options{'s'};
		last if $options{'e'} and $line_counter > $options{'e'};
		my $full_line = $_;
		next if $options{'r'} and $full_line !~ /$options{'r'}/;

		# Remove the date and server string

		my ( $mon, $day, $hr, $min, $sec, $postfix_message );
		if ( $full_line =~ /^(...) {1,2}(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) \S+ postfix\/(.+)$/ ) {
			( $mon, $day, $hr, $min, $sec, $postfix_message ) = ( $1, $2, $3, $4, $5, $6 );
			$last_line = $postfix_message;
			print "$mon $day $hr:$min:$sec $postfix_message\n" if $debug == 3;
			print $full_line if $debug == 4;
		} elsif ( $full_line =~ /^(...) {1,2}(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) --- last message repeated (\d+) times? ---$/ ) {
			# TODO, if it matters, repeat this X many times.
			( $mon, $day, $hr, $min, $sec, $postfix_message ) = ( $1, $2, $3, $4, $5, $last_line );
			$last_line = "";
			print "$mon $day $hr:$min:$sec $postfix_message\n" if $debug == 3;
			print $full_line if $debug == 4;
		} else {
			print STDERR "First regex doesn't match: $full_line";
			next;
		}

		##################################################################################
		# Sort the log lines into messages (magic)

		if ( 0 ) { # dummy line
		} elsif ( $postfix_message =~ /^(\S+)\[(\d+)\]: statistics:/ ) {
			# throw away
			print "$postfix_message\n" if $debug == 6;

		} elsif ( $postfix_message =~ /^(\S+)\[(\d+)\]: ([ABCDEF0123456789]{8,14}): (.*)$/ ) {

			# Message ID found, track by message id
			my ( $process, $pid, $message_id, $log_message ) = ( $1, $2, $3, $4 );

			if ( ! $message_ids->{$message_id} ) {
				# First time this ID has been found, track it.
				$message_ids->{$message_id} = [];
				$message_order->{$line_counter} = $message_id;

				if ( $process eq 'smtpd' ) {
					# Move any previous smptd logs to this message
					process_pid_logs_to_message_ids( $process_pid_logs, $message_ids, $message_id, $process, $pid, 1 );
				}
			}
			push @{$message_ids->{$message_id}}, "$process $pid $message_id $log_message";
			push @{$process_pid_stack->{$process}->{$pid}}, $message_id;

			# Track connections between messages
			if ( $log_message =~ /queued as ([ABCDEF0123456789]*)\)/ ) {
#				$queue_links->{$process}->$message_id++;
# 				$queue_links->{$message_id}->{$1}++;
				$queue_links->{$1}->{$message_id}++;

				print "$log_message\n" if $debug == 5;

			} elsif ( $log_message =~ /forwarded as ([ABCDEF0123456789]*)\)/ ) {
#				$queue_links->{$process}->$message_id++;
# 				$queue_links->{$message_id}->{$1}++;
				$queue_links->{$1}->{$message_id}++;

				print "$log_message\n" if $debug == 5;

			} else {
				print "$log_message\n" if $debug == 6;
			}

		} elsif ( $postfix_message =~ /^(\S+)\[(\d+)\]: (.*)/ ) {
			my ( $process, $pid, $log_message ) = ( $1, $2, $3 );
			print "$log_message\n" if $debug == 6;

			# Track by process and pid

			if ( $#{$process_pid_stack->{$process}->{$pid}} < 0 ) {

				# There's no saved messages, save them for later
				push @{$process_pid_logs->{$process}->{$pid}}, $log_message;

				if ( $process eq 'smtpd' and ( $log_message =~ /^disconnect from / or $log_message eq 'fatal: too many errors - program terminated' ) ) {

					# smtpd finished, move messages to the message_ids array
					my $process_pid = "$process:$pid:$line_counter";
					$message_order->{$line_counter} = $process_pid;
					process_pid_logs_to_message_ids( $process_pid_logs, $message_ids, $process_pid, $process, $pid, 2 );

				}

			} else {

				# There's entires, move them to the message_ids array (does this really work right?)
				my $tracker_id = shift @{$process_pid_stack->{$process}->{$pid}};
				push @{$process_pid_logs->{$process}->{$pid}}, $log_message;
				process_pid_logs_to_message_ids( $process_pid_logs, $message_ids, $tracker_id, $process, $pid, 3 );

			}

		} else {

			# Can't figure out the process or pid
			push @{$process_pid_logs->{'none'}}, $postfix_message;
			print "$postfix_message\n" if $debug == 6;

		}

	}
	close( FILE );

	######################################################################################
	# Group related messages

	my $grouped_messages = {};
	for my $line_num ( sort { $a <=> $b } keys $message_order ) {
		my $message_id = $message_order->{$line_num};
		if ( ! $queue_links->{$message_id} ) {
			push @{$grouped_messages->{$message_id}}, $message_ids->{$message_id};
		} else {
			my $parent_id = (keys %{$queue_links->{$message_id}})[0];
			while ( $queue_links->{$parent_id} ) {
				$parent_id = (keys %{$queue_links->{$parent_id}})[0];
			}
			push @{$grouped_messages->{$parent_id}}, $message_ids->{$message_id};
		}
	}

	if ( $debug == 7 ) {
		my $queue_links_count = keys %$queue_links;
		print "Links: $queue_links_count\n";
		for my $link1 ( sort keys $queue_links ) {
			my $child_link_count = keys %{$queue_links->{$link1}};
			if ( $child_link_count > 1 ) {
				print "$link1\n";
				print Dumper($queue_links->{$link1});
				die;
			}
			for my $link2 ( sort keys %{$queue_links->{$link1}} ) {
				print "$queue_links->{$link1}->{$link2} $link1 $link2\n";
			}
		}

		die "Debug 7 early exit.\n";
	}

	if ( $debug == 8 ) {
		print Dumper( $grouped_messages );
		die "Debug 8 early exit.\n";
	}

	######################################################################################
	# Generate stats for each group of messages

	for my $line_num ( sort { $a <=> $b } keys $message_order ) {
		my $message_id = $message_order->{$line_num};
		if ( $grouped_messages->{$message_id} ) {
			generate_group_stats( $stats, $grouped_messages->{$message_id} );
		}
	}

	######################################################################################
	# Cleanup process_pid_logs

	delete $process_pid_logs->{'master'};
	delete $process_pid_logs->{'anvil'};
	delete $process_pid_logs->{'scache'};
	delete $process_pid_logs->{'postscreen'};
	for my $process ( qw( smtpd smtp postsuper pickup cleanup ) ) {
		for my $pid ( keys %{$process_pid_logs->{$process}} ) {
			if ( $#{$process_pid_logs->{$process}->{$pid}} < 0 ) {
				delete $process_pid_logs->{$process}->{$pid};
			}
		}
	}

	$stats->{'stranded'} = $message_ids->{'stranded'};
	$stats->{'process_pid_logs'} = $process_pid_logs;

	return $stats;
}

sub generate_group_stats {
	my ( $stats, $grouped_messages ) = @_;
	print "-------------------------\n" if $debug == 2;
	my $this_group_stats = {};
	my $counter = 0;

	######################################################################################
	######################################################################################
	# Loop through each message in the group

	for my $message ( @$grouped_messages ) {
		for my $line ( @{$message} ) {
			if ( 0 ) { # dummy line

######### ANVIL
			} elsif ( $line =~ /^anvil (\d+) statistics/ ) {

			} elsif ( $line =~ /^anvil / ) {
				print STDERR "Found unprocessed anvil: $line\n";

######### BOUNCE

			} elsif ( $line =~ /^bounce (\d+) ([^\s]+) sender non-delivery notification: (.*)/ ) {
				$this_group_stats->{'bounce'} = $3;

			} elsif ( $line =~ /^bounce (\d+) ([^\s]+) postmaster non-delivery notification: (.*)/ ) {
				$this_group_stats->{'postmaster_bounce'} = $3;

			} elsif ( $line =~ /^bounce / ) {
				print STDERR "Found unprocessed bounce: $line\n";

######### CLEANUP

			} elsif ( $line =~ /^cleanup (\d+) ([^\s]+) warning: ([^:]*): (.*) from $dns_ip_pattern; from=<$email_pattern> to=<$email_pattern> proto=(.*) helo=<(.*)>(.*)/ ) {
				$this_group_stats->{'warning'} = $3;

			} elsif ( $line =~ /^cleanup (\d+) ([^\s]+) warning: unknown command in (.*) map: (.*)/ ) {

			} elsif ( $line =~ /^cleanup (\d+) ([^\s]+) message-id=<$email_pattern>/ ) {
			} elsif ( $line =~ /^cleanup (\d+) ([^\s]+) message-id=<>/ ) {
			} elsif ( $line =~ /^cleanup (\d+) ([^\s]+) message-id=.*/ ) {

			} elsif ( $line =~ /^cleanup / ) {
				print STDERR "Found unprocessed cleanup: $line\n";

######### LOCAL

			} elsif ( $line =~ /^local (\d+) ([^\s]+) to=<$email_pattern>, orig_to=<$email_pattern>, relay=(.*), delay=(.*), delays=(.*), dsn=(.*), status=(.*)/ ) {
				my ( $to, $orig_to, $relay, $status ) = ( $3, $4, $5, $9 );
				$this_group_stats->{'orig_to'} = lc($orig_to) if ! $this_group_stats->{'orig_to'};
				if ( $relay ne 'local' ) {
					push @{$this_group_stats->{'relays'}}, lc($relay);
					if ( $status =~ /sent \(forwarded as (.*)\)/ ) {
						$this_group_stats->{'local_orig_status'} = "sent (forwarded as .*)";
					} else {
						$this_group_stats->{'local_orig__status'} = $this_group_stats->{'local_status'};
						push @{$this_group_stats->{'to'}}, lc($to);
					}
				} else {
					$this_group_stats->{'local_relay'}++;
				}

			} elsif ( $line =~ /^local (\d+) ([^\s]+) to=<$email_pattern>, relay=(.*), delay=(.*), delays=(.*), dsn=(.*), status=(.*)/ ) {
				my ( $to, $relay, $status ) = ( $3, $4, $8 );
				if ( $relay ne 'local' ) {
					push @{$this_group_stats->{'relays'}}, lc($relay);
					if ( $status =~ /sent \(forwarded as (.*)\)/ ) {
						$this_group_stats->{'local_status'} = "sent (forwarded as .*)";
					} else {
						$this_group_stats->{'local_status'} = $this_group_stats->{'local_status'};
						push @{$this_group_stats->{'to'}}, lc($to);
					}
				} else {
					$this_group_stats->{'local_relay'}++;
				}


			} elsif ( $line =~ /^local (\d+) ([^\s]+) table hash:\/etc\/aliases\(0,lock|no_regsub|no_proxy|no_unauth|fold_fix\) has changed -- restarting/ ) {

			} elsif ( $line =~ /^local / ) {
				print STDERR "Found unprocessed local: $line\n";

######### PICKUP

			} elsif ( $line =~ /^pickup (\d+) ([^\s]+) uid=(.*) from=<$email_pattern>/ ) {
				$this_group_stats->{'pickup'} = $4;

			} elsif ( $line =~ /^pickup / ) {
				print STDERR "Found unprocessed pickup: $line\n";

######### PIPE

			} elsif ( $line =~ /^pipe (\d+) ([^\s]+) to=<$email_pattern>, orig_to=<$email_pattern>, relay=(.*), delay=(.*), delays=(.*), dsn=(.*), status=(.*)/ ) {
				my ( $to, $orig_to, $relay, $status ) = ( $3, $4, $5, $9 );

				push @{$this_group_stats->{'relays'}}, lc($relay);
				push @{$this_group_stats->{'to'}}, lc($to);
				$this_group_stats->{'orig_to'} = lc($orig_to) if ! $this_group_stats->{'orig_to'};
				$this_group_stats->{'pipe_status'} = $status;


			} elsif ( $line =~ /^pipe (\d+) ([^\s]+) to=<$email_pattern>, relay=(.*), delay=(.*), delays=(.*), dsn=(.*), status=(.*)/ ) {
				my ( $to, $relay, $status ) = ( $3, $4, $8 );

				push @{$this_group_stats->{'relays'}}, lc($relay);
				push @{$this_group_stats->{'to'}}, lc($to);
				$this_group_stats->{'pipe_status'} = $status;

			} elsif ( $line =~ /^pipe / ) {
				print STDERR "Found unprocessed pipe: $line\n";

######### QMGR

			} elsif ( $line =~ /^qmgr (\d+) ([^\s]+) from=<$email_pattern>, size=(\d+), nrcpt=(\d+)/ ) {
				$this_group_stats->{'from'} = lc($3);
				$this_group_stats->{'size'} = $4;
				$this_group_stats->{'nrcpt'} = $5;

			} elsif ( $line =~ /^qmgr (\d+) ([^\s]+) from=<>, size=(\d+), nrcpt=(\d+)/ ) {
				$this_group_stats->{'from'} = "";
				$this_group_stats->{'size'} = $4;
				$this_group_stats->{'nrcpt'} = $5;

			} elsif ( $line =~ /^qmgr (\d+) ([^\s]+) skipped, still being delivered/ ) {
				$this_group_stats->{'qmgr_skipped'} = 1;

			} elsif ( $line =~ /^qmgr (\d+) ([^\s]+) from=<$email_pattern>, status=(.*)/ ) {
				$this_group_stats->{'qmgr_status'} = $4;

			} elsif ( $line =~ /^qmgr (\d+) ([^\s]+) removed/ ) {

			} elsif ( $line =~ /^qmgr / ) {
				print STDERR "Found unprocessed qmgr: $line\n";

######### SCACHE
			} elsif ( $line =~ /^scache (\d+) statistics/ ) {

			} elsif ( $line =~ /^scache / ) {
				print STDERR "Found unprocessed scache: $line\n";

######### SMTP

			} elsif ( $line =~ /smtp (\d+) ([^\s]+) to=<$email_pattern>, orig_to=<$email_pattern>, relay=(.*), delay=(.*), delays=(.*), dsn=(.*), status=(.*)/ ) {
				my ( $to, $orig_to, $relay, $status ) = ( $3, $4, $5, $9 );
				$this_group_stats->{'orig_to'} = lc($orig_to) if ! $this_group_stats->{'orig_to'};
				if ( $relay !~ /^127.0.0.1\[127.0.0.1\]/ ) {
					push @{$this_group_stats->{'relays'}}, lc($relay);
					push @{$this_group_stats->{'to'}}, lc($to);
					parse_smtp_status( $status, $this_group_stats, "2" );
				} else {
					$this_group_stats->{'local_relay'}++;
				}

			} elsif ( $line =~ /smtp (\d+) ([^\s]+) to=<$email_pattern>, relay=(.*), delay=(.*), delays=(.*), dsn=(.*), status=(.*)/ ) {
				my ( $to, $relay, $status ) = ( $3, $4, $8 );
				if ( $relay !~ /^127.0.0.1\[127.0.0.1\]/ ) {
					push @{$this_group_stats->{'relays'}}, lc($relay);
					push @{$this_group_stats->{'to'}}, lc($to);
					parse_smtp_status( $status, $this_group_stats, "1" );

				} else {
					$this_group_stats->{'local_relay'}++;
				}

			} elsif ( $line =~ /^smtp (\d+) ([^\s]+) host $dns_ip_pattern said: (.*)/ ) {
				push @{$this_group_stats->{'smtp_host_messages'}}, $5;
				push @{$this_group_stats->{'smtp_status'}}, "other";

			} elsif ( $line =~ /^smtp (\d+) ([^\s]+) warning: hostname (.*) does not resolve to address (.*): nodename nor servname provided, or not known/ ) {
				push @{$this_group_stats->{'smtp_messages'}}, "warning: hostname $3 does not resolve to address $4";
				push @{$this_group_stats->{'smtp_status'}}, "other";

			} elsif ( $line =~ /^smtp (\d+) ([^\s]+) enabling PIX workarounds: disable_esmtp delay_dotcrlf for $dns_ip_pattern:(.*)/ ) {
				push @{$this_group_stats->{'smtp_messages'}}, "enabling PIX workaround";
				push @{$this_group_stats->{'smtp_status'}}, "other";

			} elsif ( $line =~ /^smtp (\d+) ([^\s]+) host $dns_ip_pattern refused to talk to me: (.*)/ ) {
				push @{$this_group_stats->{'smtp_messages'}}, "host ${3}[$4] refused to talk to me: $5";
				push @{$this_group_stats->{'smtp_status'}}, "other";

			# smtp 48864 55FF1D23F67 lost connection with mstar2.net[192.230.66.93] while receiving the initial server greeting
			} elsif ( $line =~ /^smtp (\d+) ([^\s]+) lost connection with $dns_ip_pattern while (.*)/ ) {
				push @{$this_group_stats->{'smtp_messages'}}, "lost connection with ${3}[$4] while $5";
				push @{$this_group_stats->{'smtp_status'}}, "other";

			} elsif ( $line =~ /^smtp (\d+) ([^\s]+) conversation with $dns_ip_pattern timed out while (.*)/ ) {
				push @{$this_group_stats->{'smtp_messages'}}, "conversation with ${3}[$4] timed out while $5";
				push @{$this_group_stats->{'smtp_status'}}, "other";

			# smtp 47551 85FF812E2E39 3 connect to smail3.nrl.navy.mil[132.250.4.151]:25: Connection refused
			} elsif ( $line =~ /^smtp (\d+) ([^\s]+) ?\d* connect to $dns_ip_pattern:(.*): Connection refused/ ) {
				push @{$this_group_stats->{'smtp_messages'}}, "connect to ${3}[$4]:$5: Connection refused";
				push @{$this_group_stats->{'smtp_status'}}, "other";

			} elsif ( $line =~ /^smtp / ) {
				print STDERR "Found unprocessed smtp: $line\n";

######### SMTPD

# lost connection/timeout

			} elsif ( $line =~ /smtpd (\d+) (.*) lost connection after (.*) from $dns_ip_pattern/ ) {
				$this_group_stats->{'lost_connection'} = $3;

			} elsif ( $line =~ /smtpd (\d+) (.*) timeout after (.*) from $dns_ip_pattern/ ) {
				$this_group_stats->{'timeout_connection'} = $3;

			} elsif ( $line =~ /smtpd (\d+) (.*) improper command pipelining after (.*) from $dns_ip_pattern: / ) {
				$this_group_stats->{'improper_command_pipelining_$3'} = $5;
				$this_group_stats->{'improper_command_pipelining'} = $5;

# Unknown user

			} elsif ( $line =~ /smtpd (\d+) (.*) error: validate response: unable to lookup user record for: $email_pattern/ ) {

			} elsif ( $line =~ /smtpd (\d+) (.*) error: get user record: unable to open user record for user=(.*)/ ) {
				$this_group_stats->{'user_does_not_exist'} = $3;

			} elsif ( $line =~ /smtpd (\d+) (.*) error: verify password: unable to lookup user record for: user=(.*)/ ) {
				$this_group_stats->{'user_does_not_exist'} = $3;

# Incorrect password

			} elsif ( $line =~ /smtpd (\d+) (.*) warning: $dns_ip_pattern: (.*) authentication failed/ ) {

			} elsif ( $line =~ /smtpd (\d+) (.*) error: validate response: error: Credentials could not be verified, username or password is invalid./ ) {

			} elsif ( $line =~ /smtpd (\d+) (.*) error: validate response: authentication failed for user=(.*) \(method=(.*)\)/ ) {
				$this_group_stats->{'incorrect_password'} = lc($3);

			} elsif ( $line =~ /smtpd (\d+) (.*) error: verify password: authentication failed: user=(.*)/ ) {
				$this_group_stats->{'incorrect_password'} = lc($3);

			} elsif ( $line =~ /smtpd (\d+) (.*) error: authentication aborted by client/ ) {
				$this_group_stats->{'auth_abort'} = 1;

			} elsif ( $line =~ /smtpd (\d+) (.*) error: authentication failed/ ) {

			} elsif ( $line =~ /smtpd (\d+) (.*) error: verify password: error: Credentials could not be verified, username or password is invalid/ ) {

# Connect

			} elsif ( $line =~ /smtpd (\d+) (.*) connect from $dns_ip_pattern/ ) {
				$this_group_stats->{'dns'} = $3 if ! $this_group_stats->{'dns'};
				$this_group_stats->{'ip'} = $4 if ! $this_group_stats->{'ip'};
				$stats->{'connection_count'}++;

# Login

			} elsif ( $line =~ /smtpd (\d+) (.*) verify password: (.*): authentication succeeded for user=(.*)/ ) {

			} elsif ( $line =~ /smtpd (\d+) (.*) client=$dns_ip_pattern, sasl_method=(.*), sasl_username=(.*)/ ) {
				$this_group_stats->{'dns'} = $3 if ! $this_group_stats->{'dns'};
				$this_group_stats->{'ip'} = $4 if ! $this_group_stats->{'ip'};
				$this_group_stats->{'auth_correct_user'} = $6;
				$this_group_stats->{'auth_correct_from'} = "$3 $4";
				$this_group_stats->{'auth_correct_method'} = $5;

			} elsif ( $line =~ /smtpd (\d+) (.*) client=$dns_ip_pattern/ ) {
				$this_group_stats->{'dns'} = $3 if ! $this_group_stats->{'dns'};
				$this_group_stats->{'ip'} = $4 if ! $this_group_stats->{'ip'};

# Warning/Error/Fatal/etc/restarts

			} elsif ( $line =~ /smtpd (\d+) (.*) warning: Illegal address syntax from $dns_ip_pattern in MAIL command: <$email_pattern>/ ) {

			} elsif ( $line =~ /smtpd (\d+) (.*) warning: hostname (.*) does not resolve to address (.*)/ ) {

			} elsif ( $line =~ /smtpd (\d+) (.*) warning: (.*)/ ) {

			} elsif ( $line =~ /smtpd (\d+) (.*) SSL_accept error from $dns_ip_pattern: (.*)/ ) {

			} elsif ( $line =~ /smtpd (\d+) (.*) improper command pipelining after DATA from $dns_ip_pattern:/ ) {

			} elsif ( $line =~ /smtpd (\d+) (.*) fatal: too many errors - program terminated/ ) {

			} elsif ( $line =~ /smtpd (\d+) (.*) table hash:\/etc\/aliases\(0,lock|fold_fix\) has changed -- restarting/ ) {

			} elsif ( $line =~ /smtpd (\d+) (.*) error: malformed response to: AUTH CRAM-MD5: missing digest/ ) {

# Noqueue

			} elsif ( $line =~ /smtpd (\d+) (.*) NOQUEUE: ([^:]+): RCPT from $dns_ip_pattern: (.*); from=<$email_pattern> to=<$email_pattern> proto=(.*) helo=<(.*)>/ ) {
				my ( $type, $noqueue_message, $from, $to, $proto, $helo ) = ( $3, $6, $7, $8, $9, $10 );
				if ( $noqueue_message =~ /(.*) <$email_pattern>: Recipient address rejected: User unknown in local recipient table/ ) {
					$this_group_stats->{'rejected_from'} = lc($from);
					$this_group_stats->{'noqueue_action'} = "$type: unknown recipient";
					push @{$this_group_stats->{'unknown_to'}}, lc($2);

				} elsif ( $noqueue_message =~ /(.*) <$email_pattern>: (.*) address rejected: (.*)/ ) {
					$this_group_stats->{'noqueue_action'} = "$type: $4 $3";

				} elsif ( $noqueue_message =~ /<$email_pattern>: (.*) address triggers (.*) action/ ) {
					$this_group_stats->{'noqueue_action'} = "$type: $3 $2";

				} elsif ( $noqueue_message =~ /<$dns_ip_pattern>: Client host triggers DISCARD action/ ) {
					$this_group_stats->{'noqueue_action'} = "$type: Client";

				} elsif ( $noqueue_message =~ /(.*) Service unavailable; Client host \[(.*)\] blocked using zen.spamhaus.org;/ ) {
					$this_group_stats->{'noqueue_action'} = "$type: spamhaus";

				} elsif ( $noqueue_message =~ /(.*) <(.*)>: Helo command rejected: (.*)/ ) {
					$this_group_stats->{'noqueue_action'} = "$type: Helo rejected: $3";

				} else {

					$this_group_stats->{'noqueue_action'} = "$type: $noqueue_message";

				}
				$this_group_stats->{'noqueue'} = $type;
				$this_group_stats->{'noqueue_message'} = $noqueue_message;
				$this_group_stats->{$type} = 1;

				my $domain = $from;
				$domain =~ s/.*@//;
				if ( $type eq 'discard' or $type eq 'reject' ) {
					$domain =~ s/.*(\.[^.]+)$/$1/;
				} else {
					$domain =~ s/.*\.([^.]+\.[^.]+)$/$1/;
				}
				$this_group_stats->{"${type}_domains"} = $domain;

			} elsif ( $line =~ /smtpd (\d+) (.*) NOQUEUE: reject: MAIL from $dns_ip_pattern: (.*) Message size exceeds fixed limit; proto=(.*) helo=<(.*)>/ ) {
				$this_group_stats->{'noqueue_action'} = "reject: Size limit exceeded";
				$this_group_stats->{'noqueue'} = 'reject';

			} elsif ( $line =~ /smtpd (\d+) (.*) NOQUEUE: / ) {
				print STDERR "Noqueue didn't match above pattern: $line\n";

# Other rejects/discards

			} elsif ( $line =~ /smtpd (\d+) (.*) discard: RCPT from $dns_ip_pattern: <$email_pattern>: Recipient address triggers DISCARD action; from=<$email_pattern> to=<$email_pattern> proto=(.*) helo=<(.*)>/ ) {
				$this_group_stats->{'queued_discards'}++;

			} elsif ( $line =~ /smtpd (\d+) (.*) reject: RCPT from $dns_ip_pattern: (.*) <$email_pattern>: Recipient address rejected: (.*); from=<$email_pattern> to=<$email_pattern> proto=(.*) helo=<(.*)>/ ) {
				$this_group_stats->{'queued_rejects'}++;

			} elsif ( $line =~ /smtpd (\d+) (.*) warning: (.*): queue file size limit exceeded/ ) {

			} elsif ( $line =~ /smtpd (\d+) (.*) warning: hostname (.*) does not resolve to address (.*): nodename nor servname provided, or not known/ ) {
				push @{$this_group_stats->{'smtpd_warnings'}}, "warning: hostname $3 does not resolve to address $4";

			} elsif ( $line =~ /smtpd (\d+) (.*) disconnect from $dns_ip_pattern/ ) {

			} elsif ( $line =~ /^smtpd / ) {
				print STDERR "Found unprocessed smtpd: $line\n";

######### NOTHING

			} elsif ( $line =~ /^postsuper / ) {

			} elsif ( $line =~ /^error / ) {

			} else {
				print STDERR "Found unprocessed line: $line\n";
			}
		}

		print Dumper( $message ) if $debug == 2;
# 		print Dumper( $message ) if ! $this_group_stats->{'ip'};

		$counter++;
	}

	######################################################################################
	######################################################################################
	# Analyze message group (log file is all analyzed)

	######### All messages stats

	for my $k ( sort keys %$this_group_stats ) {
		my $v = $this_group_stats->{$k};
		if ( $k !~ /^size$/ ) { #dns auth_correct_from  noqueue_message rejected_from from ip smtp_host_messages
			if ( ref( $v ) eq "ARRAY" ) {
				print "$k =\n" if $debug == 2;
				for my $vv ( @$v ) {
					$stats->{'all_message_stats'}->{$k}->{$vv}++;
					print "\t$vv\n" if $debug == 2;
				}
			} else {
				$stats->{'all_message_stats'}->{$k}->{$v}++;
				print "$k = $v\n" if $debug == 2;
			}
		}
	}

	######### Conditional messages stats

	if ( $this_group_stats->{'orig_to'} and $this_group_stats->{'to'} ) {
		for my $this_to ( @{$this_group_stats->{'to'}} ) {
			$stats->{'to_without_orig'}->{$this_to}++;
		}
	}

	######### Incorrect passwords

	if ( $this_group_stats->{'incorrect_password'} ) {
		my $identifier = "?";
		if ( $this_group_stats->{'ip'} and $this_group_stats->{'dns'} ) {
			$identifier = $this_group_stats->{'ip'}."[".$this_group_stats->{'dns'} ."]";
		}
		$stats->{'incorrect_password_ips'}->{$this_group_stats->{'incorrect_password'}}->{$identifier}++;
	}

	######### Accepted email from

	if ( $this_group_stats->{'incorrect_password'} or
		 $this_group_stats->{'user_does_not_exist'} or
		 $this_group_stats->{'lost_connection'} or
		 $this_group_stats->{'noqueue'} )
	{
		#print Dumper( $this_group_stats );
	} else {
# 		print Dumper( $this_group_stats );
# 		print Dumper( $grouped_messages );
	}

	######### Authenticated mail from/to

	my $identifier = '0.0.0.0';
	$identifier = $this_group_stats->{'ip'} if $this_group_stats->{'ip'};

	my $group = "";
	if ( 0 ) {

	} elsif ( $this_group_stats->{'pickup'} and $this_group_stats->{'pickup'} eq 'root' ) {
		$group = 'root_stuff';
#		$identifier = "no_ident";

	} elsif ( $this_group_stats->{'from'} and $this_group_stats->{'from'} eq $my_double_bounce_email ) {
		$group = 'double_bounce_stuff';
#		$identifier = "no_ident";

	## Allowed by IP
	} elsif ( $this_group_stats->{'ip'} and $this_group_stats->{'ip'} =~ /$onsite_regex/ ) {
		if ( $this_group_stats->{'noqueue'} or $this_group_stats->{'lost_connection'} or ( $this_group_stats->{'timeout_connection'} and $this_group_stats->{'timeout_connection'} ne 'END-OF-MESSAGE' )) {
			$group = 'my_user_errors_stuff';
		} else {
			$group = 'onsite_stuff';
			$identifier = "no_ident";
		}

	## Allowed by AUTH
	} elsif ( $this_group_stats->{'auth_correct_user'} ) {
		if ( $this_group_stats->{'noqueue'} or $this_group_stats->{'lost_connection'} or ( $this_group_stats->{'timeout_connection'} and $this_group_stats->{'timeout_connection'} ne 'END-OF-MESSAGE' ) ) {
			$group = 'my_user_errors_stuff';
		} else {
			$group = 'offsite_auth_stuff';

			if ( $this_group_stats->{'dns'} ) {
				$identifier = $this_group_stats->{'dns'};
				$identifier =~ s/.*\.(.*\..*)/$1/;
			} else {
				$identifier = "no_ident";
			}

		}

	## No email sent
	} elsif ( ! $this_group_stats->{'relays'} ) {
		if ( $this_group_stats->{'noqueue'} or
			$this_group_stats->{'lost_connection'} or
			$this_group_stats->{'incorrect_password'} or
			$this_group_stats->{'user_does_not_exist'} or
			( $this_group_stats->{'timeout_connection'} and $this_group_stats->{'timeout_connection'} ne 'END-OF-MESSAGE' ) )
		{
			$group = 'nosend_errors_stuff';
			$identifier = "no_ident";
		} else {
			$group = 'immediate_disconnect_stuff';
			$identifier = "no_ident";
		}



	## Not sure what this group is...
	} elsif ( $this_group_stats->{'noqueue'} or $this_group_stats->{'lost_connection'} or ( $this_group_stats->{'timeout_connection'} and $this_group_stats->{'timeout_connection'} ne 'END-OF-MESSAGE' )) {
		$group = 'relayed_but_with_drops_stuff';
		$identifier = $this_group_stats->{'ip'};
	} elsif ( $this_group_stats->{'incorrect_password'} or $this_group_stats->{'user_does_not_exist'} ) {
		$group = 'relayed_but_with_drops_stuff';
		$identifier = "no_ident";
		$identifier = $this_group_stats->{'ip'};

	## External senders
	} else {
		$group = 'external_senders_stuff';
		for my $to ( @{$this_group_stats->{'to'}} ) {
			$stats->{'recipient_tracking'}->{$to}->{$this_group_stats->{'from'}}++;
		}
#		print Dumper( $this_group_stats );
	}

	$stats->{$group.'_count'}++;
	$stats->{$group} = {} if ! $stats->{$group};
	segmented_stats( $stats->{$group}, $identifier, $this_group_stats );

	if ( $this_group_stats->{'auth_correct_user'} ) {
		$stats->{'auth_method_users'}->{$this_group_stats->{'auth_correct_method'}}->{$this_group_stats->{'auth_correct_user'}}++ if $this_group_stats->{'auth_correct_method'};
	}

# 	print "------------------------------------------------\n";

}

##########################################################################################
##########################################################################################

sub segmented_stats {
	my ( $stats, $name, $this_group_stats ) = @_;

	$stats->{$name} = {} if ! $stats->{$name};

	while ( my ( $k, $v ) = each %$this_group_stats ) {
		if ( $k !~ /^size$/ ) { #don't record size stats
			if ( ref( $v ) eq "ARRAY" ) {
				for my $vv ( @$v ) {
					$stats->{$name}->{'message_stats'}->{$k}->{$vv}++;
				}
			} else {
				$stats->{$name}->{'message_stats'}->{$k}->{$v}++;
			}
		}
	}
}

sub global_stats {
	my ( $stats ) = @_;

	# Relays

	$stats->{'total_sent'} = 0;
	while ( my ( $relay, $count ) = each %{$stats->{'all_message_stats'}->{'relays'}} ) {
		$relay =~ s/\[.*//;
		my @parts = reverse( split( /\./, $relay ) );
		while ( $#parts >= 0 ) {
			if ( $parts[0] !~ /^com$|^net$|^org$/ or $#parts < 2 ) {
				$stats->{'relay_counts'}->{join( '.', @parts )} += $count;
			}
			pop @parts;
		}
		$stats->{'total_sent'} += $count if $relay ne 'dovecot';
	}

	while ( my ( $dns, $count ) = each %{$stats->{'all_message_stats'}->{'dns'}} ) {
		$dns =~ s/\[.*//;
		my @parts = reverse( split( /\./, $dns ) );
		while ( $#parts >= 0 ) {
			if ( $parts[0] !~ /^com$|^net$|^org$/ or $#parts < 2 ) {
				$stats->{'dns_counts'}->{join( '.', @parts )} += $count;
			}
			pop @parts;
		}
		$stats->{'total_from'} += $count if $dns ne 'dovecot';
	}

}

##########################################################################################
##########################################################################################

sub print_stuff {
	my ( $stats ) = @_;

	if ( 0 ) {

# unknown from auth_correct_from
# plain from auth_correct_method
# bounce

	} elsif ( defined $options{'x'} ) {
		my $connection_count = $stats->{'connection_count'} || 0;
		my $lost_connection = add_up_counts( $stats->{'all_message_stats'}->{'lost_connection'} );
		my $timeout_connection = add_up_counts( $stats->{'all_message_stats'}->{'timeout_connection'});
		my $logins = add_up_counts( $stats->{'all_message_stats'}->{'auth_correct_user'} );
		my $incorrect_password = add_up_counts( $stats->{'all_message_stats'}->{'incorrect_password'} );


		my $stats2 = [
			[ 'file',					$stats->{'file'} ],
			[ 'connection_count',		$connection_count ],
			[ 'lost_connection',		$lost_connection ],
			[ 'timeout_connection',		$timeout_connection ],

			[ 'non_broke_connection',	$connection_count-$lost_connection-$timeout_connection ],

			[ 'sent',					$stats->{'total_sent'} || 0 ],
			[ 'dovecot',				$stats->{'relay_counts'}->{'dovecot'} || 0 ],
			[ 'logins',					$logins ],
			[ 'incorrect_password',		$incorrect_password ],

			[ 'discard',				$stats->{'all_message_stats'}->{'noqueue'}->{'discard'} || 0 ],
			[ 'reject',					$stats->{'all_message_stats'}->{'noqueue'}->{'reject'} || 0 ],
			[ 'hold',					$stats->{'all_message_stats'}->{'noqueue'}->{'hold'} || 0 ],
			[ 'warn',					$stats->{'all_message_stats'}->{'noqueue'}->{'warn'} || 0 ],
			[ 'header warning',			$stats->{'all_message_stats'}->{'noqueue'}->{'warning'} || 0 ],



# 			[ 'local forwarded',		$stats->{'local_status'}->{'sent (forwarded as .*)'} || 0 ],
# 			[ 'local forwarded orig',	$stats->{'local_orig_status'}->{'sent (forwarded as .*)'} || 0 ],
# 			[ 'smtp_count',				$stats->{'smtp_count'} || 0 ],
# 			[ 'deferred d 2',			$stats->{'smtp_list'}->{'deferred d 2'} || 0 ],
# 			[ 'deferred d 2',			$stats->{'smtp_list'}->{'deferred d 2'} || 0 ],
# 			[ 'sent 250 a 2',			$stats->{'smtp_list'}->{'sent 250 a 2'} || 0 ],
# 			[ 'deferred 451 c 1',		$stats->{'smtp_list'}->{'deferred 451 c 1'} || 0 ],
# 			[ 'bounced d 1',			$stats->{'smtp_list'}->{'bounced d 1'} || 0 ],
# 			[ 'bounced d 2',			$stats->{'smtp_list'}->{'bounced d 2'} || 0 ],
# 			[ 'deferred d 1',			$stats->{'smtp_list'}->{'deferred d 1'} || 0 ],
# 			[ 'sent 250 a 1',			$stats->{'smtp_list'}->{'sent 250 a 1'} || 0 ],
		];
		my @headers = ();
		my @fields = ();
		foreach my $stats3 ( @$stats2 ) {
			push @headers, $$stats3[0];
			push @fields, $$stats3[1];
		}
		if ( ! $stats->{'header_printed'} ) {
			print join( "\t", @headers )."\n";
			$stats->{'header_printed'} = 1;
		}
		print join( "\t", @fields )."\n";

	} else {

		print "File: $stats->{'file'}\n";

		print "##############################\n";

		if ( $stats->{'relay_counts'} ) {
			print_sorted_by_value( $stats, 'relay_counts', 0, 20 );
		}
		print "\n";

		#####################################################################################
		## local users

		print "##############################\n";

		my $onsite_email_count = $stats->{'onsite_stuff_count'} || 0;
		my $offsite_email_count = $stats->{'offsite_auth_stuff_count'} || 0;
		my $my_users_email_count = $onsite_email_count + $offsite_email_count;
		my $authenticated_count = add_up_counts( $stats->{'all_message_stats'}->{'auth_correct_user'} );
		my $non_authenticated_count = $my_users_email_count - $authenticated_count;

		my $server_to_count = {};
		my $onsite_sort = {};
		my $offsite_recipients = 0;
		my $onsite_recipients = 0;
		while ( my  ( $domain, $hash ) = each %{$stats->{'onsite_stuff'}} ) {
			for my $ip ( keys $hash->{'message_stats'}->{'ip'} ) {
				$onsite_sort->{$domain} += $hash->{'message_stats'}->{'ip'}->{$ip};
			}
			for my $to ( keys $hash->{'message_stats'}->{'to'} ) {
				$server_to_count->{$to} += $hash->{'message_stats'}->{'to'}->{$to};
				$onsite_recipients += $hash->{'message_stats'}->{'to'}->{$to};
			}
		}
		my $offsite_sort = {};
		while ( my  ( $domain, $hash ) = each %{$stats->{'offsite_auth_stuff'}} ) {
			for my $ip ( keys $hash->{'message_stats'}->{'ip'} ) {
				$offsite_sort->{$domain} += $hash->{'message_stats'}->{'ip'}->{$ip};
			}
			for my $to ( keys $hash->{'message_stats'}->{'to'} ) {
				$server_to_count->{$to} += $hash->{'message_stats'}->{'to'}->{$to};
				$offsite_recipients += $hash->{'message_stats'}->{'to'}->{$to};
			}
		}
		my $to_domains_users_hash = {};
		my $to_domains_total_hash = {};
		my $total_recipients = 0;
		for my $to ( keys $server_to_count ) {
			$total_recipients += $server_to_count->{$to};
			my $to_domain = $to;
			$to_domain =~ s/.*@//;
			$to_domains_total_hash->{$to_domain} += $server_to_count->{$to};
			$to_domains_users_hash->{$to_domain}++;
		}

		print <<EOF;
Local users

	Total sent: $my_users_email_count
	Total recipients: $total_recipients

	Sent from authenticated users (onsite and offsite): $authenticated_count
	Sent from non-authenticated users (onsite--assuming non-open relay): $non_authenticated_count

	Sent from onsite: $onsite_email_count
	Recipients from onsite users: $onsite_recipients

	Sent from offsite (authenticated): $offsite_email_count
	Recipients from offsite users: $offsite_recipients

EOF

		{
			my $from_hash = $stats->{'onsite_stuff'}->{'no_ident'}->{'message_stats'}->{'from'};
			my $unqiue_senders = (keys %$from_hash);
			print "Onsite local users: $unqiue_senders\n";
			my $printed_count = 0;
			for my $from ( sort { $from_hash->{$b} <=> $from_hash->{$a} or $a cmp $b } keys %{$from_hash} ) {
				my $from_count = $from_hash->{$from};
				if ( $printed_count <= 5 ) {
					print "\t$from_count: $from\n";
					$printed_count++;
				}
			}
		}
		print "\n";

		print "Offsite local user DNS domains (authenticated)\n";
		for my $domain ( sort { $offsite_sort->{$b} <=> $offsite_sort->{$a} or $a cmp $b } keys %{$stats->{'offsite_auth_stuff'}} ) {
			my $auth_correct_user_hash = $stats->{'offsite_auth_stuff'}->{$domain}->{'message_stats'}->{'auth_correct_user'};
			my $unqiue_senders = (keys %$auth_correct_user_hash);
			print "\t$offsite_sort->{$domain} from $unqiue_senders at $domain\n";
			my $printed_count = 0;
			for my $auth_correct_user ( sort { $auth_correct_user_hash->{$b} <=> $auth_correct_user_hash->{$a} or $a cmp $b } keys %{$auth_correct_user_hash} ) {
				my $auth_correct_user_count = $auth_correct_user_hash->{$auth_correct_user};
				if ( $domain eq "unknown" or $printed_count <= 5 ) {
					print "\t\t$auth_correct_user_count: $auth_correct_user\n";
					$printed_count++;
				}
			}

			if ( $domain eq "unknown" ) {
				my $ip_hash = $stats->{'offsite_auth_stuff'}->{$domain}->{'message_stats'}->{'ip'};
				print "\t\t-------------\n";
				for my $ip ( sort { $ip_hash->{$b} <=> $ip_hash->{$a} or ipsort() } keys %{$ip_hash} ) {
					my $ip_count = $ip_hash->{$ip};
					my $dns = `host $ip`;
# 					my $dns = '';
					$dns =~ s/[\d\.]+.in-addr.arpa domain name pointer (.*)\.\n$/$1/;
					$dns =~ s/Host [\d\.]+.in-addr.arpa. not found: .*\n/not found/;
					print "\t\t$ip_count: ${ip}[$dns]\n";
				}
			}
		}
		print "\n";

		print "Top recipient domains from local users:\n";
		my $printed_count = 0;
		for my $to_domain ( sort { $to_domains_total_hash->{$b} <=> $to_domains_total_hash->{$a} or $a cmp $b } keys $to_domains_total_hash ) {
			if ( $printed_count <= 5 ) {
				print "\t$to_domains_total_hash->{$to_domain}: $to_domain (unique recipients: $to_domains_users_hash->{$to_domain})\n";
				$printed_count++;
			}
		}
		print "\n";

		{
			## Errors from local users
			my $count = $stats->{'my_user_errors_stuff_count'} || 0;
			print "Errors from local users: $count\n";
			my @these_ips = keys %{$stats->{'my_user_errors_stuff'}};
			@these_ips = grep /^[\d\.]+$/, @these_ips;
			for my $ip ( sort { $stats->{'my_user_errors_stuff'}->{$b}->{'message_stats'}->{'ip'}->{$b} <=> $stats->{'my_user_errors_stuff'}->{$a}->{'message_stats'}->{'ip'}->{$a} } @these_ips ) {
				my $hash = $stats->{'my_user_errors_stuff'}->{$ip};
				if ( $ip =~ /^\d+\.\d+\.\d+\.\d+$/ ) {
					my ( $dns, $this_count, $from, $noqueue_message, $lost_connection, $pipe_status, $smtp_status ) = ( "", 0, "" );
					$dns = (keys $hash->{'message_stats'}->{'dns'})[0] if $hash->{'message_stats'}->{'dns'};
					$this_count = $hash->{'message_stats'}->{'ip'}->{$ip} if $hash->{'message_stats'}->{'ip'}->{$ip};
					if ( $hash->{'message_stats'}->{'from'} ) {
						$from = (keys $hash->{'message_stats'}->{'from'})[0];
					} elsif ( $hash->{'message_stats'}->{'auth_correct_user'} ) {
						$from = (keys $hash->{'message_stats'}->{'auth_correct_user'})[0];
					}

					print "\t$this_count: ${ip}[$dns] <$from>\n";
					for my $this_stat ( 'noqueue_message', 'lost_connection', 'pipe_status', 'smtp_status', 'relays' ) {
						if ( $hash->{'message_stats'}->{$this_stat} ) {
							for my $key ( sort keys %{$hash->{'message_stats'}->{$this_stat}} ) {
								my $value = $hash->{'message_stats'}->{$this_stat}->{$key};
								print "\t\t$this_stat: $value $key\n";
								print Dumper( $hash->{'message_stats'} ) if ! $value;
							}
						}
					}
				}
			}
		}
		print "\n";

		if ( $stats->{'all_message_stats'}->{'auth_correct_method'} ) {
			print "Authentication methods\n";
			print_sorted_by_value( $stats->{'all_message_stats'}, 'auth_correct_method', 0, 0, 1 );
			print "PLAIN users\n";
			print_sorted_by_value( $stats->{'auth_method_users'}, 'PLAIN', 0, 0, 1 );
			print "LOGIN users\n";
			print_sorted_by_value( $stats->{'auth_method_users'}, 'LOGIN', 0, 0, 1 );
		}
		print "\n";

		if ( $stats->{'all_message_stats'}->{'incorrect_password'} ) {
			print "Failed user login attempts\n";

			my $temp = $stats->{'all_message_stats'}->{'incorrect_password'};
			for my $key ( sort { $temp->{$b} <=> $temp->{$a} or $a cmp $b } keys %$temp ) {
				my $value = $temp->{$key};
				print "\t$value: $key\n";

				my $incorrect_ips = $stats->{'incorrect_password_ips'}->{$key};
				for my $key ( sort { $incorrect_ips->{$b} <=> $incorrect_ips->{$a} or $a cmp $b } keys %$incorrect_ips ) {
					my $value = $incorrect_ips->{$key};
					print "\t\t$value: $key\n";
				}
			}
		}

		#####################################################################################
		print "\n";
		print "##############################\n";
		#####################################################################################

		my $server_stats = {};
		my $total_incoming = 0;
		my $total_local_deliveries = 0;
		my $total_external_deliveries = 0;
		my $all_server_stats = {};
		while ( my  ( $ip, $hash ) = each %{$stats->{'external_senders_stuff'}} ) {
			my $short_ip = $ip;
			$short_ip =~ s/^(\d+\.\d+)\.\d+\.\d+$/$1/;
			for my $nrcpt ( keys $hash->{'message_stats'}->{'nrcpt'} ) {
				$server_stats->{$short_ip}->{'sender_count'} += $hash->{'message_stats'}->{'nrcpt'}->{$nrcpt};
				$total_incoming += $hash->{'message_stats'}->{'nrcpt'}->{$nrcpt};
			}
			$total_local_deliveries += $hash->{'message_stats'}->{'pipe_status'}->{'sent (delivered via dovecot service)'} if $hash->{'message_stats'}->{'pipe_status'}->{'sent (delivered via dovecot service)'};
			$total_external_deliveries += $hash->{'message_stats'}->{'smtp_status'}->{'sent 250 a 1'} if $hash->{'message_stats'}->{'smtp_status'}->{'sent 250 a 1'};
			$total_external_deliveries += $hash->{'message_stats'}->{'smtp_status'}->{'sent 250 a 2'} if $hash->{'message_stats'}->{'smtp_status'}->{'sent 250 a 2'};
			my @dns_servers = keys %{$hash->{'message_stats'}->{'dns'}};
			my $name = $dns_servers[0] ? "${ip}[$dns_servers[0]]" : "$ip";

			push @{$server_stats->{$short_ip}->{'ips'}}, $name;

			for my $relays ( keys $hash->{'message_stats'}->{'relays'} ) {
				my $relay_domain = $relays;
				$relay_domain =~ s/.*\.(.*\..*)\[.*/$1/;
				$server_stats->{$short_ip}->{$relay_domain} += $hash->{'message_stats'}->{'relays'}->{$relays};
				$server_stats->{$short_ip}->{'relay_count'} += $hash->{'message_stats'}->{'relays'}->{$relays};
				$all_server_stats->{'relays'}->{$relay_domain} += $hash->{'message_stats'}->{'relays'}->{$relays};

			}

			for my $to ( keys %{$hash->{'message_stats'}->{'to'}} ) {
				$all_server_stats->{'to'}->{$to} += $hash->{'message_stats'}->{'to'}->{$to};
			}

			for my $from ( keys %{$hash->{'message_stats'}->{'from'}} ) {
				$all_server_stats->{'from'}->{$from} += $hash->{'message_stats'}->{'from'}->{$from};

				my $from_domain = $from;
				$from_domain =~ s/.*@(.*)/$1/;
				$all_server_stats->{'from_domain'}->{$from_domain} += $hash->{'message_stats'}->{'from'}->{$from};

				my $tld1 = $from_domain;
				$tld1 =~ s/.*\.([^\.]+)$/$1/;
				$all_server_stats->{'tld1'}->{$tld1} += $hash->{'message_stats'}->{'from'}->{$from};

				my $tld2 = $from_domain;
				$tld2 =~ s/.*\.([^\.]+\.[^\.]+)$/$1/;
				$all_server_stats->{'tld2'}->{$tld1}->{$tld2} += $hash->{'message_stats'}->{'from'}->{$from};

			}

			for my $warning ( keys %{$hash->{'message_stats'}->{'warning'}} ) {
				$all_server_stats->{'warning'}->{$warning} += $hash->{'message_stats'}->{'warning'}->{$warning};
			}

		}

		print "From outside of the server\n";
		print "\n";

		print "\tSent to local recipients: $total_incoming\n";

# 		print Dumper( $stats->{'recipient_tracking'} );
# 		exit;

		print "\tSaved (dovecot): $total_local_deliveries\n";
		print "\tForwarded to other servers: $total_external_deliveries\n";
		print "\tAll Relays:\n";
		for my $key ( sort { $all_server_stats->{'relays'}->{$b} <=> $all_server_stats->{'relays'}->{$a} or $a cmp $b } keys $all_server_stats->{'relays'} ) {
			my $value = $all_server_stats->{'relays'}->{$key};
			print "\t\t$value: $key\n";
		}
		print "\n";

		my $to_count = keys %{$all_server_stats->{'to'}};
		my $from_count = keys %{$all_server_stats->{'from'}};
		my $from_domain_count = keys %{$all_server_stats->{'from_domain'}};
		my $tld1_count = keys %{$all_server_stats->{'tld1'}};

		print "$to_count local recipients:\n";
		print_sorted_by_value( $all_server_stats, 'to', 20, 0, 1 );
		print "\n";

		print "$from_count senders:\n";
		print_sorted_by_value( $all_server_stats, 'from', 20, 0, 1 );
		print "\n";

		print "$from_domain_count sender domains:\n";
		print_sorted_by_value( $all_server_stats, 'from_domain', 20, 0, 1 );
		print "\n";

		print "$tld1_count top level domains:\n";
		for my $key ( sort { $all_server_stats->{'tld1'}->{$b} <=> $all_server_stats->{'tld1'}->{$a} or $a cmp $b } keys %{$all_server_stats->{'tld1'}} ) {
			my $value = $all_server_stats->{'tld1'}->{$key};
			my $tld2_count = keys %{$all_server_stats->{'tld2'}->{$key}};
			if ( $tld2_count == 1 ) {
				my $tld_counter = 0;
				for my $key2 ( sort { $all_server_stats->{'tld2'}->{$key}->{$b} <=> $all_server_stats->{'tld2'}->{$key}->{$a} or $a cmp $b } keys %{$all_server_stats->{'tld2'}->{$key}} ) {
					my $value = $all_server_stats->{'tld2'}->{$key}->{$key2};
					last if $value < 10 and $tld_counter > 5;
					print "\t$value from $key2\n";
					$tld_counter++;
				}
			} else {
				print "\t$value from $tld2_count .${key}'s\n";
				my $tld_counter = 0;
				for my $key2 ( sort { $all_server_stats->{'tld2'}->{$key}->{$b} <=> $all_server_stats->{'tld2'}->{$key}->{$a} or $a cmp $b } keys %{$all_server_stats->{'tld2'}->{$key}} ) {
					my $value = $all_server_stats->{'tld2'}->{$key}->{$key2};
					last if $value < 10 and $tld_counter > 5;
					print "\t\t$value from $key2\n";
					$tld_counter++;
				}
			}
		}
		print "\n";

		print "Warnings\n";
		print_sorted_by_value( $all_server_stats, 'warning', 0, 0, 1 );

		exit;

		print "\n";
		print "By server:\n";
		for my $short_ip ( sort { $server_stats->{$b}->{'sender_count'} <=> $server_stats->{$a}->{'sender_count'} or ipsort() } keys %{$server_stats} ) {
			print "\t$short_ip\n";
			print "\t\tIP's part of this group:\n";
			for my $ip ( sort ipsort @{$server_stats->{$short_ip}->{'ips'}} ) {
				print "\t\t\t$ip\n";
			}
			print "\t\tSent from this server: $server_stats->{$short_ip}->{'sender_count'}\n";
			print "\t\tSaved from this server: $server_stats->{$short_ip}->{'relay_count'}\n";
		}

		#####################################################################################
		print "\n";
		print "##############################\n";
		#####################################################################################

		my $connection_count = $stats->{'connection_count'} || 0;
		my $lost_connection = add_up_counts( $stats->{'all_message_stats'}->{'lost_connection'} );
		my $timeout_connection = add_up_counts( $stats->{'all_message_stats'}->{'timeout_connection'} );
		my $improper_command_pipelining = add_up_counts( $stats->{'all_message_stats'}->{'improper_command_pipelining'} );
		my $discard = $stats->{'all_message_stats'}->{'noqueue'}->{'discard'} || 0;
		my $reject = $stats->{'all_message_stats'}->{'noqueue'}->{'reject'} || 0;
		my $warn = $stats->{'all_message_stats'}->{'noqueue'}->{'reject'} || 0;
		my $queued_discards = add_up_counts( $stats->{'all_message_stats'}->{'queued_discards'} );
		my $queued_rejects = add_up_counts( $stats->{'all_message_stats'}->{'queued_rejects'} );

		print "Failed sends\n";
		print "\n";

		print "\tImmediate disconnects: $stats->{'immediate_disconnect_stuff_count'}\n";
		print "\tOther failed send attempts: $stats->{'nosend_errors_stuff_count'}\n";

		print "\tLost Connections: $lost_connection\n";
		print "\tTimeouts: $timeout_connection\n";
		print "\tImproper Command Pipelining: $improper_command_pipelining\n";

		print "\tNoqueue discarded: $discard\n";
		print "\tNoqueue rejected: $reject\n";
		print "\tNoqueue warn: $warn\n";

		print "Queued discards: $queued_discards\n";

		print "Queued rejects: $queued_rejects\n";

		for my $key ( qw# noqueue noqueue_action discard_domains reject_domains hold_domains warn_domains# ) {
			print_sorted_by_value( $stats->{'all_message_stats'}, $key );
		}

		#####################################################################################
		print "\n";
		print "##############################\n";
		#####################################################################################

		print "\n";

		print "Connections: $connection_count\n";
		print "Total sent: $stats->{'total_sent'}\n";

		print "Non-broke connections: ".($connection_count-$lost_connection-$timeout_connection-$improper_command_pipelining-$discard-$reject)."\n";


		print "\n";

		for my $key ( qw# smtp_status smtp_messages smtp_host_messages# ) {
			print_sorted_by_value( $stats->{'all_message_stats'}, $key );
		}

		print "\n";

		if ( $stats->{'all_message_stats'}->{'to'} ) {
			print_sorted_by_value( $stats->{'all_message_stats'}, 'to', 20 );
		}
		if ( $stats->{'all_message_stats'}->{'orig_to'} ) {
			print_sorted_by_value( $stats->{'all_message_stats'}, 'orig_to', 20 );
		}



		if ( $stats->{'to_without_orig'} ) {
			print_sorted_by_value( $stats, 'to_without_orig', 20 );
		}

		if ( $stats->{'all_message_stats'}->{'ip'} ) {
			print_sorted_by_value( $stats->{'all_message_stats'}, 'ip', 20 );
		}


		if ( $stats->{'all_message_stats'}->{'ip'} ) {
			print_sorted_by_value( $stats->{'all_message_stats'}, 'ip', 20 );
		}

		if ( $stats->{'all_message_stats'}->{'dns'} ) {
			print_sorted_by_value( $stats->{'all_message_stats'}, 'dns', 20 );
		}

		if ( $stats->{'all_message_stats'}->{'from'} ) {
			print_sorted_by_value( $stats->{'all_message_stats'}, 'from', 20 );
		}

		if ( $stats->{'dns_counts'} ) {
			print_sorted_by_value( $stats, 'dns_counts', 0, 10 );
		}


	}
}

##########################################################################################
##########################################################################################

sub process_pid_logs_to_message_ids {
	my ( $process_pid_logs, $message_ids, $message_id, $process, $pid, $debug_aid, $stop_draining_at ) = @_;
	my @new = ();
	while ( my $old_line = pop @{$process_pid_logs->{$process}->{$pid}} ) {
		push @new, "$process $pid $message_id $debug_aid $old_line";
#		push @new, "$debug_aid $old_line";
		last if $stop_draining_at and $old_line =~ /$stop_draining_at/;
	}
	push @{$message_ids->{$message_id}}, reverse @new;
}

sub add_up_counts {
	my ( $hash ) = @_;
	my $total = 0;
	while ( my ( $k, $count ) = each %$hash ) {
		$total += $count;
	}
	return $total;
}

sub reverse_dots {
	my ( $dns ) = @_;
	my @parts = split /\./, $dns ;
	return join ( '.', reverse @parts );
}

sub d2 {
	my $bla = Dumper( $_[0] );
	$bla =~ s/^\$VAR1 = {\n//;
	$bla =~ s/^        };//;
	return $bla;
}

sub print_sorted_by_key {
	my ( $stats, $name, $count ) = @_;
	print "$name\n";
	my $temp = $stats->{$name};
	my $counter = 0;
	for my $key ( sort keys $temp ) {
		my $value = $temp->{$key};
		print "\t$key = $value\n";
		$counter++;
		last if $count and $counter > $count;
	}
}

sub print_sorted_by_value {
	my ( $stats, $name, $count, $threshold, $hide_name ) = @_;
	print "$name\n" if ! $hide_name;
	my $temp = $stats->{$name};
	my $counter = 0;
	for my $key ( sort { $temp->{$b} <=> $temp->{$a} or $a cmp $b } keys %$temp ) {
		my $value = $temp->{$key};
		last if $threshold and $value < $threshold;
		print "\t$value: $key\n";
		$counter++;
		last if $count and $counter >= $count;
	}
}

sub count_stat {
	my ( $message_stats, $a, $stats, $b, $c ) = @_;
	for my $message_stat ( @{$message_stats->{$a}} ) {
		$stats->{$b}->{$message_stat}++;# if $stats->{$b};
		$stats->{$c}++;# if $stats->{$c};
	}
}

sub parse_smtp_status {
	my ( $status_message, $this_group_stats, $extra ) = @_;

	if ( $status_message =~ /sent \((\d\d\d)(.*)/ ) {
		push @{$this_group_stats->{'smtp_status'}}, "sent $1 a $extra";

# 	} elsif ( $status_message =~ /sent \((\d\d\d)(.*)/ ) {
# 		push @{$this_group_stats->{'smtp_status'}}, "sent $1 b $extra";

	} elsif ( $status_message =~ /([^ ]*) \(host $dns_ip_pattern said: (\d\d\d)(.*) \(in reply to RCPT TO command\)\)/ ) {
		push @{$this_group_stats->{'smtp_status'}}, "$1 $4 c $extra";
		if ( $1 eq 'deferred' or $1 eq 'bounced' ) {
			push @{$this_group_stats->{'smtp_messages'}}, $status_message;
		}

	} elsif ( $status_message =~ /([^ ]*) (.*)/ ) {
		push @{$this_group_stats->{'smtp_status'}}, "$1 d $extra";
		if ( $1 eq 'deferred' or $1 eq 'bounced' ) {
			push @{$this_group_stats->{'smtp_messages'}}, $status_message;
		}

# 	if ( $status_message =~ /sent \(250 2.0.0 from MTA\(smtp:$ip_port_pattern\): 250 2.0.0 Ok: queued as (.*)\)/ ) {
# 		push @{$this_group_stats->{'smtp_status'}}, "sent 250 MTA $extra";
#
# 	} elsif ( $status_message =~ /sent \(250 2.0.0 OK (.*) (.*) - gsmtp\)/ ) {
# 		push @{$this_group_stats->{'smtp_status'}}, "sent 250 gsmtp $extra";
#
# 	} elsif ( $status_message =~ /sent \(250 2.0.0 Ok: queued as (.*)\)/ ) {
# 		push @{$this_group_stats->{'smtp_status'}}, "sent 250 queued $extra";
#
# 	} elsif ( $status_message =~ /sent \(250 2.0.0 (.*) Message accepted for delivery\)/ ) {
# 		push @{$this_group_stats->{'smtp_status'}}, "sent 250 a$extra";
#
# 	} elsif ( $status_message =~ /sent \(250 OK id=(.*)\)/ ) {
# 		push @{$this_group_stats->{'smtp_status'}}, "sent 250 b$extra";
#
# 	} elsif ( $status_message =~ /sent \(250 ok:  Message (.*) accepted\)/ ) {
# 		push @{$this_group_stats->{'smtp_status'}}, "sent 250 c$extra";
#
#
# 	} elsif ( $status_message =~ /deferred (host $dns_ip_pattern said: (\d\d\d)(.*) (in reply to RCPT TO command))\)/ ) {
# 		push @{$this_group_stats->{'smtp_status'}}, "deferred $3 $extra $4";
#
# 	} else {
# 		push @{$this_group_stats->{'smtp_status'}}, $status_message;

	}

}

sub ipsort {
	my $a1 = $a;
	my $b1 = $b;
	$a1 =~ s/^([\d\.]+).*/$1/;
	$b1 =~ s/^([\d\.]+).*/$1/;
	my @a1 = split /\./, $a1;
	my @b1 = split /\./, $b1;
	return $a1[0] <=> $b1[0]
		|| $a1[1] <=> $b1[1]
		|| $a1[2] <=> $b1[2]
		|| $a1[3] <=> $b1[3];
}

sub reverse_domains {
	my ( @bla ) = @_;
	my @sorted_domains = ();
	for my $domain ( @_ ) {
		my @parts = reverse( split( /\./, $domain ) );
		push @sorted_domains, join( '.', @parts );
	}
	return @sorted_domains;
}
