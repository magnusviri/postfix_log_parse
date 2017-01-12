# postfix_log_parse

This script parses the output of a postfix log file and tries to make sense of it.

It's a work in progress full of lots of debugging code and other messes, including a major flaw in that the date is completely discarded when parsing (I didn't really need it until later and then it was such a mess I gave up trying to add it back).

Edit these 2 lines to make it work better for you.

	my $onsite_regex = '^10\.0\.0\.';
	my $my_double_bounce_email = 'double-bounce@example.com';

Change $onsite_regex to a regex that matches your users, if possible.  This is basically the mynetworks setting found in main.cf.

Usage:

	/path/to/postfix_log_parse.pl /path/to/log_file

This is an excert of the output.

	##############################
	relay_counts
		1000: dovecot
		2000: com
		1500: com.example
		400: com.google
		100: net
		50: net.yahoodns
		30: com.hotmail

	##############################
	Local users

		Total sent: 703
		Total recipients: 1633

		Sent from authenticated users (onsite and offsite): 489
		Sent from non-authenticated users (onsite--assuming non-open relay): 214

		Sent from onsite: 493
		Recipients from onsite users: 1346

		Sent from offsite (authenticated): 210
		Recipients from offsite users: 287

It divides the emails into those sent by local users, those sent to local users, and undelivered email (disconnects, rejects, discards, etc).
