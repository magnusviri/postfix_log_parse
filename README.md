# postfix_log_parse

This script parses the output of a postfix log file and tries to make sense of it.

It's a work in progress full of lots of debugging code and other messes.

Edit these 2 lines to make it work better for you.

  my $onsite_regex = '^10\.0\.0\.';
  my $my_double_bounce_email = 'double-bounce@example.com'

Change $onsite_regex to a regex that matches your users, if possible.  This is basically the mynetworks setting found in main.cf.
