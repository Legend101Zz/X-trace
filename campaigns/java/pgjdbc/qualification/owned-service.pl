# Run as the parent of one stock fixture service in its own container. The child
# stays waitable until we reap it, so its PID cannot be recycled before signalling.
use strict;
use warnings;
use POSIX qw(:sys_wait_h);
use Errno qw(EINTR);

@ARGV or die "fixture service command missing\n";
$SIG{CHLD} = 'DEFAULT';
my $child = fork();
defined($child) or die "fixture fork failed\n";
if ($child == 0) {
    exec { $ARGV[0] } @ARGV or POSIX::_exit(127);
}

my $sent = 0;
while (1) {
    my $done = waitpid($child, WNOHANG);
    if ($done == $child) {
        my $status = $?;
        exit 1 unless $sent;
        exit 0 if WIFEXITED($status) && WEXITSTATUS($status) == 0;
        # Distinguish a deliberate direct TERM exit from a normal zero exit.
        exit 42 if WIFSIGNALED($status) && WTERMSIG($status) == 15;
        exit 1;
    }
    next if $done < 0 && $! == EINTR;
    die "fixture child unavailable\n" if $done < 0;
    if (!$sent && -f '/xtrace-service-control/stop.request') {
        kill('TERM', $child) == 1 or die "fixture stop unavailable\n";
        $sent = 1;
    }
    select(undef, undef, undef, 0.10);
}
