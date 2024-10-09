#!/usr/bin/perl

# The following is defined if we are run through mod_perl.
my $mod_perl_req = shift;

use CGI;

use IO::Socket ();
use IO::Socket::Timeout;
use File::Basename;

$CGI::APPEND_QUERY_STRING = 0; # Supposedly the default
my $q = new CGI;

$EVE_HOST   = "localhost";
$EVE_PORT   =  6666;

$EOS_XRD     = 'root://eospublic.cern.ch';
$EOS_XRD_RE  = "${EOS_XRD}(?::1094)?";
$EOS_FILE_RE = '/eos/opendata/cms/(?:[\w][-\w]+/)*[\w][-\w]+\.root';

$CERN_UPN   = "webuser";
$CERN_GName = "Web User"; # used in greeting; no SSO - unknown user

$REDIR_HOST  = `hostname`;
$REDIR_HOST =~ s/^\s+|\s+$//g ; 

$LOGDIR_WWW = "/logs/" . $CERN_UPN;
$CONFIG_WWW = "/config/";

$IS_TEST = $ENV{'SCRIPT_NAME'} =~ m/-test.pl$/;
if ($IS_TEST)
{
  $EVE_PORT    =  6669;
  $LOGDIR_WWW = "/logs-test/" . $CERN_UPN;
  $CONFIG_WWW = "/config-test/";
}

$LOGDIR_PFX = $ENV{'DOCUMENT_ROOT'} . $LOGDIR_WWW;
$LOGDIR_URL = "https://${REDIR_HOST}/${LOGDIR_WWW}";

$AUTO_REDIRECT=1;
$SOURCES = {}; # name -> prefix mapping
$error_str;

{
  $SOURCES->{'EOS'} = {
    'desc'   => "Open CERN CMS EOS PFN (/eos/opendata/cms...)",
    'prefix' => sub {
      my $f = shift;
      if    ($f =~ m!^(${EOS_XRD_RE}/${EOS_FILE_RE})$!) { return $1;  }
      elsif ($f =~ m!^(${EOS_FILE_RE})$!)               { return "${EOS_XRD}/$1"; }
      else  {
        $error_str = "should match '/eos/opendata/cms/.../file-name.root'";
        return undef;
      }
    }
  };

  $PORT_MAP_FOO = sub {
    my $resp = shift;
    my ($port_rem) = $resp->{'port'} =~ m/(\d\d)$/;
    return "https://${REDIR_HOST}/host${port_rem}/$resp->{'dir'}";
  };
}

$PRINT_URL_ARGS = 0; # Only enable for testing -- XSS attacks!
$PRINT_ENV      = 0; # Only enable for development.
$PRINT_TUNNEL_SUGGESTION = 0;


$SAMPLE_DIR = "/eos/opendata/cms";
@SAMPLES = qw{
  Run2013A/PPJet/RECO/HighPtPP-15Feb2013-v1/10000/FA35A4D7-5A79-E211-8A35-003048678F9C.root
  Run2013A/ZeroBias4/RECO/PromptReco-v1/000/211/821/00000/F01AFFAB-E877-E211-AF44-00237DDC5C24.root
  Run2015E/HighMultiplicity/AOD/PromptReco-v1/000/262/325/00000/DCD3A9B2-74A6-E511-BE1F-02163E014529.root
  Run2015E/MinimumBias12/AOD/PromptReco-v1/000/262/328/00000/62205D64-E2A6-E511-8E99-02163E0139B0.root
  Run2016G/Charmonium/MINIAOD/UL2016_MiniAODv2-v1/70000/F2CD4268-ADD0-2B4C-BFC6-E638368C3EB4.root
  Run2016G/MuonEG/MINIAOD/UL2016_MiniAODv2-v2/70000/F8EFD4D5-16FB-3B42-9F1B-8EB341817D0C.root
  Run2016H/DisplacedJet/MINIAOD/UL2016_MiniAODv2-v1/120000/F7079D79-E0A0-8B48-B977-0D384F4C292A.root
  Run2016H/JetHT/MINIAOD/UL2016_MiniAODv2-v2/130000/E2C95597-AC41-AC4C-9B01-85D31F36CE3B.root
};

################################################################################

sub pre_sanitize
{
  for my $e ($q->url_param()) {
    return 1 if $e =~ m"<script>"io;
    return 1 if $q->url_param($e) =~ m"<script>"io;
  }
  for my $e ($q->param()) {
    return 1 if $e =~ m"<script>"io;
    return 1 if $q->param($e) =~ m"<script>"io;
  }
}

sub sanitize_and_code_string
{
  my $s = shift;
  
  $s =~ s!<(/?\w+)>!__$1__!og;
  $s = $q->escapeHTML($s, 1); # also encode newlines
  return "<code>$s</code>";
}

# CGI script to connect to an Event Display server.
#
# Reports progress as it goes and at the end outputs a link to
# a newly spawned instance.
# And a reminder that a tunnel needs to be made at this point.
#
# Once things more-or-less work, we can just redirect on success:
#   print $q->redirect('http://$REDIR_HOST:$REDIR_PORT/...');
# ... or do some JS magick, or whatever.

################################################################################

sub cgi_beg
{
  print $q->header('text/html');

  print <<"FNORD";
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
<link rel="stylesheet" type="text/css" href="/css/main.css" />
  <title>cmsShowWeb Gateway</title>
</head>
<body>
FNORD
}

sub cgi_print
{
  print "<p><pre>", join("\n", @_), "</pre>\n";
}

sub cgi_end
{
  print<<"FNORD";

</body>
</html>
FNORD
}

sub cgi_die
{
  print "<p><b> $_[0] </b>\n";
  cgi_end();
  exit(1);
}

sub flush
{
  defined $mod_perl_req ? $mod_perl_req->rflush() : select()->flush();
}

################################################################################
# Connect and redirect
################################################################################
sub recv_with_timeout
{
  my $sock = shift;
  my $size = shift;
  my $timeout = shift || 5;
  my $err_to  = shift || 100;
  my $buf;
  my $sum_t = 0;

  $sock->read_timeout($timeout);

  my $ret;
  while (not defined ($ret = $sock->recv($buf, $size)))
  {
    $sum_t += $timeout;
    cgi_print "Waiting for server response, ${sum_t}s [ max = ${err_to}s ]";
    flush();
    if ($sum_t >= $err_to) {
      return undef;
    }
  }
  chomp  $buf;
  return $buf;
}

sub connect_to_server
{
  my $request = shift;
  my $verbose = shift;
  my $buf;

  cgi_print "Connecting to local cmsShowWeb forker now ..." if $verbose;

  my $client = IO::Socket->new(
      Domain   => IO::Socket::AF_INET,
      Type     => IO::Socket::SOCK_STREAM,
      proto    => 'tcp',
      PeerHost => $EVE_HOST,
      PeerPort => $EVE_PORT,
      Timeout  => 5
  ) || cgi_die "Can't open socket: $@";

  IO::Socket::Timeout->enable_timeouts_on($client);

  cgi_print "Connected to $EVE_PORT" if $verbose;

  $buf = recv_with_timeout($client, 1024, 5, 30);
  
  unless (length($buf)) {
    my $err_str = $!;
    cgi_print "Error receiving server greeting, error: ${err_str}.";
    $client->close();
    return $buf;
  }
  cgi_print "Server greeting: $buf" if $verbose;

  cgi_print "Sending $request" if $verbose;

  # MUST include trailing \n, the server is looking for it!

  my $size = $client->send($request);
  cgi_print "Sent data of length: $size" if $verbose;

  flush();

  $buf = recv_with_timeout($client, 1024, 5, 300);
 
  if (length($buf)) {
    cgi_print "Server response: $buf" if $verbose;
  } else {
    my $err_str = $!;
    cgi_print "Error receiving server response, error: ${err_str}.";
  }

  $client->close();

  return $buf;
}

sub start_session
{
  my $file = shift;
  my $fwconfig = $q->param('FWconfig');
  my $fwconfigdir = $ENV{'DOCUMENT_ROOT'} . $CONFIG_WWW . ${CERN_UPN};

  $fwconfig  =~ s/^\s+|\s+$//g;

  if ($fwconfig ne "" and $fwconfig !~ m!^http!) {
      $fwconfig = ${fwconfigdir} . "/" . ${fwconfig};
  }
  elsif ($fwconfig =~m /^https\:\/\/${REDIR_HOST}(.*)/ )
  {
    $fwconfig = $ENV{'DOCUMENT_ROOT'} . $1;
  }

  my $fwgeo = $q->param('FWgeo');
  
  my $buf = connect_to_server(qq{{"action": "load", "file": "$file",
                                  "logdir": "$LOGDIR_PFX", "logdirurl": "$LOGDIR_URL",
                                  "fwconfig": "$fwconfig", "fwconfigdir": "$fwconfigdir",
                                  "fwgeo": "$fwgeo",
                                  "user": "$CERN_UPN"}\n}, 1);

  return undef unless length($buf);

  # Expect hash response, as { 'port'=> , 'dir'=> , 'key'=> }
  my $resp = eval $buf;
  unless (defined $resp) {
    cgi_print "Failed parsing of server response:", "    $buf";
    return undef;
  }

  if (defined $resp->{'error'}) {
    cgi_print "Server responded with error:", "    $resp->{'error'}";
    if (defined $resp->{'log_fname'}) {
      print "More information might be available in the <a href=\"$LOGDIR_WWW/$resp->{'log_fname'}\">log file</a>\n";
    }
    print "<p><a href=$ENV{'SCRIPT_URI'}>Back to main page</a>\n";
    return undef;
  }

  my $URL = &$PORT_MAP_FOO($resp);

  if ($AUTO_REDIRECT) {
    print "<META HTTP-EQUIV=refresh CONTENT=\"0;URL=$URL\">\n";
    return;
  }


  print<<"FNORD";
<h2>
Your event display is ready, click link to enter:
</h2>
<p>
<a href="$URL">$URL</a>
<p>
<a href="$LOGDIR_WWW/$resp->{'log_fname'}">Log file</a>
<p>
<a href="$ENV{'SCRIPT_URI'}">Back to main page</a>
FNORD

  if ($PRINT_TUNNEL_SUGGESTION)
  {
    print<<"FNORD";
<small>
<p>
P.S. You probably need to make a tunnel to port $resp->{'port'} as things stand now.
<p>
ssh -S vocms-ctrl -O forward -L$resp->{'port'}:localhost:$resp->{'port'}  x
</small>
FNORD
  }
}


################################################################################
# Main & Form stuff
################################################################################

if (pre_sanitize())
{
  print $q->header(-type=>'text/plain', -status=> '400 Bad Request');
  exit 1;
}

cgi_beg();

if ($CONFIG_ERROR)
{
    cgi_print "Startup error: $CONFIG_ERROR";
    return;
}

# Usage of INET sockets in cgi-bin under SE requires:
#   /usr/sbin/setsebool -P httpd_can_network_connect 1
# Maybe we should use UNIX sockets.

# cgi_print("File=<code>".$q->param('File')."</code>");

my @names = $q->url_param();

if ($q->url_param("stop_redirect")) {
   $AUTO_REDIRECT=0;
}

if ($PRINT_URL_ARGS)
{
  print "<p><pre>\n";
  print "N_param = ", scalar(@names), "\n";

  for my $k (@names)
  {
    print "$k: ", $q->url_param($k), "\n";
  }
  print "\n", '-' x 80, "\n";
  print "</pre>\n";
}
if ($PRINT_ENV)
{
  print "<p><pre>\n";
  for my $k (sort keys %ENV)
  {
    print "$k: ", $ENV{$k}, "\n";
  }
  print "\n", '-' x 80, "\n";
  print "</pre>\n";
}

# Remap URL param load_file to POST param "Action" "Load File EOS" but only
# if POST "Action" is not already set.
if ($q->url_param('load_file') && not $q->param('Action'))
{
  $q->param('Action', "Load File EOS");
  $q->param('File',   $q->url_param('load_file'));
}

if ($q->param('Action') =~ m/^Load/)
{
  my $file;

  if ($q->param('Action') =~ m/^Load File (.*)$/)
  {
    my $srcobj = $SOURCES->{$1};

    my $fn_str = $q->param('File');
    $fn_str =~ s/^\s+//;
    $fn_str =~ s/\s+$//;
    my $fn_sanitized = sanitize_and_code_string($fn_str);

    cgi_print "Processing '$fn_sanitized'";

    my @files = split(/\s+/, $fn_str);
    my $fcnt = 0;
    $error_str = undef;
    foreach my $fi (@files)
    {
      my $fi_sanitized = sanitize_and_code_string($fi);
      ++$fcnt;
      if (not ref($srcobj->{'prefix'}))
      {
        cgi_print "Match prefix";
        if ($fi =~ m!${LFN_RE}!)
        {
          $fi = $srcobj->{'prefix'} . $1;
          cgi_print "$fcnt: $fi_sanitized";
        }
        else
        {
          $error_str = "filename '$fi_sanitized' ($fcnt) should match '/store/.../file-name.root'";
          last;
        }
      }
      elsif (ref($srcobj->{'prefix'}) eq 'CODE')
      {
        my $out = &{$srcobj->{'prefix'}}($fi);
        if ($out) {
          $fi = $out;
        } else {
          $error_str = "filename '$fi_sanitized' ($fcnt) $error_str";
          last;
        }
      }
      else
      {
        $error_str = "wrong source definition, prefix should be a scalar or code ref, is " . ref($srcobj->{'prefix'});
        last;
      }
    }
    $file = join(" ", @files) unless $error_str;
  }
  elsif ($q->param('Action') =~ m!^Load ([-/\w]+/\w[-\w]+\.root)!)
  {
    $file = $SOURCES->{'EOS'}{'prefix'}("${SAMPLE_DIR}/$1");
  }
  else
  {
    $error_str = "unmatched Action value '" . sanitize_and_code_string($q->param('Action')) . ">'";
  }

  if (defined $file)
  {
    start_session($file);
  }
  else
  {
    cgi_print "Error Load: $error_str";
  }
}
elsif ($q->param('Action') eq 'Show Usage')
{
  my $buf = connect_to_server(qq{{"action": "report_usage"}\n}, 0);
  my $r = eval $buf;
  print "Currently serving $r->{current_sessions} (total $r->{total_sessions} since service start).";
  print "<br><br>\n";# Request and show current session, users, run times ... log links for matchin user
  $r->{'table'} =~ s/$ENV{'DOCUMENT_ROOT'}//g;
  print $r->{'table'};
  print "<p><a href=$ENV{'SCRIPT_URI'}>Back to main page</a>\n";
}
else
{
  ## DATA ##
  print"<h2 style=\"color:navy\">cmsShowWeb OPENDATA @ CERN </h2>";
  cgi_print "Hello ${CERN_GName}, choose your action below.";

  print $q->start_form(), "\n";

  # Default hidden submit button to eat up <Enter> presses from textfields
  print $q->submit('Action', "nothing", undef, hidden, "onclick=\"event.preventDefault();\""), "\n";

  print("<h3> Open Event Display </h3>\n");
  print("Enter file name<br> <br>TODO:Addcheck for 2012 Data formats (CMSSSW_5_3_X)!!!<br>");
  print $q->textfield('File', '', 150, 32767), "\n";
  print "<table>\n";
  print join("\n", map { "<tr><td>" . $q->submit('Action', "Load File $_") . "</td><td>" . $SOURCES->{$_}{'desc'} . "</td></tr>"} (keys %$SOURCES));
  print "\n</table>\n";

  # Proto for running locate on remote server. Locks up on caches, need objects in
  print "<br>\n";

  printf "Random EDM data format samples after 2012 ";
  for my $f (@SAMPLES)
  {
    print "<br>\n";
    print $q->submit('Action', "Load $f");
  }

  print $q->end_form();

  print "<footer>";
  printf "Mail to ";
  print "<a href=\"mailto:cmstalk+visualization\@cern.ch\">cmstalk+visualization\@cern.ch</a></p> ";
  print "</footer>";
}

cgi_end();
