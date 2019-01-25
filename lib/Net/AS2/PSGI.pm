package Net::AS2::PSGI;

use strict;
use warnings;
use autodie qw(:file :filesys);

# VERSION

=head1 NAME

Net::AS2::PSGI - AS2 Protocol Plack application

=head1 VERSION

This documentation is for AS2 Protocol Version 1.0.

=head1 SYNOPSIS

    ### Create an AS2 PSGI Server

    my $view_app   = Net::AS2::PSGI->to_view_app();

    my $server_app = Net::AS2::PSGI->to_server_app();

=head1 DESCRIPTION

This module defines an AS2 Protocol compliant Plack application.

The AS2 Protocol is specified by RFC 4130. This protocol defines a
secure peer-to-peer data transfer with receipt using HTTP. The receipt
is called a Message Disposition Notification (MDN) and is specified by
RFC 3798.

The Public certificates between each partnership are exchanged
independently. i.e. The AS2 protocol does not allow for the public
certificate to be downloaded, they must be exchanged before any AS2
communication can occur.

Implementations of the AS2 Protocol extend the original RFC 4130 to
allow for transfer over HTTPS and use of newer signing algorithms,
e.g. the SHA-2 family.

The AS2 Protocol defines two modes, Synchronous and Asynchronous.

The supported AS2 Protocol version is 1.0. Version 1.1 (compression)
is not supported.

=over 4

=item Synchronous

In this mode the data is POSTed from the sender to the receiver and
the response is the MDN receipt.

=item Asynchronous

In this mode the data is POSTed from the sender to the receiver but
the response only confirms the data was sent.

The receiver on completion of receiving the data, POSTs the MDN
receipt for the data back to the sender.

=back

=cut

use Carp;

use File::Path   qw(mkpath);
use JSON::XS;
use POSIX        qw(strftime);

use Plack::Request;

use Net::AS2;

# AS2 Directories
our $CERTIFICATE_DIR;
our $PARTNERSHIP_DIR;
our $FILE_DIR;

# Certificate and Private Key Caches
my %CERTIFICATE = ();
my %PRIVATE_KEY = ();

# API functions
my %API_FUNCTIONS = (
    send       => 1,
    receive    => 1,
    MDNsend    => 1,
    MDNreceive => 1,
);

# HTTP Codes
use constant HTTP_OK          => 200;
use constant HTTP_BAD_REQUEST => 404;

=head1 CONFIGURATION AND ENVIRONMENT

The server uses the following directories.

=over 4

=item certificate_dir

This directory contains Private and Public Certificate pairings and
the Public Certificate for each defined Partnership.

For security, this directory and the files within it should not be
world readable.

An alternative, is to either supply the key and certificate text
strings directly in the L<Net::AS2> hash or supply an alternative
directory per partnership, using the C<CertificateDirectory>
L<Net::AS2> hash key.

=item partnership_dir

This directory contains JSON files that each define a partnership
between two AS2 Protocol Servers. The partnership file contains the key
names defined in L<Net::AS2>.

Subdirectories may be used, with the whole relative path being used to
define the partnership name.

For security, this directory and the files within it should not be
world readable.

=item file_dir

This directory will contain either files received from a partnership
transfer or an MDN after sending data to a partnership.

For security, this directory and the files within it should not be
world readable.

The directory structure is as follows:

=over 4

=item partnership

The subdirectory structure is created and named after the partnership
file (without the .json extension). For security, this directory
structure is created with owner read/write only.

The files being transferred between this partnership are then stored
under the following directories:

=over 4

=item SENDING

Files here are being sent to the partner, but no receipt has been received yet.

=item SENT

Files here have been sent to the partner and a receipt has been received.

=item RECEIVING

Files here are being received from the partner, but no receipt has been sent yet.

=item RECEIVED

Files here have been received from the partner and a receipt has been sent.

=back

=back

=back

=head1 SUBROUTINES

=over 4

=item init ( $config, $log )

Class Method for initialising the AS2 directory structures.

=cut

sub init {
    my ($self, $config, $log) = @_;

    # initialise the package variables, unless already defined.
    $CERTIFICATE_DIR //= $config->{certificate_dir};
    $PARTNERSHIP_DIR //= $config->{partnership_dir};
    $FILE_DIR        //= $config->{file_dir};

    if ($log) {
        $log->({ level => 'warn', message => "Failed to set CERTIFICATE_DIR" }) unless $CERTIFICATE_DIR;
        $log->({ level => 'warn', message => "Failed to set PARTNERSHIP_DIR" }) unless $PARTNERSHIP_DIR;
        $log->({ level => 'warn', message => "Failed to set FILE_DIR" })        unless $FILE_DIR;
    }

    _create_directories($log, 'init', $CERTIFICATE_DIR, $PARTNERSHIP_DIR, $FILE_DIR);

    return;
}

=item to_psgi ( api )

Class Method returning PSGI application for 'POST'ing to the given C<api> .

C<api> is one of:

=over 4

=item send

=item receive

=item send_mdn

=item receive_mdn

=back

=cut

sub to_psgi {
    my ($self, $api) = @_;

    return $self->_psgi('POST', $api);
}

=item view_psgi ()

Class Method returning PSGI application for 'GET'ting a view of
partnership data.

=cut

sub view_psgi {
    return shift->_psgi('GET', 'view');
}

=item app_psgi ()

Class Method returning PSGI application for AS2.

=cut

sub app_psgi {
    return shift->_psgi('POST', 'app');
}

=item app ( request )

API Method implementing AS2.

=back

=cut

sub app {
    my ($self, $request) = @_;

    my ($api, $new_path) = $request->path =~ m{/(\w+)(/.*)};

    return $request->new_response(HTTP_BAD_REQUEST)
      unless $api && $new_path && exists $API_FUNCTIONS{$api};

    $request->env->{PATH_INFO} = $new_path;

    return $self->$api($request);
}

=head1 API METHODS

All API methods receive a Plack request as their one and only argument.

=over 4

=item send ( request )

To send data to a partner, a POST request is created with a URL of the form /send/C<partnership>

The data is sent as the content of the POST request along with the following headers:

=over 4

=item MessageId

The AS2 Message ID.

The Message ID is validated to ensure it conforms to RFC 822.

In Asynchronous mode, the received MDN will include this value as the
C<Original Message ID>, thus tying the two independent POST requests
(send and MDN receipt) together, to complete the transfer.

=item Content-Type

The Content-Type of the data being sent.

=item Subject

The subject is an arbitrary brief one-line string.

=back

=cut

sub send { ## no critic (ProhibitBuiltinHomonyms)
    my ($self, $request) = @_;

    my $log     = $request->logger;
    my $headers = $request->headers;

    my $message_id = $headers->header('MessageId');
    if (! $message_id) {
        $log->({ level => 'error', message => "send not given MessageId header" }) if $log;
        return $request->new_response(404);
    }
    $log->({ level => 'debug', message => "$message_id : Starting to send data" }) if $log;

    my $partnership = _partnership($request);
    $log->({ level => 'debug', message => "$message_id : to $partnership" }) if $log;

    my $as2 = _as2($partnership);

    $message_id = $as2->get_message_id($message_id);

    my ($sending, $sent) = _send_directories($request, $message_id);

    my %mime_options = (
        'MessageId'    => "<$message_id>",
        'Type'         => $headers->header('Content-Type') // '',
        'Subject'      => $headers->header('Subject')      // '',
    );

    my $content = $request->content;

    my $message_file = _message_file($sending, $message_id);
    _save_file($message_file, JSON::XS->new->ascii->canonical->encode({ mdn => $as2->{Mdn}, pending => \1 }) );

    $log->({ level => 'debug', message => "<$message_id> : Created message file $message_file" }) if $log;

    my ($mdn, $mic, $mic_alg) = $as2->send($content, %mime_options);

    if ($as2->{Mdn} eq 'async') {
        my $response = $request->new_response();

        if ($mdn->{status_text} =~ qr{HTTP failure: (\d+) (.*)}) {
            $response->code($1);
            $response->body($2);
            my $body = JSON::XS->new->ascii->canonical->encode({ %$mdn }); # convert to simple hash
            _save_file($message_file, $body);
            my $failed_message_file = _message_file($sent, $message_id, '.failed');
            rename $message_file, $failed_message_file;
            $log->({ level => 'debug', message => "<$message_id> : Moved message file to $failed_message_file ($mdn->{status_text})" }) if $log;
        }
        elsif ($mdn->{unparsable}) {
            $response->code(HTTP_OK);
        }

        return $response;
    }

    my $match_mic  = $mdn->match_mic($mic, $mic_alg) ? 1 : 0;
    my $successful = $mdn->is_success && $match_mic  ? 1 : 0;

    my $body = JSON::XS->new->ascii->canonical->encode({
        match_mic  => $match_mic,
        successful => $successful,
        %$mdn, # convert to simple hash
    });

    my $response = $request->new_response(HTTP_OK);
    $response->body($body);
    $response->headers([
        'OriginalMessageId' => $mdn->original_message_id,
        'Content-Type'      => 'application/json; charset=utf-8',
        'Content-Length'    => length($body),
    ]);

    my $ext = not $successful ? '.failed' : '';
    _save_file($message_file, $body);
    my $message_file_ext = _message_file($sent, $message_id, $ext);
    rename $message_file, $message_file_ext;

    $log->({ level => 'debug', message => "<$message_id> : Moved message file to $message_file_ext" }) if $log;

    return $response;
}


=item receive ( request )

To receive data from a partner, a POST request is received via a URL of the form /receive/C<partnership>

The data is received as the content of the POST request along with the following headers:

=over 4

=item MESSAGE-ID

The AS2 Message ID.

The Message ID is validated to ensure it conforms to RFC 2822.

=item Content-Type

The Content-Type of the data being received.

=item AS2-VERSION

The AS2 Protocol version, it should be in the form 1.x. Only 1.0 is supported.

See RFC 4130 for further details about the different version numbers.

=item AS2-FROM

The partner's AS2 ID.

This value should match the PartnerId in the C<partnership.json> file.

=item AS2-TO

The receiver's (i.e. this application's) AS2 ID.

This value should match the MyId in the C<partnership.json> file.

=item DISPOSITION-NOTIFICATION-OPTIONS

I<Optional> This header is only defined if digital signatures are requested.

This header contains the requirements for the digital signature.
An example is:

 signed-receipt-protocol=required, pkcs7-signature; signed-receipt-micalg=required, sha256

=item RECEIPT-DELIVERY-OPTION

I<Optional> This header is only defined for Asynchronous mode.

This header defines a URL for the receiver to POST the MDN receipt to,
once the data has been received.

=back

=cut

sub receive {
    my ($self, $request) = @_;

    my $log     = $request->logger;
    my $headers = $request->headers;

    my $message_id = $headers->header('Message-Id');
    if (! $message_id) {
        $log->({ level => 'error', message => "receive not given Message-Id header" }) if $log;
        return $request->new_response(404);
    }
    $log->({ level => 'debug', message => "$message_id : Starting to receive data" }) if $log;

    my $partnership = _partnership($request);
    $log->({ level => 'debug', message => "$message_id : from $partnership" }) if $log;

    my $as2 = _as2($partnership);

    $message_id = $as2->get_message_id($message_id);

    my ($receiving, $received) = _receive_directories($request, $message_id);

    # Decode the incoming HTTP request as AS2 Message.
    my $message = $as2->decode_message($headers, $request->content);

    if ($message->is_mdn_async) {
        $log->({ level => 'info', message => "<$message_id> : Receiving async message from $partnership" }) if $log;

        #        $log->({ level => 'debug', message => "<$message_id> : Receiving async content:\n------\n" . $message->content . "\n------\n" }) if $log;

        my $message_state = "$receiving/$message_id.state";
        _save_file($message_state, $message->serialized_state);
        $log->({ level => 'debug', message => "<$message_id> : Created serialized state file $message_state" }) if $log;

        my $message_file = _message_file($receiving, $message_id);
        _save_file($message_file, $message->content); # TODO resolve warn/error if empty

        $log->({ level => 'debug', message => "<$message_id> : Created serialized message file $message_file" }) if $log;

        return $request->new_response(HTTP_OK);
    }

    $log->({ level => 'info',  message => "<$message_id> : Receiving sync message from $partnership" }) if $log;

#    $log->({ level => 'debug', message => "<$message_id> : Receiving sync content:\n------\n" . $message->content . "\n------\n" }) if $log;

    my ($h, $c) = $as2->prepare_sync_mdn(
        $message->is_success ?
            Net::AS2::MDN->create_success($message) :
            Net::AS2::MDN->create_from_unsuccessful_message($message)
   );

    my $ext = ! $message->is_success ? '.failed' : '';

    my $response = $request->new_response(HTTP_OK);
    $response->headers($h);
    $response->body($c);

    my $message_file = _message_file($receiving, $message_id);
    _save_file($message_file, $message->content);
    my $message_file_ext = _message_file($received, $message_id, $ext);
    rename $message_file, $message_file_ext;

    $log->({ level => 'debug', message => "<$message_id> : Moved message file to $message_file_ext" }) if $log;

    return $response;
}


=item MDNsend ( request )

Sends an MDN message to a partner.

The POST request is created with a URL of the form
/MDNsend/C<partnership> along with the following headers:

=over 4

=item MessageId

The AS2 Message ID.

The Message ID is validated to ensure it conforms to RFC 2822.

=back

In the RECEIVING directory, the file containing the saved MDN state of
the given Message ID is read and an MDN response is created from the
content. The MDN response is POSTed to the partner.

If the POST fails, the POST response code and content is stored in a
file called C<Message-Id>.C<Timestamp: %F-%H-%M-%S>.mdn-failed in the
RECEIVING directory and the POST response code is returned.

Otherwise, the data file is moved from the RECEIVING directory to
RECEIVED and the MDN state file is moved from the RECEIVING directory
to RECEIVED and renamed to have a .sent extension.  If the MDN message
is not indicating success, the data filename is also renamed to have a
.failed extension.

=cut

sub MDNsend {
    my ($self, $request) = @_;

    my $log     = $request->logger;
    my $headers = $request->headers;

    my $message_id = $headers->header('MessageId');
    if (! $message_id) {
        $log->({ level => 'error', message => "MDNsend not given MessageId header" }) if $log;
        return $request->new_response(404);
    }
    $log->({ level => 'debug', message => "$message_id : Starting to send MDN receipt" }) if $log;

    my $partnership = _partnership($request);
    $log->({ level => 'debug', message => "$message_id : to $partnership" }) if $log;

    my $as2 = _as2($partnership);

    $message_id = $as2->get_message_id($message_id);

    my ($receiving, $received) = _receive_directories($request, $message_id);
    my $state_file = "$receiving/$message_id.state";
    $log->({ level => 'debug', message => "<$message_id> : About to read " . (-r $state_file ? 'readable' : 'not readable') . " file $state_file" }) if $log;
    my $state = _slurp_file($state_file);
    $log->({ level => 'debug', message => "<$message_id> : Read MDN contact details for $partnership" }) if $log;

    my $message = Net::AS2::Message->create_from_serialized_state($state); # TODO handle die from here
    my $mdn_resp = $as2->send_async_mdn(
        $message->is_success ?
                    Net::AS2::MDN->create_success($message) :
                    Net::AS2::MDN->create_from_unsuccessful_message($message),
        $message->message_id,
    );

    my $code;
    if ($mdn_resp->is_success) {
        $code = HTTP_OK;

        my $ext = $message->is_success ? '' : $message->is_error ? '.error' : '.failed';

        my $message_file = _message_file($receiving, $message_id);
        my $message_file_ext = _message_file($received, $message_id, $ext);
        rename $message_file, $message_file_ext;
        $log->({ level => 'debug', message => "<$message_id> : Moved message file to $message_file_ext" }) if $log;

        my $message_file_state = _message_file($received, $message_id, '.state.sent');
        rename $state_file, $message_file_state;
        $log->({ level => 'debug', message => "<$message_id> : Moved state file to $message_file_state" }) if $log;

        $log->({ level => 'info', message => "<$message_id> : Sent MDN receipt to $partnership" }) if $log;
    }
    else {
        $code = $mdn_resp->code;

        my $now = strftime("%F-%H-%M-%S", localtime);
        my $error_file = "$received/$message_id.mdn.error";

        _save_file($error_file, $code . "\n$now\n" . $mdn_resp->content);
        $log->({ level => 'debug', message => "<$message_id> : Creating failed to send MDN file $error_file" }) if $log;

        my $ext = $message->is_error ? '.error' : '.failed';

        my $message_file = _message_file($receiving, $message_id);
        my $message_file_ext = _message_file($received, $message_id, $ext);
        rename $message_file, $message_file_ext;

        $log->({ level => 'debug', message => "<$message_id> : Moved message file to $message_file_ext" }) if $log;
    }

    return $request->new_response($code);
}

=item MDNreceive ( request )

Receives an MDN receipt from a partner.

The POST request is received via a URL of the form
/MDNreceive/C<partnership>

The received MDN is decoded.

If the receipt is for a successful transfer, the Original Message ID
is extracted and the file in the SENDING directory is moved to the
SENT directory and its contents replaced with the decoded MDN details.

Otherwise, the MDN details are stored in SENDING directory with a
filename called UNKNOWN.MDN.C<Message-Id> with a 200 HTTP response
being returned.

=over 4

=item Message-Id

The AS2 Message ID.

The Message ID is validated to ensure it conforms to RFC 2822.

=item Content-Type

The Content-Type of the data being received.

=item AS2-VERSION

The AS2 Protocol version, it should be in the form 1.x. Only 1.0 is supported.

See RFC 4130 for further details about the different version numbers.

=item AS2-FROM

The partner's AS2 ID.

This value should match the PartnerId in the C<partnership.json> file.

=item AS2-TO

The receiver's (i.e. this application's) AS2 ID.

This value should match the MyId in the C<partnership.json> file.

=back

=cut

sub MDNreceive {
    my ($self, $request) = @_;

    my $log     = $request->logger;
    my $headers = $request->headers;

    my $message_id = $headers->header('Message-Id');
    if (! $message_id) {
        $log->({ level => 'error', message => "MDNreceive not given Message-Id header" }) if $log;
        return $request->new_response(404);
    }
    $log->({ level => 'debug', message => "$message_id : Starting to receive MDN" }) if $log;

    my $partnership = _partnership($request);
    $log->({ level => 'debug', message => "$message_id : from $partnership" }) if $log;

    my $as2 = _as2($partnership);

    $message_id = $as2->get_message_id($message_id);

    my ($sending, $sent) = _send_directories($request, $message_id);

    my $mdn = $as2->decode_mdn($headers, $request->content);

    if (my $original_message_id = $mdn->original_message_id) {
        $log->({ level => 'debug', message => "<$message_id> : MDN original message ID <$original_message_id> from $partnership" }) if $log;

        my $body = JSON::XS->new->ascii->canonical->encode({ %$mdn }); # convert to simple hash

        my $message_file = _message_file($sending, $original_message_id);
        _save_file($message_file, $body);

        my $message_file_sent = _message_file($sent, $original_message_id);
        if (-f $message_file_sent) {
            $log->({ level => 'warn', message => "<$message_id> : MDN already received, file exists: $message_file_sent" }) if $log;
        }

        my $ext = ! $mdn->is_success ? '.failed' : '';
        my $message_file_ext = _message_file($sent, $original_message_id, $ext);

        rename $message_file, $message_file_ext;
        $log->({ level => 'debug', message => "<$message_id> : Moved completed message file to $message_file_ext" }) if $log;

        $log->({ level => 'info', message => "<$message_id> : Received MDN$ext receipt from $partnership" }) if $log;
    }
    else {
        my $receipt_file = _message_file($sending, $message_id, '.UNKNOWN.MDN');
        _save_file($receipt_file, $request->content);

        $log->({ level => 'debug', message => "<$message_id> : MDN receipt did not contain valid original_message_id" }) if $log;
    }

    return $request->new_response(HTTP_OK);
}

=item view ( env )

View a given partnership configuration.

The request is received via a URL of the form
/view/C<partnership>

The actual content of the cached private key or certificates are not
displayed, replaced instead by "...".

=back

=cut

sub view {
    my ($self, $request) = @_;

    my $log = $request->logger;

    my $partnership = _partnership($request);

    my $as2 = _as2($partnership);

    # Display relevant partnership, blanking out private and public key text
    my $p = { %$as2 };
    map { delete $p->{$_} } grep { ref($p->{$_}) } keys %$p;
    map { $p->{$_} = '...' } grep { /Key|Certificate/ && ! /File/ } keys %$p;

    my $content  = JSON::XS->new->ascii->canonical->encode($p);

    my $response = $request->new_response(HTTP_OK);
    $response->body($content);
    $response->headers([
        'Content-Type'    => 'application/json; charset=utf-8',
        'Content-Length'  => length($content),
    ]);

    return $response;
}


# INTERNAL FUNCTIONS
#
# _psgi ( api, HTTP_method )
#
# return a PSGI subroutine
#
sub _psgi {
    my ($self, $method, $api) = @_;

    return sub {
        my $request = Plack::Request->new(shift);

        if ($request->method ne $method) {
            if (my $log = $request->logger) {
                $log->({ level => 'error', message => "Called HTTP Method is not $method" });
            }
            return $request->new_response(HTTP_BAD_REQUEST)->finalize;
        }

        return $self->$api($request)->finalize;
    };
}

# _partnership ( request )
#
# get partnership from URI.
#
sub _partnership {
    my $request = shift;

    my $partnership = $request->path =~ s{^/}{}r;
    return $partnership;
}

# _message_file ( dir, message_id, ext )
#
# Return suitable file name for given message id and optional extension.
#

sub _message_file {
    my ($dir, $message_id, $ext) = @_;

    $ext //= '';

    $message_id =~ s{[^-@.a-zA-Z0-9]}{_}g;

    return "$dir/$message_id$ext";
}

# _as2 ( partnership )
#
# Internal routine that returns the L<Net::AS2> object configured
# using a relative filename given by C<partnership>, without the .json
# file extension.
#
# The partnership files are located in C<$PARTNERSHIP_DIR>, given by the
# configuration file.
#

sub _as2 {
    my ($partnership) = @_;

    my $json_file = "$PARTNERSHIP_DIR/$partnership.json";

    croak "No partnership file $json_file" unless -f $json_file;

    my $json   = _slurp_file($json_file);

    my $params = JSON::XS::decode_json($json);

    # Set the certificate directory unless already given for this specific partnership
    $params->{CertificateDirectory} //= $CERTIFICATE_DIR;

    return Net::AS2->new(%$params); # Will die if the parameters are not valid
}

sub _send_directories {
    my ($request, $message_id) = @_;

    my $parent  = $FILE_DIR . '/' . _partnership($request);
    my $sending = "$parent/SENDING";
    my $sent    = "$parent/SENT";

    _create_directories($request->logger, $message_id, $parent, $sending, $sent);

    return ($sending, $sent);
}

sub _receive_directories {
    my ($request, $message_id) = @_;

    my $parent    = $FILE_DIR . '/' . _partnership($request);
    my $receiving = "$parent/RECEIVING";
    my $received  = "$parent/RECEIVED";

    _create_directories($request->logger, $message_id, $parent, $receiving, $received);

    return ($receiving, $received);
}

sub _create_directories {
    my ($log, $message_id, @dir) = @_;

    my $status;
    my $level;
    my @errors;

    foreach my $dir (@dir) {
        next if -d $dir;
        if (mkpath($dir, 0, oct(700))) {
            $status = 'Created';
            $level  = 'debug';
        }
        else {
            $status = 'Error creating';
            $level  = 'error';
            push @errors, $dir;
        }
        $log->({ level => $level, message => "<$message_id> $status directory $dir" }) if $log;
    }
    croak "Error creating directories: @errors" if @errors;

    return;
}

sub _save_file {
    my ($file, $content) = @_;
    open my $fh, '>', $file;
    print $fh $content;
    close $fh;

    return;
}

sub _slurp_file {
    my($file) = @_;
    local $/ = undef;

    open my $fh, '<', $file;
    my $content = scalar(<$fh>);
    close $fh;

    return $content;
}

1;

=head1 EXAMPLES

This module has an /examples directory. It contains an example PSGI
application, its base configuration file, a systemd service for
starman and an nginx conf file with SSL configurations.  There is also
some basic configuration files to get you started with partnering up
with an instance of L<https://github.com/phax/as2-server>.

The module's /t testing directory, includes test cases that forks AS2
L<Plack::Test> applications, and then tests transferring files between
using AS2 synchronous and AS2 asynchronous transfer modes.

=head1 SEE ALSO

L<Net::AS2>

L<RFC 4130|https://www.ietf.org/rfc/rfc4130.txt>, L<RFC 3798|https://www.ietf.org/rfc/rfc3798.txt>
L<RFC 822|https://www.ietf.org/rfc/rfc822.txt>, L<RFC 2822|https://www.ietf.org/rfc/rfc2822.txt>

=head1 LICENSE AND COPYRIGHT

This software is copyright (c) 2019 by Catalyst IT, <ajm@cpan.org>

This is free software; you can redistribute it and/or modify it under the same terms as the Perl 5 programming language system itself.

=head1 BUGS AND LIMITATIONS

No bugs known

The AS2 Protocol Version 1.1 (compression) is not supported.

Unlike other AS2 software, this module does not provide a means to
send file to partners simply by copying a file to a designated 'send'
directory. That functionality could probably be created by combining
L<AnyEvent>, L<Twiggy> and this PSGI interface.

=head1 DISCLAIMER OF WARRANTY

This module is not certificated by any AS2 body. This module creates a basic AS2 server.

When using this server, you must have reviewed and be responsible for
all the actions and inactions caused by this server.

More legal jargon follows:

BECAUSE THIS SOFTWARE IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY FOR THE SOFTWARE, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE SOFTWARE "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SOFTWARE IS WITH YOU. SHOULD THE SOFTWARE PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR, OR CORRECTION.

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR REDISTRIBUTE THE SOFTWARE AS PERMITTED BY THE ABOVE LICENCE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE THE SOFTWARE (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A FAILURE OF THE SOFTWARE TO OPERATE WITH ANY OTHER SOFTWARE), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

=head1 AUTHOR

Andrew Maguire ajm@cpan.org
