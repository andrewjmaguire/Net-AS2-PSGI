package Net::AS2::PSGI::FileHandler;

use strict;
use warnings;
use autodie;
# VERSION

=head1 NAME

Net::AS2::PSGI::FileHandler - Provides methods to handle files being sent and received

=cut

use parent 'Net::AS2::PSGI::File';

=head1 METHODS

=over 4

=item = $self->receiving($content, $receiving_dir)


I<Note> This method must B<not> be used to send an MDN response. It is
called immediately after the request has been received and before
the response has been sent back to the partner.

=cut

sub receiving {
    my ($self, $content, $receiving_dir) = @_;

    my $receiving_file = $self->file($receiving_dir);

    $self->write($receiving_file, $content);

    $self->logger(debug => "Receiving content saved in $receiving_file");

    return $receiving_file;

}

=item = $self->received($content, $dir, $message)


I<Note> This method must B<not> be used to send an MDN response. It is
called immediately after the request has been received and before
the response has been sent back to the partner.

=cut

sub received {
    my ($self, $receiving_file, $received_dir, $message) = @_;

    my $ext = $message->is_success ? '' : $message->is_error ? '.error' : '.failed';

    my $received_file = $self->file($received_dir, $ext);

    rename $receiving_file, $received_file;

    my $content_filename = $message->filename // '';

    $self->logger(debug => "Received '$content_filename' saved in file $received_file");

    return $received_file;

}

=item = $self->sending($content, $sending_file)


=cut

sub sending {
    my ($self, $content, $sending_file) = @_;

    $self->write($sending_file, $content);

    $self->logger(debug => "Sending file $sending_file");

    return;

}

=item = $self->sent($content, $dir, $successful)


=cut

sub sent {
    my ($self, $sending_file, $sent_dir, $successful) = @_;

    my $ext = $successful ? '' : '.failed';

    my $sent_file = $self->file($sent_dir, $ext);

    rename $sending_file, $sent_file;

    $self->logger(debug => "Sent file $sent_file");

    return;
}

=back

=cut


1;
