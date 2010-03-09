package Tatsumaki::HTTPClient::OAuth;
use strict;

use Carp ();
use URI;
use URI::QueryParam;
use Net::OAuth;
require Net::OAuth::Request;
require Net::OAuth::RequestTokenRequest;
require Net::OAuth::AccessTokenRequest;
require Net::OAuth::ProtectedResourceRequest;

use Any::Moose;

extends 'Tatsumaki::HTTPClient';

has consumer_key    => ( is => 'rw', isa => 'Str', required => 1 );
has consumer_secret => ( is => 'rw', isa => 'Str', required => 1 );

has request_token        => ( is => 'rw', isa => 'Str' );
has request_token_secret => ( is => 'rw', isa => 'Str' );
has verifier             => ( is => 'rw', isa => 'Str' );

has access_token        => ( is => 'rw', isa => 'Str' );
has access_token_secret => ( is => 'rw', isa => 'Str' );

has request_token_url  => ( is => 'rw', isa => 'Str' );
has access_token_url   => ( is => 'rw', isa => 'Str' );
has authorization_url  => ( is => 'rw', isa => 'Str' );
has callback           => ( is => 'rw', isa => 'Str' );
has callback_confirmed => ( is => 'rw', isa => 'Str' );

has signature_method => ( is => 'rw', isa => 'Str', default => sub {'HMAC-SHA1'} );
has protocol_version => ( is => 'rw', isa => 'Str', default => sub {'1.0a'} );

sub rget    { _restricted_request( GET    => @_ ) }
sub rhead   { _restricted_request( HEAD   => @_ ) }
sub rpost   { _restricted_request( POST   => @_ ) }
sub rput    { _restricted_request( PUT    => @_ ) }
sub rdelete { _restricted_request( DELETE => @_ ) }

sub _restricted_request {
    my $method = shift;
    my $self   = shift;
    my $url    = shift;
    $self->make_restricted_request( $url, $method, @_ );
}

sub make_restricted_request {
    my $cb = pop if ref $_[-1] eq 'CODE';
    $cb ||= sub { };
    my $self = shift;
    my ( $url, $method, %extra_params ) = @_;

    $extra_params{token}        = $self->access_token;
    $extra_params{token_secret} = $self->access_token_secret;

    my $request_url = $self->oauth_request_url(
        'Net::OAuth::ProtectedResourceRequest',
        $url, $method, %extra_params );

    $method = lc($method);
    $self->$method( $request_url, $cb );
}

sub _nonce {
    return int( rand( 2**32 ) );
}

sub oauth_1_0a {
    my $self = shift;
    return $self->protocol_version eq '1.0a';
}

sub authorized {
    my $self = shift;
    return (   defined $self->access_token
            && defined $self->access_token_secret )
        ? 1
        : 0;
}

sub get_authorization_url {
    my $cb = pop if ref $_[-1] eq 'CODE';
    $cb ||= sub { };
    my $self              = shift;
    my %params            = @_;
    my $authorization_url = URI->new( $self->authorization_url );

    if ( !$self->request_token ) {
        my $request_token_url = $self->request_token_url;

        if ( $self->oauth_1_0a ) {
            $params{callback} = $self->callback
                unless defined $params{callback};
            Carp::croak
                "You must pass a callback parameter when using OAuth v1.0a"
                unless defined $params{callback};
        }

        my $request_url = $self->oauth_request_url(
            'Net::OAuth::RequestTokenRequest',
            $request_token_url, 'GET', %params );

        $self->get(
            $request_url,
            sub {
                my ($res) = @_;    # is HTTP::Response
                Carp::croak "GET for $request_url failed: "
                    . $res->status_line
                    unless ( $res->is_success );

                my $p = _oauth_response_params(
                    $res->content,
                    [   'oauth_token', 'oauth_token_secret',
                        'oauth_callback_confirmed'
                    ]
                );

                $self->request_token( $p->{'oauth_token'} );
                $self->request_token_secret( $p->{'oauth_token_secret'} );
                $self->callback_confirmed( $p->{'oauth_callback_confirmed'} )
                    if $p->{'oauth_callback_confirmed'};

                Carp::croak
                    "Response does not confirm to OAuth1.0a. "
                    . "oauth_callback_confirmed not received"
                    if $self->oauth_1_0a && !$self->callback_confirmed;

                $params{oauth_token} = $self->request_token;
                $authorization_url->query_form(%params);

                $cb->( $self, $authorization_url );
            }
        );

    }
    else {
        $params{oauth_token} = $self->request_token;
        $authorization_url->query_form(%params);

        $cb->( $self, $authorization_url );
    }
}

sub request_access_token {
    my $cb = pop if ref $_[-1] eq 'CODE';
    $cb ||= sub { };
    my $self             = shift;
    my %params           = @_;
    my $access_token_url = $self->access_token_url;

    $params{token} = $self->request_token unless defined $params{token};
    $params{token_secret} = $self->request_token_secret
        unless defined $params{token_secret};

    if ( $self->oauth_1_0a ) {
        $params{verifier} = $self->verifier unless defined $params{verifier};
        Carp::croak
            "You must pass a verified parameter when using OAuth v1.0a"
            unless defined $params{verifier};
    }

    my $request_url = $self->oauth_request_url(
        'Net::OAuth::AccessTokenRequest',
        $access_token_url, 'GET', %params );

    $self->get(
        $request_url,
        sub {
            my ($res) = @_;    # is HTTP::Response
            Carp::croak "GET for $request_url failed: " . $res->status_line
                unless ( $res->is_success );

            my $p = _oauth_response_params(
                $res->content,
                [ 'oauth_token', 'oauth_token_secret' ]
            );

            $self->access_token( $p->{'oauth_token'} );
            $self->access_token_secret( $p->{'oauth_token_secret'} );

            for my $method qw(request_token request_token_secret verifier) {
                $self->$method('');
            }

            $cb->( $self, $self->access_token, $self->access_token_secret );
        }
    );
}

sub oauth_request_url {
    my $self = shift;

    my $class  = shift;
    my $url    = shift;
    my $method = lc(shift);
    my %extra  = @_;

    my $uri   = URI->new($url);
    my %query = $uri->query_form;
    $uri->query_form( {} );

    my $request = $class->new(
        consumer_key     => $self->consumer_key,
        consumer_secret  => $self->consumer_secret,
        request_url      => $uri,
        request_method   => uc($method),
        signature_method => $self->signature_method,
        protocol_version => $self->oauth_1_0a
          ? Net::OAuth::PROTOCOL_VERSION_1_0A
          : Net::OAuth::PROTOCOL_VERSION_1_0,
        timestamp    => time,
        nonce        => $self->_nonce,
        extra_params => \%query,
        %extra,
    );
    $request->sign;
    Carp::croak "COULDN'T VERIFY! Check OAuth parameters.\n"
        unless $request->verify;

    my $params = $request->to_hash;
    $uri->query_form(%$params);
    $uri;
}

sub _oauth_response_params {
    my ( $content, $keys ) = @_;

    # use URI module to parse query strings like content
    my $faked_uri = URI->new( "/?" . $content, 'http' );
    my $params = {};
    for my $key (@$keys) {
        $params->{$key} = $faked_uri->query_param($key);
    }
    return $params;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;

1;
