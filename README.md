PKIX certificates management library for Erlang
===============================================

[![CI](https://github.com/processone/pkix/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/processone/pkix/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/processone/pkix/badge.svg?branch=master&service=github)](https://coveralls.io/github/processone/pkix?branch=master)
[![Hex version](https://img.shields.io/hexpm/v/pkix.svg "Hex version")](https://hex.pm/packages/pkix)

The idea of the library is to simplify certificates configuration in Erlang programs.
Typically an Erlang program which needs certificates (for HTTPS/MQTT/XMPP/etc)
provides a bunch of options such as `certfile`, `chainfile`, `privkey`, etc.
The situation becomes even more complicated when a server supports so called `virtual domains`
because a program is typically required to match a virtual domain with its certificate.
If a user has plenty of virtual domains (stored somewhere in `/etc/letsencrypt/live/*/*.pem`)
it's quickly becoming a nightmare for them to configure all this. The complexity also leads to
errors: a single configuration mistake and a program generates obscure log messages,
unreadable Erlang tracebacks or, even worse, just silently ignores the errors. Fortunately,
the large part of certificates configuration can be automated, reducing a user configuration
to something as simple as:
```yaml
certfiles:
  - /etc/letsencrypt/live/*/*.pem
```
The purpose of the library is to do this dirty job under the hood.

# System requirements

To compile the library you need:

 - Erlang/OTP ≥ 19.0
 - GNU Make. Optional: for running tests or standalone compilation.

# Compiling

Since this is an embedded library, you need to add https://github.com/processone/pkix.git
repo to your rebar configuration or what have you.

# Usage

Start the library as a regular Erlang application:
```erl
> application:ensure_all_started(pkix).
```
or use `pkix:start()` which does the same.

Let's say you have two certificates: `cert1.pem` for `domain1` and `cert2.pem`
for `domain2` with their private keys `key1.pem` and `key2.pem` and
an intermediate CA certificate `ca-intermediate.pem`. Then the flow is the following:
- Add all your PEM files to the "staged" area (the order doesn't matter):
```erl
> pkix:add_file("cert1.pem").
> pkix:add_file("cert2.pem").
> pkix:add_file("key1.pem").
> pkix:add_file("key2.pem").
> pkix:add_file("ca-intermediate.pem").
```
- Commit the changes to some directory, let's say, `"/tmp/certs"`:
```erl
> pkix:commit("/tmp/certs").
```
Now you're able to fetch a certificate file containing full chain and the
private key for domain `domain1` or `domain2`:
```erl
> pkix:get_certfile(<<"domain1">>).
{<<"/tmp/certs/7f9faada4a006091531cd37dafb70ca009630ac3">>,undefined,undefined}
> pkix:get_certfile(<<"domain2">>).
{undefined,<<"/tmp/certs/018e601430ed447e4bb767b2d610c6258c7a4e43">>,undefined}
```
The first element of the tuple is an EC certificate (presented in `cert1.pem`),
the second element is an RSA certificate (presented in `cert2.pem`) and the third element
is a DSA certificate (missing in our example).

# API
TODO. Sorry, read the [source](https://github.com/processone/pkix/blob/master/src/pkix.erl) so far.
