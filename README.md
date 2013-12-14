# oh-my-oauth

Did you ever need an easily configurable, yet feature full Ring middleware
to perform OAuth request authentication for your application? Oh my, you've
found it!

## Usage

`oauth.middleware/wrap-oauth` is the middleware you need to wrap around your
request handlers to perform OAuth authentication. The middleware function
takes a number of options to control its behavior.

    :consumer-secret-fn - a function to lookup the shared secret for a given
                          consumer key. The function takes the consumer key
                          as its only parameter and should return the
                          corresponding consumer secret, or nil if it can't
                          be found. This option is required.

    :token-secret-fn    - a function to lookup the shared secret for a given
                          token. It takes the token as its only parameter and
                          should return the token secret, or nil if it can't
                          be found. If this option isn't provided, the
                          middleware will try to verify requests using only
                          the consumer secret (0-legged OAuth).

    :error-handler-fn   - a function to handle authentication errors. This
                          function is called with the original handler, the
                          current request and an error details map as
                          parameters, if there's an authentication error in
                          the request. The default is the
                          `default-error-handler` function in this namespace,
                          that responds immediately with an error. You can
                          also use `passthrough-error-handler` or your own
                          function.

    :nonce-validator-fn - a function to validate nonce and timestamp values
                          for an authentication request. The function should
                          take four parameters: the nonce, timestamp, consumer
                          key and token. This function is only called after
                          the request has been checked for required OAuth
                          parameters, so the first three are guaranteed to be
                          non-nil. All values are strings. The default value
                          for this option is the `default-nonce-validator`,
                          that checks if timestamps are at most from one hour
                          ago.

  If this middleware is not correctly configured (right now this means a
  missing :consumer-secret-fn option), all requests that pass through it will
  return a 500 response.

## License

Copyright © 2013 Marcus Brito <marcus@bri.to>

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
