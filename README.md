# oh-my-oauth

Did you ever need an easily configurable, yet feature full Ring middleware
to perform OAuth request authentication for your application? Oh my, you've
found it!

## Usage

`oauth.middleware/wrap-oauth` is the middleware you need to wrap around your
request handlers to perform OAuth authentication. The middleware function
takes a number of options to control its behavior.

    :consumer-secret-fn - a function to lookup the shared secret for a given
                          consumer key. Its signature should look like this:

                            (defn find-consumer-secret [consumer-key] ...)

                          It should return the consumer secret for the given
                          key. This option is required.

    :token-secret-fn    - a function to lookup the shared secret for a given
                          token. Its signature should look like this:

                            (defn find-token-secret [token] ...)

                          It should return the token secret. If this option
                          isn't provided, the middleware will try to verify
                          requests using only the consumer secret (0-legged
                          OAuth).

    :error-handler-fn   - a function to handle authentication errors. Its
                          signature should look like this:

                            (defn handle-errors [handler request details] ...)

                          Where `handler` is the original handler function
                          being wrapped by this middleware; `request` is the
                          request being currently handled, and `details` is
                          a map with information about why the request failed
                          to authenticate. This maps contains three keys:

                            :error   - a keyword identifying exactly what went
                                       wrong during authentication.
                            :status  - a (proposed) HTTP status code to use in
                                       the response.
                            :message - a (proposed) error message to use in
                                       the resonse.

                          The default is the `default-error-handler` function
                          in this namespace. It responds immediately using the
                          `:status` key as the response status, and the
                          `:message` for the body.

                          As an alternative, the `passthrough-error-handler`
                          function allows the request to proceed, adding the
                          error details map to the `:oauth-error` key in the
                          request.

    :nonce-validator-fn - a function to validate nonce and timestamp values
                          for an authentication request. Its signature should
                          look like this:

                            (defn validate-nonce [nonce timestamp consumer-key token] ...)

                          This function is called after the request has been
                          checked for required parameters, so the first three
                          are guaranteed to be non-nil. All values are strings.

                          The default value for this option is the
                          `default-nonce-validator`, that checks if timestamps
                          are at most from one hour ago, ignoring all other
                          parameters.

If the middleware is not correctly configured (right now this means a
missing `:consumer-secret-fn` option), all wrapped requests will return a
HTTP 500 response and a message explaining the configuration problem as
its body."

## License

Copyright © 2013 Marcus Brito <marcus@bri.to>

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
