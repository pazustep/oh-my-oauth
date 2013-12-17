(ns oh-my-oauth.middleware
  (:require [clojure.string :as str]
            [ring.util.codec :as codec]
            [oh-my-oauth.signature :as sig]))

(def ^:private signature-checkers
  {"hmac-sha1" sig/hmac-sha1-signature})

(def ^:private required-params
  #{"oauth_consumer_key"
    "oauth_signature_method"
    "oauth_signature"
    "oauth_timestamp"
    "oauth_nonce"})

(defn- required-params-missing? [params]
  (not-every? params required-params))

;; The following validation functions are supposed to be chained together.
;; Each can produce the expected outcome for the `authenticate-request`
;; function or nil if further checks are necessary.

(defn- validate-required-params
  "Check if all required OAuth protocol parameters are present in the
  request, returning an error if any required parameters are missing."
  [params]
  (let [missing (clojure.set/difference required-params params)]
    (if-not (empty? missing)
      [false {:error :missing-oauth-param
              :status 400
              :message (str "Missing required authentication parameter: " (str/join ", " missing))}])))

(defn- validate-nonce
  "Checks the `oauth_nonce` value, together with `oauth_timestamp`,
  `oauth_customer_key` and `oauth_token` values. The OAuth specification says
  that a nonce should not be reused for the same timestamp, customer key and
  token, and that's the job the `nonce-validator-fn` should perform."
  [{:strs [oauth_nonce oauth_timestamp oauth_customer_key oauth_token]} nonce-validator-fn]
  (if-not (nonce-validator-fn oauth_nonce oauth_timestamp oauth_customer_key oauth_token)
    [false {:error :invalid-nonce
            :status 400
            :message (str "Invalid OAuth nonce or timestamp values")}]))

(defn- validate-signature-method
  "Checks if the `oauth_signature_method` parameter is among the supported
  signature methods"
  [params]
  (let [method (params "oauth_signature_method")]
    (if-not (contains? signature-checkers (str/lower-case method))
      [false {:error :unsupported-signature-method
              :status 400
              :message (str "Unsupported signature method: " method)}])))

(defn- validate-signature
  "Validates the `oauth_signature` value for the request. Returns an error if
  the signature is invalid, or the extracted OAuth credentials if everything
  is ok."
  [request params consumer-secret-fn token-secret-fn]
  (let [base-string (sig/signature-base request)
        consumer-key (params "oauth_consumer_key")
        consumer-secret (consumer-secret-fn consumer-key)
        token (params "oauth_token")
        token-secret (token-secret-fn token)
        sig-checker (signature-checkers (str/lower-case (params "oauth_signature_method")))
        request-sig (params "oauth_signature")
        computed-sig (sig-checker base-string consumer-secret token-secret)]
    (if (= request-sig computed-sig)
      [true {:oauth-consumer-key consumer-key
             :oauth-token token}]
      [false {:error :invalid-signature
              :status 401
              :message "Invalid OAuth signature"}])))

(defn- authenticate-request
  "Tries to authenticate the `request` using OAuth.

  If it succeeds, returns a vector with `true` as the first element and the
  extracted OAuth data as the second.  If the authentication fails, returns
  a vector with `false` as the first element and the error details as the
  second."
  [request consumer-secret-fn token-secret-fn nonce-validator-fn]
  (let [params (sig/oauth-params request)]
    (or (validate-required-params params)
        (validate-nonce params nonce-validator-fn)
        (validate-signature-method params)
        (validate-signature request params consumer-secret-fn token-secret-fn))))

(defn default-error-handler
  "Default error handler used by `wrap-oauth`.

  Interrupts request processing, immediately returning an appropriate error
  response. Use this if you don't want to handle authentication errors
  yourself, and assume that all requests that reach the wrapped handler are
  properly authenticated."
  [_ _ error]
  {:status (:status error)
   :headers {"Content-Type" "text/plain; charset=utf8"}
   :body (:message error)})

(defn passthrough-error-handler
  "OAuth error handler allowing the request to proceed.

  The authentication error details will be available to the handler under the
  `:oauth-error` key in the request map. Use this if you want to let the
  wrapped handler deal with authentication errors."
  [handler request error]
  (handler (assoc request {:oauth-error error})))

(defn default-nonce-validator
  "Default implementation of the nonce validation function. This
  implementation doesn't really check the nonce value and instead
  only rejects timestamp values older than one hour."
  [_ timestamp _ _]
  (try
    (let [time (-> timestamp Long/parseLong (* 1000))
          one-hour-ago (- (System/currentTimeMillis) 3600000)]
      (> time one-hour-ago))
    (catch NumberFormatException _ false)))

(defn- config-error
  "Builds a ring response map for a 500 HTTP code and an error message when
  the `wrap-oauth` middleware is not configured correctly."
  [message]
  {:status 500
   :headers {"Content-Type" "text/plain; charset=utf8"}
   :body (str "`wrap-oauth` middleware improperly configured: " message)})

(def ^:private default-options
  {:token-secret-fn (constantly nil)
   :error-handler-fn default-error-handler
   :nonce-validator-fn default-nonce-validator})

(defn wrap-oauth
  "Middleware to verify OAuth parameters in the request.

  Accepts a number of options that controls authentication:

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
  [handler & {:as opts}]
  (let [opts (merge default-options opts)
        {:keys [consumer-secret-fn token-secret-fn error-handler-fn nonce-validator-fn]} opts]
    (if consumer-secret-fn
      (fn [request]
        (let [[success details] (authenticate-request request
                                                      consumer-secret-fn
                                                      token-secret-fn
                                                      nonce-validator-fn)]
          (if success
            (handler (merge request details))
            (error-handler-fn handler request details))))
      (fn [_]
        (config-error ":consumer-secret-fn option is required.")))))
