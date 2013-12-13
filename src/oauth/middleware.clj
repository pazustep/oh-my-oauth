(ns oauth.middleware
  (:require [oauth.signature :as sig]
            [clojure.string :as str]
            [ring.util.codec :as codec]))

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

(defn do-oauth
  "Tries to authenticate the `request` using OAuth.

  If it succeeds, returns a vector with :ok as the first element and a
  modified request as the second. The modified request will have the
  additional :oauth-consumer-key and :oauth-token associated.

  If the authentication fails, returns a vector with :ok as the first element
  and a ring response map as the second. The :status key will be set to 400 or
  401 depending on the type of the error and :body will be set to the error
  message."
  [request {:keys [consumer-secret-fn token-secret-fn]}]
  (let [params (sig/oauth-params request)
        base (sig/signature-base request)
        token-secret-fn (or token-secret-fn (constantly nil))]
    (if (required-params-missing? params)
      [:error {:status 400 :body "Missing OAuth parameter"}]

      (let [signature-method (get params "oauth_signature_method")
            signature-checker (get signature-checkers (str/lower-case signature-method))]
        (if (nil? signature-checker)
          [:error {:status 400 :body "Unsupported signature method"}]

          (let [base-string (sig/signature-base request)
                consumer-key (get params "oauth_consumer_key")
                consumer-secret (consumer-secret-fn consumer-key)
                token (get params "oauth_token")
                token-secret (token-secret-fn token)
                request-sig (codec/percent-decode (get params "oauth_signature"))
                computed-sig (signature-checker base-string consumer-secret token-secret)]
            (if (= request-sig computed-sig)
              [:ok (merge request
                          {:oauth-consumer-key consumer-key
                           :oauth-token        token})]

              [:error {:status 401 :body "Invalid credentials"}])))))))

(defn wrap-oauth-provider
  "Middleware to verify OAuth parameters in the request. Accepts a number of
  options that control the verification:

    :consumer-secret-fn - a function to lookup the shared secret for a given
                          consumer key. The function takes the consumer key
                          as its only parameter and should return the
                          corresponding consumer secret, or nil if it can't
                          be found. This option is mandatory, and an exception
                          will be thrown if it's not provided.

    :token-secret-fn    - a function to lookup the shared secret for a given
                          token. The secret takes the token as its only
                          parameter and should return the token secret, or nil
                          if it can't be found. If this option isn't provided,
                          the middleware will try to verify requests using only
                          the consumer secret (0-legged OAuth)."
  [handler & {:keys [consumer-secret-fn token-secret-fn] :as opts}]
  (if consumer-secret-fn
    (fn [request]
      (let [[outcome request-or-response] (do-oauth request opts)]
        (if (= :ok outcome)
          (handler request-or-response)
          request-or-response)))))
