(ns oauth.t-middleware
  (use midje.sweet)
  (require [oauth.middleware :refer [do-oauth wrap-oauth-provider]]))

(def valid-request
  {:request-method :post
   :scheme         :https
   :server-name    "api.twitter.com"
   :server-port    443
   :uri            "/1/statuses/update.json"
   :params         {"include_entities" "true"
                    "status"           "Hello Ladies + Gentlemen, a signed OAuth request!"}
   :headers        {"authorization"
                     (str "OAuth oauth_consumer_key=\"xvz1evFS4wEEPTGEFPHBog\","
                          "oauth_nonce=\"kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg\","
                          "oauth_signature_method=\"HMAC-SHA1\","
                          "oauth_timestamp=\"1318622958\","
                          "oauth_token=\"370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb\","
                          "oauth_version=\"1.0\","
                          "oauth_signature=\"tnnArxj06cWHq44gCs1OSKk%2FjLY%3D\"")}})

(def missing-params-request
  {:request-method :post
   :scheme         :https
   :server-name    "api.twitter.com"
   :server-port    443
   :uri            "/1/statuses/update.json"
   :params         {"include_entities" "true"
                    "status"           "Hello Ladies + Gentlemen, a signed OAuth request!"}
   :headers        {"authorization"
                     (str "OAuth oauth_consumer_key=\"xvz1evFS4wEEPTGEFPHBog\","
                          "oauth_timestamp=\"1318622958\","
                          "oauth_token=\"370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb\","
                          "oauth_version=\"1.0\","
                          "oauth_signature=\"tnnArxj06cWHq44gCs1OSKk%2FjLY%3D\"")}})

(def invalid-signature-request
  {:request-method :post
   :scheme         :https
   :server-name    "api.twitter.com"
   :server-port    443
   :uri            "/1/statuses/update.json"
   :params         {"include_entities" "true"
                    "status"           "Hello Ladies + Gentlemen, a signed OAuth request!"}
   :headers        {"authorization"
                     (str "OAuth oauth_consumer_key=\"xvz1evFS4wEEPTGEFPHBog\","
                          "oauth_nonce=\"kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg\","
                          "oauth_signature_method=\"HMAC-SHA1\","
                          "oauth_timestamp=\"1318622958\","
                          "oauth_token=\"370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb\","
                          "oauth_version=\"1.0\","
                          "oauth_signature=\"blablabla\"")}})

(def consumer-secret-fn (constantly "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw"))

(def token-secret-fn (constantly "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE"))

(fact "`do-auth` should return :ok for a correctly signed request"
  (do-oauth valid-request
            {:consumer-secret-fn consumer-secret-fn
             :token-secret-fn    token-secret-fn})
  => (has-prefix [:ok]))

(let [handler (fn [req] {:status 200 :body "IT WORKS!"})
      wrapped (wrap-oauth-provider handler
                                   :consumer-secret-fn consumer-secret-fn
                                   :token-secret-fn token-secret-fn)]

  (fact
    "`wrap-oauth-provider` lets a correctly signed request proceed."
        (wrapped valid-request) => (contains {:status 200}))

  (fact
    "`wrap-oauth-provider complains about missing parameters."
    (wrapped missing-params-request) => (contains {:status 400}))

  (fact
    "`wrap-oauth-provider complains about invalid signatures."
    (wrapped invalid-signature-request) => (contains {:status 401})))