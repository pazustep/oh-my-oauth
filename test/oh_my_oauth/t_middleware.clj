(ns oh-my-oauth.t-middleware
  (use midje.sweet)
  (require [oh-my-oauth.middleware :refer [default-nonce-validator wrap-oauth]]))

(def valid-request
  {:request-method :post
   :scheme :https
   :server-name "api.twitter.com"
   :server-port 443
   :uri "/1/statuses/update.json"
   :params {"include_entities" "true"
            "status" "Hello Ladies + Gentlemen, a signed OAuth request!"}
   :headers {"authorization"
             (str "OAuth oauth_consumer_key=\"xvz1evFS4wEEPTGEFPHBog\","
                  "oauth_nonce=\"kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg\","
                  "oauth_signature_method=\"HMAC-SHA1\","
                  "oauth_timestamp=\"1318622958\","
                  "oauth_token=\"370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb\","
                  "oauth_version=\"1.0\","
                  "oauth_signature=\"tnnArxj06cWHq44gCs1OSKk%2FjLY%3D\"")}})

(def missing-params-request
  {:request-method :post
   :scheme :https
   :server-name "api.twitter.com"
   :server-port 443
   :uri "/1/statuses/update.json"
   :params {"include_entities" "true"
            "status" "Hello Ladies + Gentlemen, a signed OAuth request!"}
   :headers {"authorization"
             (str "OAuth oauth_consumer_key=\"xvz1evFS4wEEPTGEFPHBog\","
                  "oauth_timestamp=\"1318622958\","
                  "oauth_token=\"370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb\","
                  "oauth_version=\"1.0\","
                  "oauth_signature=\"tnnArxj06cWHq44gCs1OSKk%2FjLY%3D\"")}})

(def invalid-signature-request
  {:request-method :post
   :scheme :https
   :server-name "api.twitter.com"
   :server-port 443
   :uri "/1/statuses/update.json"
   :params {"include_entities" "true"
            "status" "Hello Ladies + Gentlemen, a signed OAuth request!"}
   :headers {"authorization"
             (str "OAuth oauth_consumer_key=\"xvz1evFS4wEEPTGEFPHBog\","
                  "oauth_nonce=\"kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg\","
                  "oauth_signature_method=\"HMAC-SHA1\","
                  "oauth_timestamp=\"1318622958\","
                  "oauth_token=\"370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb\","
                  "oauth_version=\"1.0\","
                  "oauth_signature=\"blablabla\"")}})

(def no-authorization-request
  {:request-method :post
   :scheme :https
   :server-name "api.twitter.com"
   :server-port 443
   :uri "/1/statuses/update.json"})

(def consumer-secret-fn (constantly "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw"))

(def token-secret-fn (constantly "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE"))

(let [validator #(default-nonce-validator nil % nil nil)
      minutes-from-now #(-> (System/currentTimeMillis) (+ (* % 60000)) str)]
  (fact "`default-nonce-validator` rejects old timestamps"
    (validator "137131201") => false)

  (fact "`default-nonce-validator` rejects invalid timestamps"
    (validator "abcde") => false)

  (fact "`default-nonce-validator` accepts a timestamp from 30 minutes ago"
    (let [timestamp (minutes-from-now -10)]
      (validator timestamp) => true))

  (fact "`default-nonce-validator` accepts a timestamp 10 minutes from now"
    (let [timestamp (minutes-from-now 10)]
      (validator timestamp) => true)))

(fact
  "`wrap-oauth` always returns 500 if it's improperly configured"
  (let [handler (fn [req] {:status 200 :body "success"})
        wrapped (wrap-oauth handler)]
    (wrapped valid-request) => (contains {:status 500})))

(let [handler (fn [req] {:status 200 :body "success"})
      wrapped (wrap-oauth handler
                          :consumer-secret-fn consumer-secret-fn
                          :token-secret-fn token-secret-fn
                          :nonce-validator-fn (constantly true))]

  (fact
    "`wrap-oauth` lets a correctly signed request proceed."
    (wrapped valid-request) => (contains {:status 200}))

  (fact
    "`wrap-oauth` handles a non-OAuth request by returning 400."
    (wrapped no-authorization-request) => (contains {:status 400}))

  (fact
    "`wrap-oauth` complains about missing parameters."
    (wrapped missing-params-request) => (contains {:status 400}))

  (fact
    "`wrap-oauth` complains about invalid signatures."
    (wrapped invalid-signature-request) => (contains {:status 401})))