(ns oh-my-oauth.t_signature
  (:use midje.sweet)
  (:require [oh-my-oauth.signature :as sig]))

(fact "`parse-authorization` can parse an Authorization header into a clojure map"
  ;; Basic
  (sig/parse-authorization "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
    => {:scheme "Basic" :params "QWxhZGRpbjpvcGVuIHNlc2FtZQ==", :realm nil}

  ;; Digest
  (sig/parse-authorization
    (str "Digest "
         "realm=\"testrealm@host.com\","
         "qop=\"auth,auth-int\","
         "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\","
         "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""))
    => {:scheme "Digest"
        :realm  "testrealm@host.com"
        :params {"qop" "auth,auth-int"
                 "nonce" "dcd98b7102dd2f0e8b11d0f600bfb0c093"
                 "opaque" "5ccc069c403ebaf9f0171e9517f40e41"}}

  ;; OAuth
  (sig/parse-authorization
    (str "OAuth realm=\"Example\","
         "oauth_consumer_key=\"0685bd9184jfhq22\","
         "oauth_token=\"ad180jjd733klru7\","
         "oauth_signature_method=\"HMAC-SHA1\","
         "oauth_signature=\"wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D\","
         "oauth_timestamp=\"137131200\","
         "oauth_nonce=\"4572616e48616d6d65724c61686176\","
         "oauth_version=\"1.0\""))
    => {:scheme "OAuth"
        :realm  "Example"
        :params {"oauth_consumer_key"     "0685bd9184jfhq22"
                 "oauth_token"            "ad180jjd733klru7"
                 "oauth_signature_method" "HMAC-SHA1"
                 "oauth_signature"        "wOJIO9A2W5mFwDgiDvZbTSMK/PY="
                 "oauth_timestamp"        "137131200"
                 "oauth_nonce"            "4572616e48616d6d65724c61686176"
                 "oauth_version"          "1.0"}})

(fact "`base-uri` correctly derives the base string URI from a request"
  (sig/base-uri
    {:scheme :http
     :server-name "EXAMPLE.COM"
     :server-port 80
     :uri "/r%20v/X"})
  => "http://example.com/r%20v/X")

(fact "`base-uri` should handle a missing server port"
  (sig/base-uri
    {:scheme :http
     :server-name "EXAMPLE.COM"
     :uri "/path"})
  => "http://example.com/path")

;; Example used in RFC 5849
(def req1
  {:request-method :post
   :scheme         :http
   :server-name    "example.com"
   :server-port    80
   :uri            "/request"
   :params         {"a2" "r b"
                    "a3" ["a" "2 q"]
                    "c2" ""
                    "c@" ""
                    "b5" "=%3D"}
   :headers        {"authorization"
                     (str "OAuth realm=\"Example\","
                          "oauth_consumer_key=\"9djdj82h48djs9d2\","
                          "oauth_token=\"kkk9d7dh3k39sjv7\","
                          "oauth_signature_method=\"HMAC-SHA1\","
                          "oauth_timestamp=\"137131201\","
                          "oauth_nonce=\"7d8f3e4a\","
                          "oauth_signature=\"bYT5CMsGcbgUdFHObYMEfcx6bsw%3D\"")}})

;; Example from Twitter docs at https://dev.twitter.com/docs/auth/creating-signature
(def req2
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
                          "oauth_version=\"1.0\"")}})


;; This example comes from section 3.4.1.1
(fact "`signature-base` correctly derives the signature base string from a request"
  (sig/signature-base req1)
  => (str "POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q"
          "%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_"
          "key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_m"
          "ethod%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk"
          "9d7dh3k39sjv7")

  (sig/signature-base req2)
  => (str "POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&inc"
          "lude_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%"
          "26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_"
          "signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth"
          "_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth"
          "_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%"
          "252C%2520a%2520signed%2520OAuth%2520request%2521"))

(fact "`hmac-sha1-signature` verifies signatures correctly"
  (sig/hmac-sha1-signature (sig/signature-base req2)
                           "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw"
                           "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE")
  => "tnnArxj06cWHq44gCs1OSKk/jLY=")
