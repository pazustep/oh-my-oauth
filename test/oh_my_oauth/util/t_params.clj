(ns oh-my-oauth.util.t-params
  (:use midje.sweet)
  (:require [oh-my-oauth.util.params :refer [parse-params]]))

(fact
  "`parse-params` should correctly parse a parameter list"
  (parse-params
    (str "realm=\"testrealm@host.com\","
         "qop=\"auth,auth-int\","
         "nonce=\"dcd98b7102dd\\\"2f0e8b11d0f600bfb0c093\","
         "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""))
  => {"opaque" "5ccc069c403ebaf9f0171e9517f40e41"
      "nonce"  "dcd98b7102dd\\\"2f0e8b11d0f600bfb0c093"
      "qop"    "auth,auth-int"
      "realm"  "testrealm@host.com"})

(fact
  "`parse-params` should return nil for an invalid parameter list"
  (parse-params "xbttt;;") => nil)

(fact
  "`parse-params` should return nil even for partially valid parameter lists"
  (parse-params "realm=\"testrealm@host.com\",eee") => nil)
