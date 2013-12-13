(ns oauth.util.params)

;; From RFC 2616, section 2.2: token "=" quoted-string
(def ^:private head-re #"([^\p{Cntrl}()<>@,;:\\\"\/\[\]?={} \t]+)=\"((?:[^\"\\]|\\.)*)\"")

;; Same as above, with a prepended comma optionally surrounded by whitespace
(def ^:private tail-re #"\s*,\s*([^\p{Cntrl}()<>@,;:\\\"\/\[\]?={} \t]+)=\"((?:[^\"\\]|\\.)*)\"")

(defn parse-params
  "Parse a comma-separated parameter list, like those used in HTTP headers.
  Returns a map of parameter keys to values, or `nil` if the input fails to
  parse as a parameter list."
  [input]
  (if input
    (loop [input input regex head-re params nil]
      (let [matcher (re-matcher regex input)]
        (if (.lookingAt matcher)
          (let [kv (rest (re-groups matcher))
                params (apply assoc params kv)
                rest (subs input (.end matcher))]
            (if (= (count rest) 0) ; end of input
              params
              (recur rest tail-re params))))))))

;; The following string:
;;    "realm=\"testrealm@host.com\",qop=\"auth,auth-int\",nonce=\"dcd98b7102dd\\\"2f0e8b11d0f600bfb0c093\",opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""
;; Should parse into:
;;    {"opaque" "5ccc069c403ebaf9f0171e9517f40e41", "nonce" "dcd98b7102dd\\\"2f0e8b11d0f600bfb0c093", "qop" "auth,auth-int", "realm" "testrealm@host.com"}
