(ns oh-my-oauth.util.params)

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
