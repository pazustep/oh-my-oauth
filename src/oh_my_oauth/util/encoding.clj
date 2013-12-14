(ns oh-my-oauth.util.encoding
  "Functions dealing with OAuth percent encoding, as defined in section 3.6
  of the specification"
  (:require [clojure.string :refer [escape]]))

(def ^:private safe-chars
  "A set with all characters considered safe from OAuth percent encoding.
  These are ALPHA, DIGIT, '-', '.', '_' and '~'."
  (let [ranges [[48 58] [65 91] [97 123]] ; 0-9, A-Z, a-z
        safe-chars #{\- \. \_ \~}
        range-to-set #(->> % (apply range) (map char) (set))
        range-sets (map range-to-set ranges)
        safe-sets (conj range-sets safe-chars)]
    (apply clojure.set/union safe-sets)))

(defn ^:private encode-char
  "Percent encodes a character, if it's not safe. Returns a string with the
  percent encoding for the character, or `nil` if it's a safe character."
  [ch]
  (if-not (contains? safe-chars ch)
    (format "%%%X" (int ch))))

(defn percent-encode
  "Percent encodes the given string."
  [str]
  (escape str encode-char))

