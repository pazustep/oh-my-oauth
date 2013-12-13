(ns oauth.signature
  (:import (javax.crypto Mac)
           (javax.crypto.spec SecretKeySpec))
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [ring.util.codec :as codec]
            [oauth.util.params :refer [parse-params]]
            [oauth.util.encoding :refer [percent-encode]]))

(defn- auth-params
  "Returns the parameters for an `Authorization` header. This tries to parse
  the provided input as a parameter list, returning the resulting map if it
  succeeds. If parsing fails, returns the unmodified input string."
  [input]
  (or (parse-params input) input))

(defn parse-authorization
  "Parses an HTTP 1.1 `Authorization` header, following RFC-2617 as closely
  as possible. Returns a map with three keys, `:scheme`, `:realm`, and
  `:params` if parsing is successful, or `nil` if `auth` doesn't look like
  a proper `Authorization` header. `:scheme` is the authorization scheme,
  like `Basic`, `Digest` or `OAuth`. `:params` is a map, if the contents of
  the auth string after the scheme looks like a key-value list, or a plain
  string otherwise. `:realm` will be the value of the `realm` param, if
  present."
  [auth]
  (if-not (str/blank? auth)
    (let [parts (str/split (or auth "") #" " 2)]
      (let [params (auth-params (second parts))]
        {:scheme (first parts)
         :params (if (map? params) (dissoc params "realm") params)
         :realm  (if (map? params) (params "realm") nil)}))))

(defn oauth-authorization-params
  "Extract OAuth parameters from the `Authorization` request header,
  returning them. Returns nil if the request doesn't have an Authorization
  header with the OAuth scheme."
  [request]
  (let [auth (-> (:headers request)
                 (get "authorization")
                 (parse-authorization))
        scheme (:scheme auth)]
    (if (= "oauth" (str/lower-case scheme))
      (:params auth))))

(defn- upcase-method
  "Returns the upcase method from a ring request, like GET or POST. This is
  the first part in an OAuth signature base string."
  [request]
  (str/upper-case (name (:request-method request))))

(def ^:private default-ports {:http 80 :https 443})

(defn- default-port? [{:keys [scheme server-port]}]
  (or (nil? server-port)
      (= (get default-ports scheme) server-port)))

(defn base-uri
  "Returns the base string URI from a ring request map.
  See OAuth 1.0a specification, section 3.4.1.2"
  [{:keys [scheme server-name server-port uri] :as request}]
  (str (name scheme) "://"
       (str/lower-case server-name)
       (if (default-port? request) "" (str ":" server-port))
       uri))

(def ^:private valid-protocol-params
  #{"oauth_consumer_key"
    "oauth_token"
    "oauth_signature_method"
    "oauth_signature"
    "oauth_timestamp"
    "oauth_nonce"
    "oauth_version"})

(defn oauth-params
  "Returns a map of all OAuth protocol parameters present in the provided
  request. The parameters are collected from the `Authorization` header and
  the :params key."
  [request]
  (-> request
      (oauth-authorization-params)
      (merge (select-keys (:params request) valid-protocol-params))))

(defn normalized-parameters
  "Returns the normalized parameters from a ring request map, as a String.
  Parameters are obtained from the `:params` key (encompassing both query
  [GET] and entity body [POST] parameters) and the `Authorization` header.

  The parameters are then percent-encoded and sorted in ascending lexical
  order. If a parameter appears more than once, the multiple appearances
  are sorted by the value in lexical order.

  Each parameter key and value are then joined together by a `=` character;
  all pairs are then joined with a `&` character."
  [request]
  (letfn [(collect [request]
            (-> request
                (oauth-authorization-params)
                (dissoc "oauth_signature")
                (merge (:params request))))
          (encode-kvs [[key value]]
            (let [values (if (vector? value) value [value])]
              (map (fn [v] [(percent-encode key) (percent-encode v)])
                   (sort values))))
          (encode [params]
            (sort (mapcat encode-kvs params)))
          (join [params]
            (str/join "&" (map #(str/join "=" %) params)))]
    (-> request collect encode join)))

(defn signature-base
  "Returns the OAuth base signature string from a ring request map.
  See OAuth 1.0a specification, section 3.4.1."
  [request]
  (->> request
       ((juxt upcase-method base-uri normalized-parameters))
       (map percent-encode)
       (str/join "&")))

(def ^:private hmac-sha1-algorithm "HmacSHA1")

(defn hmac-sha1-signature
  "Computes a HMAC-SHA1 signature for `text-base`, using `consumer-secret`
  and `token-secret`. Both secrets will be joined with a '&' and used as
  the key for a HMAC-SHA1 operation, performed over `text-base`. The
  resulting bytes are then base64 encoded and returned. You can use
  `signature-base` to obtain the text base for a OAuth request."
  [text-base consumer-secret token-secret]
  (let [keystr (->> [consumer-secret token-secret] (map percent-encode) (str/join "&"))
        keyspec (SecretKeySpec. (.getBytes keystr) hmac-sha1-algorithm)
        mac (Mac/getInstance hmac-sha1-algorithm)]
    (doto mac
      (.init keyspec)
      (.update (.getBytes text-base)))
    (codec/base64-encode (.doFinal mac))))

(defn valid?
  "Returns `true` if the provided Ring request map represents an OAUth
  request with a valid signature, or `false` otherwise."
  [request]
  false)
