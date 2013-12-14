(ns oh-my-oauth.util.t-encoding
  (:use midje.sweet)
  (:require [oh-my-oauth.util.encoding :refer [percent-encode]]))

(fact
  "`percent-encode` should not encode safe characters"
  (percent-encode "abcdAaZ123.-_~") => "abcdAaZ123.-_~")

(fact
  "`percent-encode` should encode everything else"
  (percent-encode "http://www.example.com/test?b=2&c d%20e")
  => "http%3A%2F%2Fwww.example.com%2Ftest%3Fb%3D2%26c%20d%2520e")
