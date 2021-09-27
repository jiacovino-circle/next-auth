"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = Foursquare;

function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) { symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); } keys.push.apply(keys, symbols); } return keys; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys(Object(source), true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

function Foursquare(options) {
  var {
    apiVersion
  } = options;
  return _objectSpread({
    id: "foursquare",
    name: "Foursquare",
    type: "oauth",
    version: "2.0",
    params: {
      grant_type: "authorization_code"
    },
    accessTokenUrl: "https://foursquare.com/oauth2/access_token",
    authorizationUrl: "https://foursquare.com/oauth2/authenticate?response_type=code",
    profileUrl: "https://api.foursquare.com/v2/users/self?v=".concat(apiVersion),

    profile(profile) {
      return {
        id: profile.id,
        name: "".concat(profile.firstName, " ").concat(profile.lastName),
        image: "".concat(profile.prefix, "original").concat(profile.suffix),
        email: profile.contact.email
      };
    }

  }, options);
}