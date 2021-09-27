"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = Zoho;

function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) { symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); } keys.push.apply(keys, symbols); } return keys; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys(Object(source), true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

function Zoho(options) {
  return _objectSpread({
    id: "zoho",
    name: "Zoho",
    type: "oauth",
    version: "2.0",
    scope: "AaaServer.profile.Read",
    params: {
      grant_type: "authorization_code"
    },
    accessTokenUrl: "https://accounts.zoho.com/oauth/v2/token",
    authorizationUrl: "https://accounts.zoho.com/oauth/v2/auth?response_type=code",
    profileUrl: "https://accounts.zoho.com/oauth/user/info",

    profile(profile) {
      return {
        id: profile.ZUID,
        name: "".concat(profile.First_Name, " ").concat(profile.Last_Name),
        email: profile.Email,
        image: null
      };
    }

  }, options);
}