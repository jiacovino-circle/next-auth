"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = Discord;

function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) { symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); } keys.push.apply(keys, symbols); } return keys; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys(Object(source), true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

function Discord(options) {
  return _objectSpread({
    id: "discord",
    name: "Discord",
    type: "oauth",
    version: "2.0",
    scope: "identify email",
    params: {
      grant_type: "authorization_code"
    },
    accessTokenUrl: "https://discord.com/api/oauth2/token",
    authorizationUrl: "https://discord.com/api/oauth2/authorize?response_type=code&prompt=none",
    profileUrl: "https://discord.com/api/users/@me",

    profile(profile) {
      if (profile.avatar === null) {
        var defaultAvatarNumber = parseInt(profile.discriminator) % 5;
        profile.image_url = "https://cdn.discordapp.com/embed/avatars/".concat(defaultAvatarNumber, ".png");
      } else {
        var format = profile.avatar.startsWith("a_") ? "gif" : "png";
        profile.image_url = "https://cdn.discordapp.com/avatars/".concat(profile.id, "/").concat(profile.avatar, ".").concat(format);
      }

      return {
        id: profile.id,
        name: profile.username,
        image: profile.image_url,
        email: profile.email
      };
    }

  }, options);
}