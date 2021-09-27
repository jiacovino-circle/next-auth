"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = csrfTokenHandler;

var _crypto = require("crypto");

var cookie = _interopRequireWildcard(require("./cookie"));

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function _getRequireWildcardCache(nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

function csrfTokenHandler(req, res) {
  var {
    cookies,
    secret
  } = req.options;
  console.log("DEBUGGING csrfTokenHandler()");

  if (cookies.csrfToken.name in req.cookies) {
    console.log("DEBUGGING csrfTokenHandler()", "cookies.csrfToken.name IS in req.cookies");
    var [_csrfToken, _csrfTokenHash] = req.cookies[cookies.csrfToken.name].split('|');
    console.log("DEBUGGING csrfTokenHandler(): csrfToken", _csrfToken);
    console.log("DEBUGGING csrfTokenHandler(): csrfTokenHash", _csrfTokenHash);
    var expectedCsrfTokenHash = (0, _crypto.createHash)('sha256').update("".concat(_csrfToken).concat(secret)).digest('hex');
    console.log("DEBUGGING csrfTokenHandler(): expectedCsrfTokenHash", expectedCsrfTokenHash);

    if (_csrfTokenHash === expectedCsrfTokenHash) {
      var csrfTokenVerified = req.method === 'POST' && _csrfToken === req.body.csrfToken;
      req.options.csrfToken = _csrfToken;
      req.options.csrfTokenVerified = csrfTokenVerified;
      console.log("DEBUGGING csrfTokenHandler(): csrfTokenVerified", csrfTokenVerified);
      return;
    }
  }

  console.log("DEBUGGING csrfTokenHandler()", "If no csrfToken from cookie - because it's not been set yet, or because the hash doesn't match (e.g. because it's been modifed or because the secret has changed) create a new token.");
  var csrfToken = (0, _crypto.randomBytes)(32).toString('hex');
  var csrfTokenHash = (0, _crypto.createHash)('sha256').update("".concat(csrfToken).concat(secret)).digest('hex');
  var csrfTokenCookie = "".concat(csrfToken, "|").concat(csrfTokenHash);
  cookie.set(res, cookies.csrfToken.name, csrfTokenCookie, cookies.csrfToken.options);
  req.options.csrfToken = csrfToken;
}