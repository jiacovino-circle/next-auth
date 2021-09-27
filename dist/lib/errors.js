"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.DeleteVerificationRequestError = exports.GetVerificationRequestError = exports.CreateVerificationRequestError = exports.DeleteSessionError = exports.UpdateSessionError = exports.GetSessionError = exports.CreateSessionError = exports.UnlinkAccountError = exports.LinkAccountError = exports.DeleteUserError = exports.UpdateUserError = exports.GetUserByProviderAccountIdError = exports.GetUserByIdError = exports.GetUserByEmailError = exports.GetUserError = exports.CreateUserError = exports.AccountNotLinkedError = exports.OAuthCallbackError = exports.UnknownError = void 0;

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

class UnknownError extends Error {
  constructor(error) {
    var _error$message;

    super((_error$message = error === null || error === void 0 ? void 0 : error.message) !== null && _error$message !== void 0 ? _error$message : error);
    this.name = "UnknownError";

    if (error instanceof Error) {
      this.stack = error.stack;
    }
  }

  toJSON() {
    return {
      name: this.name,
      message: this.message,
      stack: this.stack
    };
  }

}

exports.UnknownError = UnknownError;

class OAuthCallbackError extends UnknownError {
  constructor() {
    super(...arguments);

    _defineProperty(this, "name", "OAuthCallbackError");
  }

}

exports.OAuthCallbackError = OAuthCallbackError;

class AccountNotLinkedError extends UnknownError {
  constructor() {
    super(...arguments);

    _defineProperty(this, "name", "AccountNotLinkedError");
  }

}

exports.AccountNotLinkedError = AccountNotLinkedError;

class CreateUserError extends UnknownError {
  constructor() {
    super(...arguments);

    _defineProperty(this, "name", "CreateUserError");
  }

}

exports.CreateUserError = CreateUserError;

class GetUserError extends UnknownError {
  constructor() {
    super(...arguments);

    _defineProperty(this, "name", "GetUserError");
  }

}

exports.GetUserError = GetUserError;

class GetUserByEmailError extends UnknownError {
  constructor() {
    super(...arguments);

    _defineProperty(this, "name", "GetUserByEmailError");
  }

}

exports.GetUserByEmailError = GetUserByEmailError;

class GetUserByIdError extends UnknownError {
  constructor() {
    super(...arguments);

    _defineProperty(this, "name", "GetUserByIdError");
  }

}

exports.GetUserByIdError = GetUserByIdError;

class GetUserByProviderAccountIdError extends UnknownError {
  constructor() {
    super(...arguments);

    _defineProperty(this, "name", "GetUserByProviderAccountIdError");
  }

}

exports.GetUserByProviderAccountIdError = GetUserByProviderAccountIdError;

class UpdateUserError extends UnknownError {
  constructor() {
    super(...arguments);

    _defineProperty(this, "name", "UpdateUserError");
  }

}

exports.UpdateUserError = UpdateUserError;

class DeleteUserError extends UnknownError {
  constructor() {
    super(...arguments);

    _defineProperty(this, "name", "DeleteUserError");
  }

}

exports.DeleteUserError = DeleteUserError;

class LinkAccountError extends UnknownError {
  constructor() {
    super(...arguments);

    _defineProperty(this, "name", "LinkAccountError");
  }

}

exports.LinkAccountError = LinkAccountError;

class UnlinkAccountError extends UnknownError {
  constructor() {
    super(...arguments);

    _defineProperty(this, "name", "UnlinkAccountError");
  }

}

exports.UnlinkAccountError = UnlinkAccountError;

class CreateSessionError extends UnknownError {
  constructor() {
    super(...arguments);

    _defineProperty(this, "name", "CreateSessionError");
  }

}

exports.CreateSessionError = CreateSessionError;

class GetSessionError extends UnknownError {
  constructor() {
    super(...arguments);

    _defineProperty(this, "name", "GetSessionError");
  }

}

exports.GetSessionError = GetSessionError;

class UpdateSessionError extends UnknownError {
  constructor() {
    super(...arguments);

    _defineProperty(this, "name", "UpdateSessionError");
  }

}

exports.UpdateSessionError = UpdateSessionError;

class DeleteSessionError extends UnknownError {
  constructor() {
    super(...arguments);

    _defineProperty(this, "name", "DeleteSessionError");
  }

}

exports.DeleteSessionError = DeleteSessionError;

class CreateVerificationRequestError extends UnknownError {
  constructor() {
    super(...arguments);

    _defineProperty(this, "name", "CreateVerificationRequestError");
  }

}

exports.CreateVerificationRequestError = CreateVerificationRequestError;

class GetVerificationRequestError extends UnknownError {
  constructor() {
    super(...arguments);

    _defineProperty(this, "name", "GetVerificationRequestError");
  }

}

exports.GetVerificationRequestError = GetVerificationRequestError;

class DeleteVerificationRequestError extends UnknownError {
  constructor() {
    super(...arguments);

    _defineProperty(this, "name", "DeleteVerificationRequestError");
  }

}

exports.DeleteVerificationRequestError = DeleteVerificationRequestError;