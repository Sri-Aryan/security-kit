'use strict';

// An error caused by user input or project state. Printed without a stack trace.
class UserError extends Error {
  constructor(message, hint) {
    super(message);
    this.userError = true;
    this.hint = hint;
  }
}

module.exports = { UserError };
