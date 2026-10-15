'use strict';

const readline = require('readline');

function canPrompt() {
  return Boolean(process.stdin.isTTY && process.stdout.isTTY);
}

function ask(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

// Ask until the answer is one of the choices (case-insensitive). Empty answer picks the default.
async function choose(question, choices, defaultChoice) {
  for (;;) {
    const answer = (await ask(`${question} [${choices.join('/')}] (${defaultChoice}): `)).toLowerCase();
    if (!answer) return defaultChoice;
    if (choices.includes(answer)) return answer;
  }
}

module.exports = { canPrompt, ask, choose };
