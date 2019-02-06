#!/usr/bin/env node

const Alpine = require('alpine');
const fs = require('fs').promises;
const { Readable, Transform } = require('stream');
const readline = require('readline');

const ENCODING = 'utf8';
const NO_DATA_MESSAGE_TIMEOUT_MS = 2000;

// Set up standard input encoding
process.stdin.setEncoding(ENCODING);

// Create new Alpine instance for parsing logs
const alpine = new Alpine();
// Print message if no input is provided after a timeout
var timeoutsElapsed = 0;
const noDataMessage = setInterval(() => {
  timeoutsElapsed++;
  console.error(`No data received on stdin yet after ${timeoutsElapsed * NO_DATA_MESSAGE_TIMEOUT_MS / 1000} seconds...`);
}, NO_DATA_MESSAGE_TIMEOUT_MS);
process.stdin.once('data', () => clearInterval(noDataMessage));

if (process.argv.length < 3) {
  console.error('No ruleset passed to log processor.');
  process.exit();
}

class ApacheLogEntryStream extends Readable {
  constructor(input) {
    super({
      objectMode: true
    });
    this._lineReader = readline.createInterface({ input });
  }

  _read(size) {
    // Ignoring size for ease of dev
    this._lineReader.once('line', l => this.push(alpine.parseLine(l)));
  }
}

function parseRules(ruleFileString) {
  return ruleFileString.replace(/^(#.*|\s*)\n?/gm, '') // Remove comments
    .replace(/\\\n/gm, ' ') // Remove escaped new lines
    .split('\n')
    .filter(rule => /"@rx ((?:[^"\\]|\\.)*)"/g.exec(rule))
    .map(rule => ({
      regex: new RegExp(/"@rx ((?:[^"\\]|\\.)*)"/g.exec(rule)[1].replace(/\(\?i:/g, '(?:').replace(/\(\?i\)/g, '').replace(/\+\+/g, '+')),
      message: /msg:'([^']+)'/ig.exec(rule) ? /msg:'([^']+)'/ig.exec(rule)[1] : '[NO MESSAGE PROVIDED]',
      severity: /severity:'([^']+)'/ig.exec(rule) ? /severity:'([^']+)'/ig.exec(rule)[1] : '[NO SEVERITY PROVIDED]',
    }))
    .filter(rule => !!rule.regex);
}


class ObjectToJSONTransformStream extends Transform {
  constructor() {
    super({
      writableObjectMode: true,
      transform(obj, encoding, callback) {
        return callback(null, JSON.stringify(obj) + ',\n');
      }
    });
    this.push('[');
  }
}

class RegexRuleCheckingStream extends Transform {
  constructor(rules) {
    super({
      objectMode: true,
      transform(entry, encoding, callback) {
        this.runRules(entry).forEach(matchedRule => this.push(matchedRule));
        callback();
      }
    });
    this.rules = rules;
  }

  runRules(entry) {
    return this.rules.filter(rule => rule.regex.test(entry.originalLine))
      .map(({ message, severity }) => ({ message, severity, entry }));
  }
}

function processLogs(rulesFile) {
  const entryStream = new ApacheLogEntryStream(process.stdin);
  fs.readFile(rulesFile, ENCODING)
    .then(parseRules)
    .then(rules => entryStream
      .pipe(new RegexRuleCheckingStream(rules))
      .pipe(new ObjectToJSONTransformStream())
      .pipe(process.stdout))
    .catch(err => {
      console.error('Error occurred while processing rules: ', err);
    });
}

processLogs(process.argv[2]);
