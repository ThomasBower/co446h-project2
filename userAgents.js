#!/usr/bin/env node

const Alpine = require('alpine');
const fs = require('fs').promises;
const { Readable, Transform } = require('stream');
const readline = require('readline');
const path = require('path');

const ENCODING = 'utf8';
const NO_DATA_MESSAGE_TIMEOUT_MS = 2000;

// Set up standard input encoding
process.stdin.setEncoding(ENCODING);

// Create new Alpine instance for parsing logs
const alpine = new Alpine();
// Print message if no input is provided after a timeout
let timeoutsElapsed = 0;
const noDataMessage = setInterval(() => {
  timeoutsElapsed++;
  console.error(`No data received on stdin yet after ${timeoutsElapsed * NO_DATA_MESSAGE_TIMEOUT_MS / 1000} seconds...`);
}, NO_DATA_MESSAGE_TIMEOUT_MS);
process.stdin.once('data', () => clearInterval(noDataMessage));

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

class ObjectToLogOutputTransformStream extends Transform {
  constructor() {
    super({
      writableObjectMode: true,
      transform(obj, encoding, callback) {
        return callback(null, `${obj.entry.originalLine}"${severityScores[obj.severity || 'ERROR']}" "${obj.message || '[NO REASON FOUND]'}"\n\n`);
      }
    });
  }
}


class RuleCheckingStream extends Transform {
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
    return this.rules
      .map(rule => {
        const filename = entry.request.split(' ')[1].split('?')[0];
        if (rule.regex) {
          const matches = rule.regex.exec(entry.request);
          return {
            ...rule,
            regex: rule.regex.toString(),
            matches: matches,
            hit: matches && matches.length > 0
          };
        } else if (rule.endsWith && filename.endsWith(rule.endsWith)) {
          return {
            ...rule,
            hit: true
          };
        }
        return { hit: false };
      })
      .filter(({ hit }) => hit)
      .map((rule) => ({ ...rule, entry }));
  }
}

function processLogs(ruleFiles) {
  const entryStream = new ApacheLogEntryStream(process.stdin);
  // Apply anomaly detection
  entryStream.pipe(new AnomalyDetectionStream())
    .pipe(new ObjectToLogOutputTransformStream())
    .pipe(process.stdout);
  // Load rule files and process
  Promise.all(ruleFiles.map(f => fs.readFile(f, ENCODING)))
    .then(ruleSets => ruleSets.join('\n# FILE SEPARATOR #\n'))
    .then(rules => {
      // Process rules
      entryStream
        .pipe(new RuleCheckingStream(rules))
        .pipe(new ObjectToLogOutputTransformStream())
        .pipe(process.stdout);
    })
    .catch(err => {
      console.error('Error occurred while processing rules: ', err);
    });
}

processLogs(process.argv.slice(2));
