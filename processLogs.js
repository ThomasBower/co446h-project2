#!/usr/bin/env node

const fs = require('fs').promises;
const { Transform } = require('stream');
const ApacheLogEntryStream = require('./apacheLogEntryStream');

const ENCODING = 'utf8';
const NO_DATA_MESSAGE_TIMEOUT_MS = 2000;

// Set up standard input encoding
process.stdin.setEncoding(ENCODING);

// Print message if no input is provided after a timeout
let timeoutsElapsed = 0;
const noDataMessage = setInterval(() => {
  timeoutsElapsed++;
  console.error(`No data received on stdin yet after ${timeoutsElapsed * NO_DATA_MESSAGE_TIMEOUT_MS / 1000} seconds...`);
}, NO_DATA_MESSAGE_TIMEOUT_MS);
process.stdin.once('data', () => clearInterval(noDataMessage));

function parseRules(ruleFileString) {
  return ruleFileString
    .replace(/^(#.*|\s*)\n/gm, '') // Remove comments
    .replace(/\\\n/gm, ' ') // Remove escaped new lines
    .split('\n')
    .filter(line => /^SecRule .+ "@(rx|endsWith)/.test(line) && line.indexOf('chain') === -1)
    .map(rule => {
      if (/"@rx ((?:[^"\\]|\\.)*)"/g.exec(rule)) {
        return ({
          id: /id:(\d+)/i.exec(rule) ? /id:(\d+)/ig.exec(rule)[1] : null,
          regex: new RegExp(/"@rx ((?:[^"\\]|\\.)*)"/g.exec(rule)[1].replace(/\(\?i:/g, '(?:').replace(/\(\?i\)/g, '').replace(/\+\+/g, '+')),
          message: /msg:'([^']+)'/ig.exec(rule) ? /msg:'([^']+)'/ig.exec(rule)[1] : null,
          severity: /severity:'([^']+)'/ig.exec(rule) ? /severity:'([^']+)'/ig.exec(rule)[1] : null,
        });
      } else if (/"@endsWith/g.test(rule)) {
        return ({
          id: /id:(\d+)/i.exec(rule) ? /id:(\d+)/ig.exec(rule)[1] : null,
          endsWith: getFirstMatch(/"@endsWith (\S+)"/ig, rule),
          message: /msg:'([^']+)'/ig.exec(rule) ? /msg:'([^']+)'/ig.exec(rule)[1] : null,
          severity: /severity:'([^']+)'/ig.exec(rule) ? /severity:'([^']+)'/ig.exec(rule)[1] : null,
        });
      }
    })
    .filter(r => !!r);
}

function getFirstMatch(regex, str, defaultVal = null) {
  const matches = regex.exec(str);
  return matches && matches.length > 0 ? matches[1] : defaultVal;
}

const severityScores = {
  'CRITICAL': 3,
  'ERROR': 2,
  'WARNING': 1,
  'NOTICE': 0
};

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

class AnomalyDetectionStream extends Transform {
  constructor() {
    super({
      objectMode: true,
      transform(entry, encoding, callback) {
        if (this.checkModel(entry)) {
          callback(null, {
            entry, severity: 'ERROR', message: 'Model check error'
          });
        }
      }
    })
  }

  checkModel(entry) {
    return false;
  }
}

function processLogs(ruleFiles) {
  const entryStream = new ApacheLogEntryStream(process.stdin);
  // Load rule files and process
  Promise.all(ruleFiles.map(f => fs.readFile(f, ENCODING)))
    .then(ruleSets => ruleSets.join('\n# FILE SEPARATOR #\n'))
    .then(parseRules)
    .then(rules => entryStream
      .pipe(new RuleCheckingStream(rules))
      .pipe(new ObjectToLogOutputTransformStream())
      .pipe(process.stdout))
    .catch(err => {
      console.error('Error occurred while processing rules: ', err);
    });
}

processLogs(process.argv.slice(2));
