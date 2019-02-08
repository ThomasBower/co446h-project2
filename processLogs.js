#!/usr/bin/env node

const fs = require('fs').promises;
const readFileSync = require('fs').readFileSync;
const path = require('path');
const { Transform } = require('stream');
const createLogObjStream = require('./createLogObjStream');
const FuzzySet = require('fuzzyset.js');

const ENCODING = 'utf8';
const NO_DATA_MESSAGE_TIMEOUT_MS = 2000;

// Set up standard input encoding
process.stdin.setEncoding(ENCODING);
const entryStream = createLogObjStream(process.stdin);

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

class IPWhiteListTransformStream extends Transform {
  constructor() {
    super({
      objectMode: true,
      transform(obj, encoding, callback) {
        if (CONFIG.whitelistedIPs && !CONFIG.whitelistedIPs.includes(obj.remoteHost)) {
          this.push(obj);
        }
        callback();
      }
    });
  }
}


class ObjectToLogOutputTransformStream extends Transform {
  constructor() {
    super({
      writableObjectMode: true,
      transform(obj, encoding, callback) {
        return callback(null, `${obj.entry.originalLine}"${this.severityScores[obj.severity || 'ERROR']}" "${obj.message || '[NO REASON FOUND]'}"\n\n`);
      }
    });
    this.severityScores = {
      'CRITICAL': 3,
      'ERROR': 2,
      'WARNING': 1,
      'NOTICE': 0
    };
  }
}


class RuleCheckingStream extends Transform {
  constructor(rules, model) {
    super({
      objectMode: true,
      transform(entry, encoding, callback) {
        this.runSignatureRules(entry);
        if (CONFIG.enableAnomalyDetection) {
          this.ddosCheck(entry);
          this.runUserAgentAnomalyDetection(entry);
          this.runFilesizeAnomalyDetection(entry);
        }
        callback();
      }
    });
    this._rules = rules;
    this._model = model;
    this._userAgentModel = new FuzzySet(Object.keys(model.UserAgents));
    this._countRequestsSeenThisSecond = 0;
    this._previousEntry = null;
  }

  // Assumes the timestamp is accurate to the nearest second
  ddosCheck(entry) {
    if (this._previousEntry && this._previousEntry.time === entry.time) {
      this._countRequestsSeenThisSecond++;
    } else {
      if (this._countRequestsSeenThisSecond > CONFIG.maxRequestsPerSecond) {
        this.push({
          entry: this._previousEntry,
          severity: 'CRITICAL',
          message: `Possible (D)DoS (last request of flood reported) - ${this._countRequestsSeenThisSecond} requests per second.`
        })
      }
      this._countRequestsSeenThisSecond = 1;
    }
    this._previousEntry = entry;
  }

  runSignatureRules(entry) {
    return this._rules.forEach(rule => {
      if (rule.regex) {
        this.runRegexRule(rule, entry);
      } else if (rule.endsWith) {
        this.runEndsWithRule(rule, entry);
      }
    });
  }

  runEndsWithRule(rule, entry) {
    if (entry.request.split(' ')[1].split('?')[0].endsWith(rule.endsWith)) {
      this.push({
        ...rule,
        entry
      });
    }
  }

  runRegexRule(rule, entry) {
    const matches = rule.regex.exec(entry.request);
    if (matches && matches.length > 0) {
      this.push({
        ...rule,
        regex: rule.regex.toString(),
        matches: matches,
        entry
      });
    }
  }

  runUserAgentAnomalyDetection(entry) {
    const ua = entry['RequestHeader User-agent'];

    // Model 1 - Checks for very different user-agent strings
    const match = this._userAgentModel.get(ua, null, 0.1);
    if (!match || this._model.UserAgents[match[0][1]] < CONFIG.userAgentPrevalenceGeneral) {
      this.push({entry, severity: 'WARNING', message: `Unusual user agent detected "${ua}"`});
    }
    // Model 2 - Checks for sightly wrong user-agent strings
    const agentMatch = this._model.SpecificUserAgents[getGenericAgent(ua)];
    if (agentMatch && agentMatch < CONFIG.userAgentPrevalenceSpecific) {
      this.push({entry, severity: 'WARNING', message: `Unusual user agent detected (version masked) "${ua}"`});
    }
  }

  runFilesizeAnomalyDetection(entry) {
    const respSize = Number(entry['sizeCLF']);
    if (isNaN(respSize)) return;
    const fileExt = path.extname((entry.request.split(' ')[1] || '').split('?')[0]);
    const {mean, stdDeviation} = this._model.FileExtSizes[fileExt];
    const threshold = stdDeviation * Math.sqrt(100 / (100 - CONFIG.filesizeAlertPercentile));
    if (Math.abs(respSize - mean) > threshold) this.push({
      entry,
      severity: 'WARNING',
      message: `Unusual file size (${respSize}) for file of type ${fileExt}`
    });
  }
}

function processLogs(ruleFiles) {
  // Load rule files and process
  Promise.all(ruleFiles.map(f => fs.readFile(f, ENCODING)))
    .then(ruleSets => ruleSets.join('\n# FILE SEPARATOR #\n'))
    .then(parseRules)
    .then(rules => Promise.all([rules, fs.readFile('model.json', ENCODING).then(JSON.parse)]))
    .then(([rules, model]) => entryStream
      .pipe(new IPWhiteListTransformStream())
      .pipe(new RuleCheckingStream(rules, model))
      .pipe(new ObjectToLogOutputTransformStream())
      .pipe(process.stdout)
    )
    .catch(err => {
      console.error('Error occurred while processing rules: ', err);
    });
}

function getGenericAgent(userAgent) {
  return userAgent.replace(/[.0-9]/g, "X").replace(/X+/g, "X");
}

// Read config
const CONFIG = JSON.parse(readFileSync('config.json', ENCODING));

processLogs(process.argv.slice(2));

