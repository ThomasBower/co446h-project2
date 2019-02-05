#!/usr/bin/env node

const Alpine = require('alpine');
const os = require('os');
const fs = require('fs').promises;
const { Readable } = require('stream');
const readline = require('readline');
const { spawn } = require('child_process');

const ENCODING = 'utf8';
const NO_DATA_MESSAGE_TIMEOUT_MS = 200000;
const NUM_THREADS = os.cpus().length;

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

const entryStream = new ApacheLogEntryStream(process.stdin);

fs.readFile(process.argv[2], ENCODING)
  .then(parseRules)
  .then(rules => {
    const rulePool = rules.slice(NUM_THREADS);
    for (let i = 0; i < NUM_THREADS; i++) {
      const rule = rules[i];
      spawnRegexProc(rule, rulePool);
    }
  })
  .catch(err => {
    console.error('Error occurred while processing rules: ', err);
  });

let finishedProcs = 0;
function spawnRegexProc(rule, pool) {
  const ruleProc = spawn(process.execPath, ['./runRegex', rule.regexString]);
  ruleProc.on('exit', code => {
    if (code !== 0) console.error(`Regex proc with rule "${rule.regex}" failed with exit code ${code}.`);
    if (pool.length !== 0) {
      spawnRegexProc(pool.pop(), pool);
    } else {
      finishedProcs++;
      if (finishedProcs === NUM_THREADS) {
        // All processing complete
      }
    }
  });

  entryStream.pipe(ruleProc.stdin);
  ruleProc.stdout.pipe(process.stdout);
}

function parseRules(ruleFileString) {
  return ruleFileString.replace(/^(#.*|\s*)\n?/gm, '') // Remove comments
    .replace(/\\\n/gm, ' ') // Remove escaped new lines
    .split('\n')
    .filter(rule => /"@rx ((?:[^"\\]|\\.)*)"/g.exec(rule))
    .map(rule => ({
      regexString: /"@rx ((?:[^"\\]|\\.)*)"/g.exec(rule)[1].replace(/\(\?i:/g, '(?:').replace(/\(\?i\)/g, '').replace(/\+\+/g, '+'),
      message: /msg:'([^']+)'/ig.exec(rule) ? /msg:'([^']+)'/ig.exec(rule)[1] : '',
      severity: /severity:'([^']+)'/ig.exec(rule) ? /severity:'([^']+)'/ig.exec(rule)[1] : '',
    }));
}
