#!/usr/bin/env node

const Alpine = require('alpine');
const fs = require('fs').promises;
const { Readable } = require('stream');
const readline = require('readline');
const { fork } = require('child_process');


const ENCODING = 'utf8';
const NO_DATA_MESSAGE_TIMEOUT_MS = 2000;
const NUM_THREADS = System.Environment.ProcessorCount;

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

if (process.argv.length < 1) {
  console.error('No ruleset passed to log processor.');
  process.exit();
}

async function readRules(rulesFile) {
  const rawRules = await fs.readFile(rulesFile, ENCODING);
  return [{
    regexString: '.',
    message: '[TEST RULE] Marks every item as suspicious',
    severity: 'CRITICAL'
  }];
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

readRules(process.argv[0]).then(rules => {
  const rulePool = rules.slice(NUM_THREADS);
  for (let i = 0; i < NUM_THREADS; i++) {
    const rule = rules[i];
    spawnRegexProc(rule, rulePool);
  }
});

function spawnRegexProc(rule, pool) {
  const ruleProc = fork('./runRegex', [rule.regexString], { stdio: [entryStream, 'inherit', 'inherit'] });
  ruleProc.on('exit', code => {
    if (code !== 0) console.error(`Regex proc with rule "${rule.regex}" failed with exit code ${code}.`);
    spawnRegexProc(pool.pop(), pool);
  });
}

