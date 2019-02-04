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

if (process.argv.length < 1) {
  console.error('No ruleset passed to log processor.');
  process.exit();
}

async function readRules(rulesFile) {
  const rawRules = await fs.readFile(process.argv[0], ENCODING);
}

class ApacheLogEntryStream extends Readable {
  constructor(input) {
    super({
      objectMode: true
    });
    this._lineReader = readline.createInterface({ input });
  }

  _read(size) {
    this._lineReader.once('line', l => this.push(alpine.parseLine(l)));
  }
}

const entryStream = new ApacheLogEntryStream(process.stdin);
let jsonPipe = new Transform({ writableObjectMode: true, transform(obj, enc, callback) { callback(null, JSON.stringify(obj) + '\n') } });
entryStream.pipe(jsonPipe).pipe(process.stdout);
