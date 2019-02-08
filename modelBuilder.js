#!/usr/bin/env node

const ApacheLogEntryStream = require('./apacheLogEntryStream');
const fs = require('fs').promises;
const FuzzySet = require('fuzzyset.js');

// Set up standard input encoding
process.stdin.setEncoding('utf8');
const entryStream = new ApacheLogEntryStream(process.stdin);

const SIMILARITY_THRESHOLD = 0.8;

const UserAgents = {};
const UserAgentSet = FuzzySet();

entryStream.on('data', e => {
  const userAgent = e['RequestHeader User-agent']
  const result = UserAgentSet.get(userAgent, null, SIMILARITY_THRESHOLD);
  if (result) {
    UserAgents[result[0][1]]++;
  } else {
    UserAgentSet.add(userAgent);
    UserAgents[userAgent] = 1;
  }
});

entryStream.on('end', () => {
  fs.writeFile('./model.json', JSON.stringify({ UserAgents }))
    .catch(error => console.error('Error when saving model:', error));
});
