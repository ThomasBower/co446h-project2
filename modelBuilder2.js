#!/usr/bin/env node

const createLogObjStream = require('./createLogObjStream');
const fs = require('fs').promises;
const FuzzySet = require('fuzzyset.js');

const SIMILARITY_THRESHOLD = 0.9;

const UserAgents = {};
const UserAgentSet = FuzzySet();

process.stdin.setEncoding('utf8');
const entryStream = createLogObjStream(process.stdin);

let lineCount = 0;
entryStream.on('data', e => {
  lineCount++;
  const userAgent = e['RequestHeader User-agent'].replace(/[.0-9]/g, "X").replace(/X+/g, "X");
  const result = UserAgentSet.get(userAgent, null, SIMILARITY_THRESHOLD);
  if (result) {
    UserAgents[result[0][1]]++;
  } else {
    UserAgentSet.add(userAgent);
    UserAgents[userAgent] = 1;
  }
});

entryStream.on('end', () => {
  Object.keys(UserAgents).forEach(key => UserAgents[key] = UserAgents[key] / lineCount);
  fs.writeFile('./model2.json', JSON.stringify({ UserAgents }))
    .catch(error => console.error('Error when saving model:', error));
});
