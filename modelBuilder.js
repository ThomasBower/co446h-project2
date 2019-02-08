#!/usr/bin/env node

const createLogObjStream = require('./createLogObjStream');
const fs = require('fs').promises;
const path = require('path');
const FuzzySet = require('fuzzyset.js');

const SIMILARITY_THRESHOLD = 0.1;

const FileExtSizes = {};
const UserAgents = {};
const UserAgentSet = FuzzySet();
const SpecificUserAgents = {};

process.stdin.setEncoding('utf8');
const entryStream = createLogObjStream(process.stdin);

let lineCount = 0;

function getGenericAgent(userAgent) {
  return userAgent.replace(/[.0-9]/g, "X").replace(/X+/g, "X");
}

entryStream.on('data', e => {
  lineCount++;
  const userAgent = e['RequestHeader User-agent'];
  const result = UserAgentSet.get(userAgent, null, SIMILARITY_THRESHOLD);
  if (result) {
    UserAgents[result[0][1]]++;
  } else {
    UserAgentSet.add(userAgent);
    UserAgents[userAgent] = 1;
  }
  const respSize = Number(e['sizeCLF']);
  if (isNaN(respSize)) return;
  const fileExt = path.extname((e.request.split(' ')[1] || '').split('?')[0]);
  if (!FileExtSizes[fileExt]) FileExtSizes[fileExt] = [];
  FileExtSizes[fileExt].push(respSize);
  const specificAgent = getGenericAgent(e['RequestHeader User-agent']);
  SpecificUserAgents[specificAgent] = SpecificUserAgents[specificAgent] ? SpecificUserAgents[specificAgent] + 1 : 1;
});

entryStream.on('end', () => {
  Object.keys(FileExtSizes).forEach((key => {
    const sizes = FileExtSizes[key];
    const mean = sizes.reduce((sum, size) => sum + size, 0) / sizes.length;
    const stdDeviation = Math.sqrt(sizes.reduce((sum, size) => sum + Math.pow(size - mean, 2)) / (sizes.length - 1));
    FileExtSizes[key] = { stdDeviation, mean };
  }));
  Object.keys(UserAgents).forEach(key => UserAgents[key] = UserAgents[key] / lineCount);
  Object.keys(SpecificUserAgents).forEach(key => SpecificUserAgents[key] = SpecificUserAgents[key] / lineCount);
  fs.writeFile('./model.json', JSON.stringify({ UserAgents, FileExtSizes, SpecificUserAgents }))
    .catch(error => console.error('Error when saving model:', error));
});
