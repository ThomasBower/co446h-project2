#!/usr/bin/env node

const ApacheLogEntryStream = require('./apacheLogEntryStream');
const fs = require('fs').promises;

// Set up standard input encoding
process.stdin.setEncoding('utf8');
const entryStream = new ApacheLogEntryStream(process.stdin);

const Model = {};
const blacklistedKeys = ['originalLine'];

entryStream.on('data', e => {
  Object.keys(e).forEach(key => {
    if (blacklistedKeys.includes(key)) return;
    Model[key] = Model[key] || {};
    Model[key][e[key]] = Model[key][e[key]] + 1 || 1;
  });
});

entryStream.on('end', () => {
  const NormalisedModel = {};
  Object.keys(Model).forEach(key =>
    NormalisedModel[key] = Object.entries(Model[key]).map(([value, count]) => ({ value, count })));
  fs.writeFile('./model.json', JSON.stringify(NormalisedModel))
    .catch(error => console.error('Error when saving model:', error));
});
