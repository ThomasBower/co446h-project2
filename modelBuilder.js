#!/usr/bin/env node

const ApacheLogEntryStream = require('./apacheLogEntryStream');
const fs = require('fs').promises;

// Set up standard input encoding
process.stdin.setEncoding('utf8');
const entryStream = new ApacheLogEntryStream(process.stdin);

const Model = {};

const entries = [];

entryStream.on('data', e => {
  entries.push(e);
  // console.log(e);
});

entryStream.on('end', () => {
  fs.writeFile('./model.json', JSON.stringify(Model))
    .catch(error => console.error('Error when saving model:', error));
  fs.writeFile('./entries.json', JSON.stringify(entries))
    .catch(error => console.error('Error when saving entries:', error));
});
