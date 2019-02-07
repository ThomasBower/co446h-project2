#!/usr/bin/env node

const readline = require('readline');

const rl = readline.createInterface({input: process.stdin});

const dict = {};

rl.on('line', l => {
  l = l.trim();
  if (!dict[l]) dict[l] = 0;
  dict[l]++;
});

rl.on('close', () => {
  Object.entries(dict)
    .sort(([_, c1], [__, c2]) => c2 - c1)
    .map(([ip, count]) => console.log(`${ip}: ${count}`));
});
