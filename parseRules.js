const fsPromises = require('fs').promises;

async function parseRules(filename) {
  let rules = await fsPromises.readFile(filename, 'utf8');
  rules = rules.replace(/^(#.*|\s*)\n?/gm, ''); // Remove comments
  rules = rules.replace(/\\\n/gm, ' '); // Remove escaped new lines
  rules = rules.split('\n');
  return rules.filter(rule => /"@rx ((?:[^"\\]|\\.)*)"/g.exec(rule))
    .map(rule => {
      return {
        rule,
        regexString: /"@rx ((?:[^"\\]|\\.)*)"/g.exec(rule)[1].replace(/\(\?i:/g, '(?:').replace(/\(\?i\)/g, '').replace(/\+\+/g, '+'),
        message: /msg:'([^']+)'/ig.exec(rule) ? /msg:'([^']+)'/ig.exec(rule)[1] : '',
        severity: /severity:'([^']+)'/ig.exec(rule) ? /severity:'([^']+)'/ig.exec(rule)[1] : '',
      }
    });
}

export default parseRules;
