const Alpine = require('alpine');
const alpine = new Alpine();

process.stdin.setEncoding('utf8');

alpine.parseReadStream(process.stdin, function (entry) {
  console.log(entry);
});
