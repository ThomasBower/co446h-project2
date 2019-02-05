const regexStr = process.argv[2];

process.stdin.pipe(new (require('stream').Transform)({
  // writableObjectMode: true,
  transform(chunk, encoding, callback) {
    callback(chunk);
    // return callback(JSON.stringify(chunk));
  }
})).pipe(process.stdout);
