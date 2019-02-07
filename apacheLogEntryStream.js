const Alpine = require('alpine');
const { Readable } = require('stream');
const readline = require('readline');

class ApacheLogEntryStream extends Readable {
  constructor(input) {
    super({
      objectMode: true
    });
    // Create new Alpine instance for parsing logs
    this.alpine = new Alpine();
    this._lineReader = readline.createInterface({ input });
  }

  _read(size) {
    // Ignoring size for ease of dev
    this._lineReader.once('line', l => this.push(this.alpine.parseLine(l)));
  }
}

module.exports = ApacheLogEntryStream;
