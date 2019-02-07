const Alpine = require('alpine');
const { Readable } = require('stream');
const readline = require('readline');

class ApacheLogEntryStream extends Readable {
  constructor(input) {
    super({
      objectMode: true,
      read() {
        // Ignoring size for ease of dev
        this._lineReader.once('line', l => this.push(this.alpine.parseLine(l)));
      }
    });
    // Create new Alpine instance for parsing logs
    this.alpine = new Alpine();
    this._lineReader = readline.createInterface({ input });
    this._lineReader.on('close', () => this.push(null));
  }

}

module.exports = ApacheLogEntryStream;
