const byline = require('byline');
const Alpine = require('alpine');

module.exports = function createLogObjStream(stream) {
  return byline.createStream(stream)
    .pipe(new Alpine(Alpine.LOGFORMATS.COMBINED + ' %{TLS-Version}i %{Cipher-Suite}i').getObjectStream());
};
