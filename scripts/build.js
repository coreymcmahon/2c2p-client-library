console.log('requiring concat');
var concat = require('concat');
console.log('checking env');
var env = process.ENV.environment || 'production';
console.log('concatenating');
concat(['keys/'+env+'.js', 'src/my2c2p.1.6.6.js'], 'dist/my2c2p.1.6.6.'+env+'.js');
console.log('finishing.');