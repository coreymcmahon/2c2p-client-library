var gulp = require('gulp');
var concat = require('gulp-concat');
var util = require('gulp-util');

var env = util.env.production ? 'production' : 'development';

gulp.task('default', function() {
  return gulp.src(['keys/'+env+'.js', 'src/my2c2p.1.6.6.js'])
    .pipe(concat('my2c2p.1.6.6.'+env+'.js'))
    .pipe(gulp.dest('./dist/'));
});