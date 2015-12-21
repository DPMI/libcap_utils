module.exports = function(grunt) {
	grunt.initConfig({
		pkg: grunt.file.readJSON('package.json'),

		sass: {
			options: {
				sourceMap: true,
				sourceComments: true,
				includePaths: [
					"bower_components/bootstrap-sass/assets/stylesheets",
					"bower_components/fontawesome/scss",
				],
			},
			dist: {
				files: {
					'site.min.css': 'css/*.scss'
				},
			},
		},

		jshint: {
			options: {
				browser: true,
				devel: true,
				undef: true,
				strict: true,
				validthis: true,
				globals: {
					angular: true,
					showdown: true,
				},
			},
			script: ['js/*.js'],
		},

		html2js: {
			options: {
				useStrict: true,
				base: 'template',
				rename: function(x){ return 'template/' + x; },
			},
			main: {
				src: ['template/*.html'],
				dest: 'js/template.js',
			},
		},

		uglify: {
			options: {
				sourceMap: true,
				screwIE8: true,
				beautify: false,
			},
			vendor: {
				files: {
					'vendor.min.js': [
						'bower_components/angular/angular.js',
						'bower_components/angular-route/angular-route.js',
						'bower_components/angular-translate/angular-translate.js',
						'bower_components/angular-bootstrap/ui-bootstrap-tpls.js',
						'bower_components/angular-sanitize/angular-sanitize.js',
						'bower_components/showdown/dist/showdown.js',
						'bower_components/ng-showdown/dist/ng-showdown.js',
					],
				},
			},
			dist: {
				files: {
					'site.min.js': [
						'js/*.js'
					],
				},
			},
		},

		watch: {
			stylesheet: {
				files: ['css/*.scss'],
				tasks: ['sass'],
			},
			script: {
				files: ['js/*.js'],
				tasks: ['jshint', 'uglify:dist'],
			},
			template: {
				files: ['template/*.html'],
				tasks: ['html2js', 'uglify:dist'],
			},
		},

		connect: {
			server: {

			},
		},
	});

	grunt.loadNpmTasks('grunt-sass');
	grunt.loadNpmTasks('grunt-contrib-connect');
	grunt.loadNpmTasks('grunt-contrib-jshint');
	grunt.loadNpmTasks('grunt-contrib-uglify');
	grunt.loadNpmTasks('grunt-contrib-watch');
	grunt.loadNpmTasks('grunt-html2js');

	grunt.registerTask('serve', function(){
		grunt.task.run(['default', 'connect', 'watch']);
	});

	grunt.registerTask('default', ['sass', 'jshint', 'html2js', 'uglify']);
};
