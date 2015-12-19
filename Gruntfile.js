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
				},
			},
			script: ['js/*.js'],
		},

		uglify: {
			options: {
				sourceMap: true,
				screwIE8: true,
				beautify: false,
			},
			dist: {
				files: {
					'site.min.js': [
						'bower_components/jquery/dist/jquery.min.js',
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
				tasks: ['jshint', 'uglify'],
			},
		},

		connect: {
			server: {

			},
		},
	});

	grunt.registerTask('serve', function(){
		grunt.task.run(['default', 'connect', 'watch']);
	});

	grunt.loadNpmTasks('grunt-sass');
	grunt.loadNpmTasks('grunt-contrib-connect');
	grunt.loadNpmTasks('grunt-contrib-jshint');
	grunt.loadNpmTasks('grunt-contrib-uglify');
	grunt.loadNpmTasks('grunt-contrib-watch');

	grunt.registerTask('default', ['sass', 'jshint', 'uglify']);
};
