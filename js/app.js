(function(){
	'use strict';

	var app = angular.module('site', [
		'ngRoute',
		'pascalprecht.translate',
		'ui.bootstrap',
		'ng-showdown',
		'templates-main',
	])
		.config(Config)
		.controller('TOCController', TOCController)
		.controller('PageController', PageController)
	;

	Config.$inject = ['$translateProvider', '$routeProvider'];
	function Config($translateProvider, $routeProvider){
		$translateProvider.translations({});

		$routeProvider
			.when('/0.7', {
				templateUrl: 'template/toc.html',
				controller: 'TOCController',
				controllerAs: 'vm',
			})
			.when('/0.7/:page', {
				templateUrl: 'template/page.html',
				controller: 'PageController',
				controllerAs: 'vm',
			})
			.otherwise({
				redirectTo: '/0.7'
			})
		;
	}

	function TOCController(){
		var vm = this;
	}

	PageController.$inject = ['$routeParams'];
	function PageController($routeParams){
		var vm = this;

		console.log($routeParams.page);
	}

})();
