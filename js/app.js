(function(){
	'use strict';

	var base_url = 'https://raw.githubusercontent.com/DPMI/libcap_utils/master/doc/';

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

	Config.$inject = ['$translateProvider', '$routeProvider', '$showdownProvider'];
	function Config($translateProvider, $routeProvider, $showdownProvider){
		$translateProvider.translations({});

		showdown.extension('rewrite_url', function(){
			return [
				{ type: 'output', regex: 'src="(.*)"', replace: 'src="' + base_url + '/$1"' },
			];
		});

		$showdownProvider.setOption('headerLevelStart', 2);
		$showdownProvider.loadExtension('rewrite_url');

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

	function capitalize(string) {
		return string.charAt(0).toUpperCase() + string.slice(1);
	}

	function getUrl(name){
		return base_url + capitalize(name) + '.md';
	}

	PageController.$inject = ['$routeParams', '$http'];
	function PageController($routeParams, $http){
		var vm = this;
		vm.content = undefined;
		vm.error = undefined;

		$http.get(getUrl($routeParams.page), {cache: true}).then(function(response){
			vm.content = response.data;
		}, function(e){
			vm.error = e.status + ': ' + e.statusText;
		});
	}

})();
