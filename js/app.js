'use strict';

var angular = require('angular');
var angular_idle = require('ng-idle');
var angular_bootstrap = require('angular-ui-bootstrap');

var app = angular.module('PassManager', ['ngIdle', 'ui.bootstrap']);

require('./controllers')