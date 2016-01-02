'use strict';

var app = require('angular').module('PassManager');

app.controller('MainController', require('./main'))

//configure ng-idle
.config(function(IdleProvider) {
    IdleProvider.idle(5*60);
})
.run(function(Idle){
    Idle.watch();
});