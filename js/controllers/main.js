// Substantial portion of this javascript code is taken from:
// https://github.com/eirc/pass.js

'use strict';

var openpgp = require('openpgp');

module.exports = function($scope, $q, $sce, $window, Idle) {

    $scope.radioModel = 'office';
    $scope.locked = true;
    $scope.output = [];

    //local shared variables
    var loadedPrivateKey,
        loadedEncryptedFile = [];

    //reload private key if radioModel is selected
    $scope.$watchCollection('radioModel', function() {
        handlePrivateKeyFile('.gnupg/secring.gpg');
    });

    //password input
    var keyPasswordInput = document.getElementById('pwd');
    keyPasswordInput.addEventListener('keydown', function(event) {
        if (event.keyCode === 13) {

            loadedPrivateKey.decrypt(keyPasswordInput.value);
            keyPasswordInput.value = '';
            $scope.output = [];

            if (loadedPrivateKey.primaryKey.isDecrypted) {
                $scope.locked = false;
                //load config file
                var txtFile = new XMLHttpRequest();
                if ($scope.radioModel == 'admin') txtFile.open("GET", "conf/admin.txt", true);
                else txtFile.open("GET", "conf/office.txt", true);
                txtFile.onreadystatechange = function() {
                    if (txtFile.readyState === 4) { // document is ready to parse.
                        if (txtFile.status === 200 || txtFile.status == 0) { // file is found
                            //decrypt all files specified in config
                            var lines = txtFile.responseText.split("\n");
                            for (var i = 0; i < lines.length; i++) {
                                handleEncryptedFile('.password-store/' + lines[i], i);
                            }
                        }
                    }
                }
                txtFile.send(null);
            } else {
                $scope.passForm.pwd.$setValidity("pwd", false);
                console.log("Wrong password");
            }
        }
    });

    var handlePrivateKeyFile = function(filename) {
        loadedPrivateKey = null;
        var rawFile = new XMLHttpRequest();
        rawFile.open("GET", filename, true);
        rawFile.responseType = "arraybuffer";
        rawFile.onreadystatechange = function() {
            if (rawFile.readyState === 4) {
                if (rawFile.status === 200 || rawFile.status == 0) {
                    var data = "";
                    var arrayBuffer = rawFile.response;
                    var byteArray = new Uint8Array(arrayBuffer);
                    for (var i = 0; i < byteArray.byteLength; i++) {
                        data += String.fromCharCode(parseInt(byteArray[i]));
                    }
                    privateKeyReader(filename, data);
                }
            }
        }
        rawFile.send(null);
    };

    var privateKeyReader = function(filename, data) {

        //load private key based on radioModel selection
        if ($scope.radioModel == 'admin') loadedPrivateKey = readBinaryKey(data).keys[1];
        else loadedPrivateKey = readBinaryKey(data).keys[0];

        if (loadedPrivateKey && loadedPrivateKey.isPrivate() && loadedPrivateKey.primaryKey) {
            if (!loadedPrivateKey.primaryKey.isDecrypted) {
                keyPasswordInput.focus();
            }
        } else {
            console.log("Invalid private key " + filename);
        }
    }

    var handleEncryptedFile = function(filename, index) {
        var rawFile = new XMLHttpRequest();
        rawFile.open("GET", filename, true);
        rawFile.responseType = "arraybuffer";
        rawFile.onreadystatechange = function() {
            if (rawFile.readyState === 4) {
                if (rawFile.status === 200 || rawFile.status == 0) {
                    var data = "";
                    var arrayBuffer = rawFile.response;
                    var byteArray = new Uint8Array(arrayBuffer);
                    for (var i = 0; i < byteArray.byteLength; i++) {
                        data += String.fromCharCode(parseInt(byteArray[i]));
                    }
                    encryptedFileReader(filename, data, index);
                }
            }
        }
        rawFile.send(null);
    };

    var encryptedFileReader = function(filename, data, index) {
        try {
            loadedEncryptedFile[index] = readBinaryMessage(data);
        } catch (e) {
            console.log("Invalid file " + filename);
            console.log(e);
        }
        decryptIfReady(filename, index);
    };

    // Read a binary gpg encrypted file to an openpgp Message.
    var readBinaryMessage = function(binaryData) {
        var packetlist = new openpgp.packet.List();
        packetlist.read(binaryData);
        return new openpgp.message.Message(packetlist);
    };

    // Read a binary gpg private keyring file to one or more openpgp Keys.
    var readBinaryKey = function(binaryData) {
        var result = {};
        result.keys = [];
        try {
            var packetlist = new openpgp.packet.List();
            packetlist.read(binaryData);
            var keyIndex = packetlist.indexOfTag(openpgp.enums.packet.publicKey, openpgp.enums.packet.secretKey);
            if (keyIndex.length === 0) {
                throw new Error('No key packet found in armored text');
            }
            for (var i = 0; i < keyIndex.length; i++) {
                var oneKeyList = packetlist.slice(keyIndex[i], keyIndex[i + 1]);
                try {
                    var newKey = new openpgp.key.Key(oneKeyList);
                    result.keys.push(newKey);
                } catch (e) {
                    result.err = result.err || [];
                    result.err.push(e);
                }
            }
        } catch (e) {
            result.err = result.err || [];
            result.err.push(e);
        }
        return result;
    };

    var decryptIfReady = function(filename, index) {

        if (loadedPrivateKey && loadedPrivateKey.primaryKey.isDecrypted && loadedEncryptedFile[index]) {

            // Wrap the slow decryption process in a timeout block so it won't block the browser,
            // also give it a few milliseconds for the renderings above to happen in the browser.
            // The async worker API would be useful here but it cannot work with the file:// protocol due to browser
            // security restrictions and working with file:// is a hard requirement.
            setTimeout(function() {

                openpgp.decryptMessage(loadedPrivateKey, loadedEncryptedFile[index]).then(function(plaintext) {
                    $scope.output.push({
                        file: filename.replace(/.password-store\/|.gpg/g, ''),
                        password: $sce.trustAsHtml(plaintext.replace(/\n/g, "<br>"))
                    });
                    return $q(function(resolve) {
                        resolve();
                    });
                }).catch(function(error) {
                    console.log("Error during decryption process");
                    console.log(error);
                });

            }, 10);
        }

    };

    //reload page after idle timeout
    $scope.$on('IdleStart', function() {
        window.location.reload();
    });

};