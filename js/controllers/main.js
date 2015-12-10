// Substantial portion of this javascript code is taken from:
// https://github.com/eirc/pass.js

'use strict';

var openpgp = require('openpgp');

module.exports = function($scope) {

    // Local shared variables
    var privateKeyFileReader = new FileReader(),
        encryptedFileReader = new FileReader(),
        loadedPrivateKey,
        loadedEncryptedFile;

    // Page elements
    var keyPasswordInput = document.getElementById('pwd');

    keyPasswordInput.addEventListener('keydown', function(event) {
        if (event.keyCode === 13) {
            loadedPrivateKey.decrypt(keyPasswordInput.value);
            keyPasswordInput.value = '';

            if (loadedPrivateKey.primaryKey.isDecrypted) {
                handleEncryptedFile('.password-store/office/test.gpg')
            }
        }
    });

    var handlePrivateKeyFile = function(file) {
        loadedPrivateKey = null;

        var rawFile = new XMLHttpRequest();
        rawFile.open("GET", file, true);
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
                    privateKeyReader(data);
                }
            }
        }
        rawFile.send(null);
    };

    var privateKeyReader = function(file) {
        loadedPrivateKey = readBinaryKey(file).keys[0] ||
            openpgp.key.readArmored(file).keys[0];

        if (loadedPrivateKey && loadedPrivateKey.isPrivate() && loadedPrivateKey.primaryKey) {
            if (loadedPrivateKey.primaryKey.isDecrypted) {} else {
                keyPasswordInput.focus();
            }
        } else {}
    }

    var handleEncryptedFile = function(file) {
        loadedEncryptedFile = null;
        var rawFile = new XMLHttpRequest();
        rawFile.open("GET", file, true);
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
                    encryptedFileReader(data);
                }
            }
        }
        rawFile.send(null);
    };

    var encryptedFileReader = function(file) {
        try {
            loadedEncryptedFile = readBinaryMessage(file);
        } catch (e) {
            try {
                loadedEncryptedFile = openpgp.message.readArmored(file);
            } catch (e) {}
        }

        if (loadedEncryptedFile) {}

        decryptIfReady();
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

    var decryptIfReady = function() {

        if (loadedPrivateKey && loadedPrivateKey.primaryKey.isDecrypted && loadedEncryptedFile) {

            // Wrap the slow decryption process in a timeout block so it won't block the browser,
            // also give it a few milliseconds for the renderings above to happen in the browser.
            // The async worker API would be useful here but it cannot work with the file:// protocol due to browser
            // security restrictions and working with file:// is a hard requirement.
            setTimeout(function() {

                openpgp.decryptMessage(loadedPrivateKey, loadedEncryptedFile).then(function(plaintext) {
                    console.log(plaintext);
                }).catch(function(error) {
                    // failure
                });

            }, 10);
        }
    };

    handlePrivateKeyFile('.gnupg/secring.gpg');

};