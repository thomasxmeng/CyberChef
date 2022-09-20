/**
 * @author Thomas XM [txm20@cantab.ac.uk]
 * @author davidlehn []
 * @copyright Crown Copyright 2022
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import forge from "node-forge";
import { cryptNotice } from "../lib/Crypt.mjs";

/**
 * Generate a Random ED25519 Key Pair
 */

    constructor() {
        super();

        this.name = "Generate ED25519 Key Pair";
        this.module = "Ciphers";
        this.description = `Generate an ED25519 key pair with a given number of bits.<br><br>${cryptNotice}`;
        this.infoURL = "https://en.wikipedia.org/wiki/EdDSA";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
            {
                name: "ED25519 seed", 
                type: "option",
                value: [
                    "32",
                    "XX",
                    "XXX"
                ]
            },
            {
                name: "Output Format",
                type: "option",
                value: [
                    "PEM",
                    "JSON",
                    "DER"
                ]
            }
        ];
    }

    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    async run(input, args) {
        const [Seed, outputFormat] = args;
        /**
         * @seed: overwrite seed value in bytes
         */
        var seed = forge.random.getBytesSync(32);
      
        return new Promise((resolve, reject) => {
            forge.pki.ed25519.generateKeyPair({
                seed: Number(seed),
            }, (err, keypair) => {
                if (err) return reject(err);

                let result;

                switch (outputFormat) {
                    case "PEM":
                        result = forge.pki.publicKeyToPem(keypair.publicKey) + "\n" + forge.pki.privateKeyToPem(keypair.privateKey);
                        break;
                    case "JSON":
                        result = JSON.stringify(keypair);
                        break;
                    case "DER":
                        result = forge.asn1.toDer(forge.pki.privateKeyToAsn1(keypair.privateKey)).getBytes();
                        break;
                }

                resolve(result);
            });
        });
    }

}

export default GenerateED25519KeyPair;
