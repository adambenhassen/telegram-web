/*
 * Originally from:
 * https://github.com/zhukov/webogram
 * Copyright (C) 2014 Igor Zhukov <igor.beatle@gmail.com>
 * https://github.com/zhukov/webogram/blob/master/LICENSE
 */

import {TLSerialization} from '@lib/mtproto/tl_utils';
import cryptoWorker from '@lib/crypto/cryptoMessagePort';
import Modes from '@config/modes';
import bytesFromHex from '@helpers/bytes/bytesFromHex';
import bytesToHex from '@helpers/bytes/bytesToHex';
import bigInt from 'big-integer';
import {getMtprotoTarget} from '@config/mtprotoTarget';

export type RSAPublicKeyHex = {
  modulus: string,
  exponent: string
};

export class RSAKeysManager {
  private publicKeysHex: RSAPublicKeyHex[];
  private publicKeysParsed: {
    [hex: string]: RSAPublicKeyHex
  } = {};
  private target = getMtprotoTarget();
  private prepared = false;
  private preparePromise: Promise<void> = null;

  private async loadPublicKeys() {
    if(__MTPROTO_PRIVATE__) {
      return [this.target.mode === 'private' ? this.target.publicKeyHex : undefined];
    }

    const keys = await import('./rsaKeys');
    return Modes.test ? keys.testPublicKeysHex : keys.telegramPublicKeysHex;
  }

  public prepare(): Promise<void> {
    if(this.preparePromise) return this.preparePromise;
    else if(this.prepared) {
      return Promise.resolve();
    }

    return this.preparePromise = this.loadPublicKeys().then((publicKeys) => {
      this.publicKeysHex = publicKeys;
      return Promise.all(this.publicKeysHex.map((keyParsed) => {
        if(!keyParsed) {
          throw new Error('[MT] private MTProto public key metadata is missing');
        }

        const RSAPublicKey = new TLSerialization();
        RSAPublicKey.storeBytes(bytesFromHex(keyParsed.modulus), 'n');
        RSAPublicKey.storeBytes(bytesFromHex(keyParsed.exponent), 'e');

        const buffer = RSAPublicKey.getBuffer();

        return cryptoWorker.invokeCrypto('sha1', buffer).then((bytes) => {
          const fingerprintBytes = bytes.slice(-8);
          fingerprintBytes.reverse();

          this.publicKeysParsed[bytesToHex(fingerprintBytes).toLowerCase()] = {
            modulus: keyParsed.modulus,
            exponent: keyParsed.exponent
          };
        });
      }));
    }).then(() => {
      this.prepared = true;

      // console.log('[MT] Prepared keys');
      this.preparePromise = null;
    });
  }

  public async select(fingerprints: Array<string>) {
    await this.prepare();

    for(let i = 0; i < fingerprints.length; ++i) {
      let fingerprintHex = bigInt(fingerprints[i]).toString(16).toLowerCase();

      if(fingerprintHex.length < 16) {
        fingerprintHex = new Array(16 - fingerprintHex.length).fill('0').join('') + fingerprintHex;
      }

      if(this.target.mode === 'private' && fingerprintHex !== this.target.fingerprint) {
        continue;
      }

      // console.log(fingerprintHex, this.publicKeysParsed);
      const foundKey = this.publicKeysParsed[fingerprintHex];
      if(foundKey) {
        return Object.assign({
          fingerprint: fingerprints[i]
        }, foundKey);
      }
    }
  }
}

export default new RSAKeysManager();
