/*
 * Originally from:
 * https://github.com/zhukov/webogram
 * Copyright (C) 2014 Igor Zhukov <igor.beatle@gmail.com>
 * https://github.com/zhukov/webogram/blob/master/LICENSE
 */

import MTTransport, {MTConnectionConstructable} from '@lib/mtproto/transports/transport';
import Modes from '@config/modes';
import App from '@config/app';
import indexOfAndSplice from '@helpers/array/indexOfAndSplice';
import HTTP from '@lib/mtproto/transports/http';
import Socket from '@lib/mtproto/transports/websocket';
import TcpObfuscated from '@lib/mtproto/transports/tcpObfuscated';
import {IS_WEB_WORKER} from '@helpers/context';
import {DcId} from '@types';
import {getEnvironment} from '@environment/utils';
import SocketProxied from '@lib/mtproto/transports/socketProxied';
import {getMtprotoTarget, isPrivateMtprotoTarget, validateMtprotoTarget} from '@config/mtprotoTarget';
import type {MtprotoTarget} from '@config/mtprotoTarget';

export type TransportType = 'websocket' | 'https' | 'http';
export type ConnectionType = 'client' | 'download' | 'upload';
export type MtprotoRoute = {
  dcId: DcId,
  connectionType: ConnectionType,
  transportType: 'websocket',
  endpoint: string
};
type Servers = {
  [transportType in TransportType]: {
    [connectionType in ConnectionType]: {
      [dcId: DcId]: MTTransport[]
    }
  }
};

const TEST_SUFFIX = Modes.test ? '_test' : '';
const PREMIUM_SUFFIX = '_premium';
const RETRY_TIMEOUT_CLIENT = 3000;
const RETRY_TIMEOUT_DOWNLOAD = 3000;

export function getTelegramConnectionSuffix(connectionType: ConnectionType) {
  return connectionType === 'client' ? '' : '-1';
}

// A dcId can arrive from the service worker's `stream/` route, i.e. from a URL any page
// can craft: interpolated unchecked it turns the endpoint into an attacker-chosen host
// (`1.evil.com/` -> wss://kws1.evil.com/-1.web.telegram.org/apiws). Telegram has exactly
// five DCs, so validate here, before the value can reach a URL or a storage key.
export function assertValidDcId(dcId: DcId): DcId {
  const id = +dcId;
  if(typeof dcId !== 'number' || !Number.isInteger(id) || id < 1 || id > 5) {
    throw new Error('[MT] invalid dcId: ' + dcId);
  }

  return id as DcId;
}

export function resolveMtprotoRoute({
  target,
  dcId,
  connectionType,
  transportType,
  migrationDcId
}: {
  target: MtprotoTarget,
  dcId: DcId,
  connectionType: ConnectionType,
  transportType: TransportType,
  premium?: boolean,
  migrationDcId?: DcId
}): MtprotoRoute {
  const validTarget = validateMtprotoTarget(target);
  const validDcId = assertValidDcId(dcId);
  const routeDcId = migrationDcId === undefined ? validDcId : assertValidDcId(migrationDcId);
  if(!['client', 'download', 'upload'].includes(connectionType)) {
    throw new Error('[MT] invalid connection type: ' + connectionType);
  }
  if(validTarget.mode !== 'private') {
    throw new Error('[MT] private route requested for a Telegram target');
  }
  if(transportType !== 'websocket') {
    throw new Error('[MT] private MTProto target only permits websocket transport');
  }

  return {
    dcId: routeDcId,
    connectionType,
    transportType,
    endpoint: validTarget.endpoint
  };
}

export function constructTelegramWebSocketUrl(_dcId: DcId, connectionType: ConnectionType, premium?: boolean) {
  const dcId = assertValidDcId(_dcId);

  if(__MTPROTO_PRIVATE__ || isPrivateMtprotoTarget()) {
    return resolveMtprotoRoute({
      target: getMtprotoTarget(),
      dcId,
      connectionType,
      transportType: 'websocket',
      premium
    }).endpoint;
  }

  if(!__MTPROTO_PRIVATE__) {
    if(!import.meta.env.VITE_MTPROTO_HAS_WS) {
      return;
    }

    const suffix = getTelegramConnectionSuffix(connectionType);
    const path = connectionType !== 'client' ? 'apiws' + TEST_SUFFIX + (premium ? PREMIUM_SUFFIX : '') : ('apiws' + TEST_SUFFIX);
    const chosenServer = `wss://${App.suffix.toLowerCase()}ws${dcId}${suffix}.web.telegram.org/${path}`;

    return chosenServer;
  }
}

export class DcConfigurator {
  private sslSubdomains = __MTPROTO_PRIVATE__ ? [] : ['pluto', 'venus', 'aurora', 'vesta', 'flora'];

  private dcOptions = __MTPROTO_PRIVATE__ ? [] : Modes.test ?
    [
      {id: 1, host: '149.154.175.10',  port: 80},
      {id: 2, host: '149.154.167.40',  port: 80},
      {id: 3, host: '149.154.175.117', port: 80}
    ] :
    [
      {id: 1, host: '149.154.175.50',  port: 80},
      {id: 2, host: '149.154.167.50',  port: 80},
      {id: 3, host: '149.154.175.100', port: 80},
      {id: 4, host: '149.154.167.91',  port: 80},
      {id: 5, host: '149.154.171.5',   port: 80}
    ];

  public chosenServers: Servers = {} as any;

  private transportSocket = (dcId: DcId, connectionType: ConnectionType, premium?: boolean) => {
    if(isPrivateMtprotoTarget() && !import.meta.env.VITE_MTPROTO_HAS_WS) {
      throw new Error('[MT] private MTProto target requires WebSocket support');
    }
    if(!import.meta.env.VITE_MTPROTO_HAS_WS) {
      return;
    }

    const chosenServer = constructTelegramWebSocketUrl(dcId, connectionType, premium);
    const logSuffix = connectionType === 'upload' ? '-U' : connectionType === 'download' ? '-D' : '';

    const retryTimeout = connectionType === 'client' ? RETRY_TIMEOUT_CLIENT : RETRY_TIMEOUT_DOWNLOAD;

    let oooohLetMeLive: MTConnectionConstructable;
    if(import.meta.env.VITE_MTPROTO_SW || !import.meta.env.VITE_SAFARI_PROXY_WEBSOCKET) {
      oooohLetMeLive = Socket;
    } else {
      oooohLetMeLive = (getEnvironment().IS_SAFARI && IS_WEB_WORKER && typeof(SocketProxied) !== 'undefined') /* || true */ ? SocketProxied : Socket;
    }

    return new TcpObfuscated(oooohLetMeLive, dcId, chosenServer, logSuffix, retryTimeout);
  };

  private transportHTTP = (dcId: DcId, connectionType: ConnectionType, premium?: boolean) => {
    if(__MTPROTO_PRIVATE__ || isPrivateMtprotoTarget()) {
      throw new Error('[MT] private MTProto target does not permit HTTP transport');
    }
    if(!__MTPROTO_PRIVATE__) {
      if(!import.meta.env.VITE_MTPROTO_HAS_HTTP) {
        return;
      }

      let chosenServer: string;
      if(Modes.ssl || !Modes.http) {
        const suffix = getTelegramConnectionSuffix(connectionType);
        const subdomain = this.sslSubdomains[dcId - 1] + suffix;
        const path = Modes.test ? 'apiw_test1' : 'apiw1';
        chosenServer = 'https://' + subdomain + '.web.telegram.org/' + path;
      } else {
        for(const dcOption of this.dcOptions) {
          if(dcOption.id === dcId) {
            chosenServer = 'http://' + dcOption.host + (dcOption.port !== 80 ? ':' + dcOption.port : '') + '/apiw1';
            break;
          }
        }
      }

      const logSuffix = connectionType === 'upload' ? '-U' : connectionType === 'download' ? '-D' : '';
      return new HTTP(dcId, chosenServer, logSuffix);
    }
  };

  public chooseServer(
    dcId: DcId,
    connectionType: ConnectionType = 'client',
    transportType: TransportType = Modes.transport,
    reuse = true,
    premium?: boolean
  ) {
    /* if(transportType === 'websocket' && !Modes.multipleConnections) {
      connectionType = 'client';
    } */

    dcId = assertValidDcId(dcId);

    if((__MTPROTO_PRIVATE__ || isPrivateMtprotoTarget()) && transportType !== 'websocket') {
      throw new Error('[MT] private MTProto target only permits websocket transport');
    }

    if(!this.chosenServers.hasOwnProperty(transportType)) {
      this.chosenServers[transportType] = {
        client: {},
        download: {},
        upload: {}
      };
    }

    const servers = this.chosenServers[transportType][connectionType];

    if(!(dcId in servers)) {
      servers[dcId] = [];
    }

    const transports = servers[dcId];

    if(!transports.length || !reuse/*  || (upload && transports.length < 1) */) {
      let transport: MTTransport;

      if(__MTPROTO_PRIVATE__ || isPrivateMtprotoTarget()) {
        transport = this.transportSocket(dcId, connectionType, premium);
      } else if(!__MTPROTO_PRIVATE__ && import.meta.env.VITE_MTPROTO_HAS_WS && import.meta.env.VITE_MTPROTO_HAS_HTTP) {
        transport = (transportType === 'websocket' ? this.transportSocket : this.transportHTTP)(dcId, connectionType, premium);
      } else if(!import.meta.env.VITE_MTPROTO_HTTP) {
        transport = this.transportSocket(dcId, connectionType, premium);
      } else {
        transport = this.transportHTTP(dcId, connectionType, premium);
      }

      if(!transport) {
        console.error('No chosenServer!', dcId);
        return null;
      }

      if(reuse) {
        transports.push(transport);
      }

      return transport;
    }

    return transports[0];
  }

  public static removeTransport<T>(obj: any, transport: T) {
    for(const transportType in obj) {
      // @ts-ignore
      for(const connectionType in obj[transportType]) {
        // @ts-ignore
        for(const dcId in obj[transportType][connectionType]) {
          // @ts-ignore
          const transports: T[] = obj[transportType][connectionType][dcId];
          indexOfAndSplice(transports, transport);
        }
      }
    }
  }
}
