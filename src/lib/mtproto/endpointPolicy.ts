import type {MtprotoTarget} from '@config/mtprotoTarget';

export function assertPrivateMtprotoWebSocketEndpoint(target: MtprotoTarget, endpoint: string) {
  if(target.mode === 'private' && endpoint !== target.endpoint) {
    throw new Error('[MT] private MTProto endpoint is not allowed');
  }
}
