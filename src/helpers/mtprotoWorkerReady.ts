export const MTPROTO_WORKER_READY_MESSAGE = '__mtproto_worker_ready__';

type WorkerEventTarget = {
  addEventListener: (type: string, listener: (event: any) => void) => void,
  removeEventListener: (type: string, listener: (event: any) => void) => void,
  start?: () => void
};

type WorkerLike = WorkerEventTarget & {
  port?: WorkerEventTarget
};

const toWorkerError = (event: any) => {
  if(event instanceof Error) return event;
  if(event?.error instanceof Error) return event.error;

  return new Error(event?.message || 'MTProto worker failed before it became ready');
};

export function waitForMtprotoWorkerReady(worker: WorkerLike, timeoutMs = 10000): Promise<void> {
  const messageTarget = worker.port || worker;
  const eventTargets = new Set<WorkerEventTarget>([worker, messageTarget]);

  return new Promise((resolve, reject) => {
    let settled = false;

    const cleanup = () => {
      eventTargets.forEach((target) => {
        target.removeEventListener('error', onError);
        target.removeEventListener('messageerror', onError);
      });
      messageTarget.removeEventListener('message', onMessage);
      clearTimeout(timeout);
    };

    const finish = (error?: Error) => {
      if(settled) return;
      settled = true;
      cleanup();
      error ? reject(error) : resolve();
    };

    const onMessage = (event: MessageEvent) => {
      if(event?.data?.type !== MTPROTO_WORKER_READY_MESSAGE) return;
      finish();
    };
    const onError = (event: any) => finish(toWorkerError(event));
    const timeout = setTimeout(() => {
      finish(new Error('MTProto worker did not become ready'));
    }, timeoutMs);

    messageTarget.addEventListener('message', onMessage);
    eventTargets.forEach((target) => {
      target.addEventListener('error', onError);
      target.addEventListener('messageerror', onError);
    });
    messageTarget.start?.();
  });
}

export function notifyMtprotoWorkerReady(source: MessageEventSource) {
  (source as any).postMessage({type: MTPROTO_WORKER_READY_MESSAGE});
}
