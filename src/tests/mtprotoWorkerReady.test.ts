import {describe, expect, it} from 'vitest';
import {
  MTPROTO_WORKER_READY_MESSAGE,
  waitForMtprotoWorkerReady
} from '@helpers/mtprotoWorkerReady';

type Listener = (event: any) => void;

class FakeWorker {
  private listeners = new Map<string, Set<Listener>>();

  public addEventListener(type: string, listener: Listener) {
    let listeners = this.listeners.get(type);
    if(!listeners) this.listeners.set(type, listeners = new Set());
    listeners.add(listener);
  }

  public removeEventListener(type: string, listener: Listener) {
    this.listeners.get(type)?.delete(listener);
  }

  public dispatch(type: string, event: any) {
    this.listeners.get(type)?.forEach((listener) => listener(event));
  }
}

describe('private MTProto worker readiness', () => {
  it('does not confirm attachment before the worker ready message', async() => {
    const worker = new FakeWorker();
    let attached = false;
    const ready = waitForMtprotoWorkerReady(worker as any).then(() => attached = true);

    worker.dispatch('message', {data: {type: 'invoke'}});
    await Promise.resolve();
    expect(attached).toBe(false);

    worker.dispatch('message', {data: {type: MTPROTO_WORKER_READY_MESSAGE}});
    await ready;
    expect(attached).toBe(true);
  });

  it('rejects when the worker reports an attach error', async() => {
    const worker = new FakeWorker();
    const error = new Error('worker attach failed');
    const ready = waitForMtprotoWorkerReady(worker as any);

    worker.dispatch('error', {error});

    await expect(ready).rejects.toBe(error);
  });
});
