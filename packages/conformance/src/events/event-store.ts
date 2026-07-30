import type { ScenarioEventSink } from './event-bus.js';
import type { ObservedEvent, ObservedEventName } from './event-types.js';

export interface Disposable {
  dispose(): void;
}

export type EventPredicate = (event: ObservedEvent) => boolean;

export interface WaitOptions {
  timeoutMs: number;
  after?: ObservedEvent;
  signal?: AbortSignal;
  inconclusiveMessage?: string;
}

export interface NoEventOptions {
  timeoutMs: number;
  after?: ObservedEvent;
  signal?: AbortSignal;
}

export interface ScenarioEventStore extends ScenarioEventSink {
  all(): ObservedEvent[];
  find(predicate: EventPredicate): ObservedEvent | undefined;
  has(name: ObservedEventName): boolean;
  waitFor(name: ObservedEventName, options: WaitOptions): Promise<ObservedEvent>;
  waitForAny(names: ObservedEventName[], options: WaitOptions): Promise<ObservedEvent>;
  expectNone(names: ObservedEventName[], options: NoEventOptions): Promise<void>;
  subscribe(listener: (event: ObservedEvent) => void): Disposable;
  close(): void;
}

export interface InMemoryScenarioEventStoreOptions {
  acceptLateEvents?: boolean;
}

export class EventStoreTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EventStoreTimeoutError';
  }
}

export class EventStoreAbortedError extends Error {
  constructor(message = 'Event wait aborted') {
    super(message);
    this.name = 'EventStoreAbortedError';
  }
}

export class ForbiddenObservedEventError extends Error {
  readonly event: ObservedEvent;

  constructor(event: ObservedEvent) {
    super(`Forbidden event observed: ${event.name}`);
    this.name = 'ForbiddenObservedEventError';
    this.event = event;
  }
}

interface PendingWaiter {
  predicate: EventPredicate;
  resolve(event: ObservedEvent): void;
  reject(error: Error): void;
  cleanup(): void;
}

/**
 * Whether `event` was observed after `reference`.
 *
 * The wall-clock timestamp is the primary key because it is the only ordering
 * that is comparable across processes: `monotonicMs` is a per-process
 * `performance.now()` reading for events emitted in this process, and a
 * millisecond-truncated wall-clock reading for events replayed from SQLite (see
 * `rowToObservedEvent`). Timestamps carry microsecond resolution and fixed
 * width, so string comparison orders them; `monotonicMs` only breaks ties
 * between events that share one.
 */
export function compareEventOrder(left: ObservedEvent, right: ObservedEvent): number {
  if (left.timestamp !== right.timestamp) return left.timestamp < right.timestamp ? -1 : 1;
  return left.monotonicMs - right.monotonicMs;
}

export function isEventAfter(event: ObservedEvent, reference: ObservedEvent | undefined): boolean {
  return reference === undefined || compareEventOrder(event, reference) > 0;
}

function timeoutMessage(names: ObservedEventName[], options: WaitOptions): string {
  return options.inconclusiveMessage ?? `Timed out waiting for event: ${names.join(', ')}`;
}

export function createInMemoryScenarioEventStore(options: InMemoryScenarioEventStoreOptions = {}): ScenarioEventStore {
  const events: ObservedEvent[] = [];
  const listeners = new Set<(event: ObservedEvent) => void>();
  const waiters = new Set<PendingWaiter>();
  let closed = false;

  function find(predicate: EventPredicate): ObservedEvent | undefined {
    return events.find(predicate);
  }

  function matchExisting(names: ObservedEventName[], options: WaitOptions): ObservedEvent | undefined {
    return find((event) => names.includes(event.name) && isEventAfter(event, options.after));
  }

  function removeWaiter(waiter: PendingWaiter): void {
    waiter.cleanup();
    waiters.delete(waiter);
  }

  function waitForAny(names: ObservedEventName[], waitOptions: WaitOptions): Promise<ObservedEvent> {
    const existing = matchExisting(names, waitOptions);
    if (existing) return Promise.resolve(existing);
    if (closed) return Promise.reject(new EventStoreAbortedError('Event store is closed'));
    if (waitOptions.signal?.aborted) return Promise.reject(new EventStoreAbortedError());

    return new Promise<ObservedEvent>((resolve, reject) => {
      const timer = setTimeout(() => {
        removeWaiter(waiter);
        reject(new EventStoreTimeoutError(timeoutMessage(names, waitOptions)));
      }, waitOptions.timeoutMs);

      const onAbort = (): void => {
        removeWaiter(waiter);
        reject(new EventStoreAbortedError());
      };

      const waiter: PendingWaiter = {
        predicate: (event) => names.includes(event.name) && isEventAfter(event, waitOptions.after),
        resolve,
        reject,
        cleanup: () => {
          clearTimeout(timer);
          waitOptions.signal?.removeEventListener('abort', onAbort);
        }
      };

      waitOptions.signal?.addEventListener('abort', onAbort, { once: true });
      waiters.add(waiter);
    });
  }

  return {
    all: () => [...events],
    find,
    has: (name) => events.some((event) => event.name === name),
    async emit(event) {
      if (closed && !options.acceptLateEvents) return;

      events.push(event);

      for (const listener of listeners) {
        listener(event);
      }

      for (const waiter of [...waiters]) {
        if (!waiter.predicate(event)) continue;
        removeWaiter(waiter);
        waiter.resolve(event);
      }
    },
    waitFor: (name, waitOptions) => waitForAny([name], waitOptions),
    waitForAny,
    expectNone(names, noEventOptions) {
      const existing = matchExisting(names, noEventOptions);
      if (existing) return Promise.reject(new ForbiddenObservedEventError(existing));
      if (closed) return Promise.reject(new EventStoreAbortedError('Event store is closed'));
      if (noEventOptions.signal?.aborted) return Promise.reject(new EventStoreAbortedError());

      return new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => {
          removeWaiter(waiter);
          resolve();
        }, noEventOptions.timeoutMs);

        const onAbort = (): void => {
          removeWaiter(waiter);
          reject(new EventStoreAbortedError());
        };

        const waiter: PendingWaiter = {
          predicate: (event) => names.includes(event.name) && isEventAfter(event, noEventOptions.after),
          resolve: (event) => reject(new ForbiddenObservedEventError(event)),
          reject,
          cleanup: () => {
            clearTimeout(timer);
            noEventOptions.signal?.removeEventListener('abort', onAbort);
          }
        };

        noEventOptions.signal?.addEventListener('abort', onAbort, { once: true });
        waiters.add(waiter);
      });
    },
    subscribe(listener) {
      listeners.add(listener);
      return {
        dispose: () => {
          listeners.delete(listener);
        }
      };
    },
    close() {
      closed = true;
      for (const waiter of [...waiters]) {
        removeWaiter(waiter);
        waiter.reject(new EventStoreAbortedError('Event store closed'));
      }
      listeners.clear();
    }
  };
}
