import { awaitWithSignal } from "./request.js";
import { remainingReleasePolicyMs } from "./operations.js";
import {
  connectAndVerifyTvc,
  type ConnectedTvcRuntime,
  type DecryptionServiceConnectionConfig,
} from "./connect.js";

/**
 * The client's one verified connection, made on first use. Verification runs
 * again once the release policy's validity window no longer holds, and after
 * `forget`.
 */
export type DecryptionServiceSession = {
  /** The verified connection, verifying first when there is none or it no longer holds. */
  context(signal: AbortSignal): Promise<ConnectedTvcRuntime>;
  /** Drops `context` if it is still the current one, so the next call verifies again. */
  forget(context: ConnectedTvcRuntime): void;
};

/** Whether the connection's release policy is still in force. Operations check the same window again before they sign. */
function holds(context: ConnectedTvcRuntime): boolean {
  return remainingReleasePolicyMs(context, context.nowMs()) > 0;
}

export function sessionFromConnector(
  connect: (signal: AbortSignal) => Promise<ConnectedTvcRuntime>,
): DecryptionServiceSession {
  let active: ConnectedTvcRuntime | null = null;
  type Flight = { controller: AbortController; promise: Promise<ConnectedTvcRuntime>; users: number };
  let pending: Flight | null = null;

  return {
    async context(signal): Promise<ConnectedTvcRuntime> {
      let flight: Flight | undefined;
      try {
        signal.throwIfAborted();
        if (active && holds(active)) return active;
        active = null;
        if (!pending) {
          const controller = new AbortController();
          const current: Flight = { controller, users: 0, promise: Promise.resolve().then(async () => {
            controller.signal.throwIfAborted();
            const context = await connect(controller.signal);
            // An abandoned connector may ignore cancellation and finish after its replacement.
            controller.signal.throwIfAborted();
            if (pending === current) active = context;
            return context;
          }).finally(() => { if (pending === current) pending = null; }) };
          pending = current;
        }
        flight = pending;
        flight.users += 1;
        return await awaitWithSignal(flight.promise, signal);
      } finally {
        if (flight && --flight.users === 0 && pending === flight) {
          pending = null;
          // One cancelled caller must not cancel another caller's verification.
          flight.controller.abort(signal.reason);
        }
      }
    },

    forget(context): void {
      if (active === context) active = null;
    },
  };
}

export function createDecryptionServiceSession(config: DecryptionServiceConnectionConfig): DecryptionServiceSession {
  // Single-flighted: concurrent first calls share one verification.
  return sessionFromConnector((signal) => connectAndVerifyTvc(config, signal));
}
