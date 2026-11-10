// Hooks: import from client components only ("@mws-dashboard/ui/machine").
// Small finite state machines for the console's asynchronous UI: a component
// is always in exactly one named state, events move it along declared edges
// only, and timed edges (`after`) leave a state on their own. The state is
// exposed as `data-state` so styles can animate each phase.
import { useCallback, useEffect, useReducer, useRef } from "react";

export interface Event {
  type: string;
}

type Target<S extends string, E extends Event> = S | ((event: E) => S | undefined);

export interface StateNode<S extends string, E extends Event> {
  /** Event type → next state (or a function choosing it; undefined ignores the event). */
  on?: { [K in E["type"]]?: Target<S, Extract<E, { type: K }>> };
  /** Leave this state on its own after `ms`. */
  after?: { ms: number; to: S };
}

export interface Machine<S extends string, E extends Event> {
  initial: S;
  states: Record<S, StateNode<S, E>>;
}

export function machine<S extends string, E extends Event>(config: Machine<S, E>): Machine<S, E> {
  return config;
}

/** The state `event` leads to from `state`; the same state when no edge matches. */
export function transition<S extends string, E extends Event>(m: Machine<S, E>, state: S, event: E): S {
  const edge = m.states[state].on?.[event.type as E["type"]] as Target<S, E> | undefined;
  if (edge === undefined) return state;
  const next = typeof edge === "function" ? edge(event) : edge;
  return next ?? state;
}

type Internal<S> = { state: S; entered: number };

/** Run a machine in a component: `[state, send]`. `onEnter` runs on every
 * entry into a state (including re-entry through a self edge). */
export function useMachine<S extends string, E extends Event>(m: Machine<S, E>, onEnter?: (state: S) => void): [S, (event: E) => void] {
  const [current, dispatch] = useReducer(
    (cur: Internal<S>, action: E | { type: "@after"; from: S; entered: number; to: S }): Internal<S> => {
      if (action.type === "@after") {
        const a = action as { from: S; entered: number; to: S };
        // Only the timer of the entry that is still current may fire.
        return cur.state === a.from && cur.entered === a.entered ? { state: a.to, entered: cur.entered + 1 } : cur;
      }
      const edge = m.states[cur.state].on?.[action.type as E["type"]] as Target<S, E> | undefined;
      if (edge === undefined) return cur;
      const next = typeof edge === "function" ? edge(action as E) : edge;
      return next === undefined ? cur : { state: next, entered: cur.entered + 1 };
    },
    { state: m.initial, entered: 0 },
  );
  const enter = useRef(onEnter);
  enter.current = onEnter;
  useEffect(() => {
    enter.current?.(current.state);
    const after = m.states[current.state].after;
    if (!after) return;
    const timer = setTimeout(() => dispatch({ type: "@after", from: current.state, entered: current.entered, to: after.to }), after.ms);
    return () => clearTimeout(timer);
  }, [m, current]);
  const send = useCallback((event: E) => dispatch(event), []);
  return [current.state, send];
}
