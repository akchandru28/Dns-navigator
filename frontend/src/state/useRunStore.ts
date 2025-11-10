import { create } from "zustand";
import type { RunResult, RunOptions } from "../types";
import { createRun, getRun } from "../api";

interface RunState {
  current?: RunResult;
  loading: boolean;
  error?: string;
  startRun: (opts: RunOptions) => Promise<void>;
  poll: (id: string) => Promise<void>;
}

export const useRunStore = create<RunState>((set, get) => ({
  loading: false,
  async startRun(opts) {
    set({ loading: true, error: undefined });
    try {
      const { run_id } = await createRun(opts);
      await get().poll(run_id);
    } catch (e: any) {
      set({ loading: false, error: e.message });
    }
  },
  async poll(id) {
    let done = false;
    while (!done) {
      const data = await getRun(id);
      set({ current: data, loading: data.phase !== "Completed" && data.phase !== "Error" });
      done = data.phase === "Completed" || data.phase === "Error";
      if (!done) await new Promise(r => setTimeout(r, 900));
    }
  }
}));
