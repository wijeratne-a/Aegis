import { create } from "zustand";

interface PolicyStore {
  policyCommitment: string | null;
  setPolicyCommitment: (hash: string | null) => void;
}

export const usePolicyStore = create<PolicyStore>((set) => ({
  policyCommitment: null,
  setPolicyCommitment: (hash) => set({ policyCommitment: hash }),
}));
