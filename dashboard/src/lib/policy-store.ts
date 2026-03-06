import { create } from "zustand";

interface PolicyStore {
  activeOrgId: string;
  policyCommitment: string | null;
  policyStorageKey: string | null;
  setActiveOrgId: (orgId: string) => void;
  setPolicyCommitment: (hash: string | null, orgId?: string) => void;
  setPolicyStorageKey: (key: string | null, orgId?: string) => void;
  policyCommitmentByOrg: Record<string, string>;
  policyStorageKeyByOrg: Record<string, string>;
}

export const usePolicyStore = create<PolicyStore>((set) => ({
  activeOrgId: "default",
  policyCommitment: null,
  policyStorageKey: null,
  policyCommitmentByOrg: {},
  policyStorageKeyByOrg: {},
  setActiveOrgId: (orgId) =>
    set((state) => ({
      activeOrgId: orgId,
      policyCommitment: state.policyCommitmentByOrg[orgId] ?? null,
      policyStorageKey: state.policyStorageKeyByOrg[orgId] ?? null,
    })),
  setPolicyCommitment: (hash, orgId) =>
    set((state) => {
      const targetOrg = orgId ?? state.activeOrgId;
      const nextByOrg = { ...state.policyCommitmentByOrg };
      if (hash) nextByOrg[targetOrg] = hash;
      else delete nextByOrg[targetOrg];
      return {
        policyCommitmentByOrg: nextByOrg,
        policyCommitment: targetOrg === state.activeOrgId ? hash : state.policyCommitment,
      };
    }),
  setPolicyStorageKey: (key, orgId) =>
    set((state) => {
      const targetOrg = orgId ?? state.activeOrgId;
      const nextByOrg = { ...state.policyStorageKeyByOrg };
      if (key) nextByOrg[targetOrg] = key;
      else delete nextByOrg[targetOrg];
      return {
        policyStorageKeyByOrg: nextByOrg,
        policyStorageKey: targetOrg === state.activeOrgId ? key : state.policyStorageKey,
      };
    }),
}));
