import React, { createContext, useContext, useState } from "react";
import { useRecoveryFlow } from "@/lib/trpc";
import { KeyEnvelope } from "@quantum-auth/crypto-sdk";

// Define the recovery steps
export enum RecoveryStep {
  ENTER_USER_ID = "enter-user-id",
  ENTER_SHARES = "enter-shares",
  VERIFY_SHARES = "verify-shares",
  RECOVER_KEY = "recover-key",
  COMPLETE = "complete",
}

// Define the context state
interface RecoveryContextState {
  currentStep: RecoveryStep;
  userId: string;
  shares: string[];
  recoveredKey: KeyEnvelope | null;
  isLoading: boolean;
  error: Error | null;
  // Actions
  setUserId: (userId: string) => void;
  addShare: (share: string) => void;
  removeShare: (index: number) => void;
  verifyShares: () => Promise<boolean>;
  recoverKey: () => Promise<void>;
  completeRecovery: () => void;
  goToStep: (step: RecoveryStep) => void;
  reset: () => void;
}

// Create the context
const RecoveryContext = createContext<RecoveryContextState | undefined>(
  undefined,
);

// Provider component
export function RecoveryProvider({ children }: { children: React.ReactNode }) {
  // State
  const [currentStep, setCurrentStep] = useState<RecoveryStep>(
    RecoveryStep.ENTER_USER_ID,
  );
  const [userId, setUserId] = useState<string>("");
  const [shares, setShares] = useState<string[]>([]);
  const [recoveredKey, setRecoveredKey] = useState<KeyEnvelope | null>(null);
  const [error, setError] = useState<Error | null>(null);

  // Use the recovery flow hooks
  const {
    verifyShares: verifySharesApi,
    recoverKey: recoverKeyApi,
    isLoading,
  } = useRecoveryFlow();

  // Add a share
  const addShare = (share: string) => {
    if (!shares.includes(share)) {
      setShares([...shares, share]);
    }
  };

  // Remove a share
  const removeShare = (index: number) => {
    setShares(shares.filter((_, i) => i !== index));
  };

  // Verify the shares
  const verifyShares = async () => {
    try {
      setError(null);

      // Verify the shares
      const valid = await verifySharesApi(shares);

      if (valid) {
        // Move to the next step
        setCurrentStep(RecoveryStep.RECOVER_KEY);
      }

      return valid;
    } catch (err) {
      setError(
        err instanceof Error ? err : new Error("Failed to verify shares"),
      );
      return false;
    }
  };

  // Recover the key
  const recoverKey = async () => {
    try {
      setError(null);

      // Recover the key
      const key = await recoverKeyApi(shares, userId);

      // Save the recovered key
      setRecoveredKey({
        algorithm: key.algorithm,
        public_key: key.public_key,
        encrypted_private_key: key.encrypted_private_key,
        created_at: new Date(),
      });

      // Move to the next step
      setCurrentStep(RecoveryStep.COMPLETE);
    } catch (err) {
      setError(err instanceof Error ? err : new Error("Failed to recover key"));
    }
  };

  // Complete the recovery process
  const completeRecovery = () => {
    setCurrentStep(RecoveryStep.COMPLETE);
  };

  // Go to a specific step
  const goToStep = (step: RecoveryStep) => {
    setCurrentStep(step);
  };

  // Reset the recovery process
  const reset = () => {
    setCurrentStep(RecoveryStep.ENTER_USER_ID);
    setUserId("");
    setShares([]);
    setRecoveredKey(null);
    setError(null);
  };

  // Context value
  const value: RecoveryContextState = {
    currentStep,
    userId,
    shares,
    recoveredKey,
    isLoading,
    error,
    setUserId,
    addShare,
    removeShare,
    verifyShares,
    recoverKey,
    completeRecovery,
    goToStep,
    reset,
  };

  return (
    <RecoveryContext.Provider value={value}>
      {children}
    </RecoveryContext.Provider>
  );
}

// Hook for using the recovery context
export function useRecovery() {
  const context = useContext(RecoveryContext);
  if (context === undefined) {
    throw new Error("useRecovery must be used within a RecoveryProvider");
  }
  return context;
}
