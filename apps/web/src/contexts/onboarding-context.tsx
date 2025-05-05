import React, { createContext, useContext, useState } from 'react';
import { useOnboardingFlow } from '@/lib/trpc';
import { crypto } from '@/lib/crypto';
import { KeyEnvelope } from '@quantum-auth/crypto-sdk';

// Define the onboarding steps
export enum OnboardingStep {
  WELCOME = 'welcome',
  GENERATING_KEYS = 'generating-keys',
  CREATE_RECOVERY = 'create-recovery',
  SAVE_RECOVERY = 'save-recovery',
  COMPLETE = 'complete',
}

// Define the context state
interface OnboardingContextState {
  currentStep: OnboardingStep;
  keyEnvelope: KeyEnvelope | null;
  recoveryShares: string[];
  recoveryThreshold: number;
  isLoading: boolean;
  error: Error | null;
  // Actions
  startOnboarding: () => Promise<void>;
  generateKeys: (password?: string) => Promise<void>;
  createRecoveryShares: (threshold: number, numShares: number) => Promise<void>;
  completeOnboarding: () => void;
  goToStep: (step: OnboardingStep) => void;
}

// Create the context
const OnboardingContext = createContext<OnboardingContextState | undefined>(undefined);

// Provider component
export function OnboardingProvider({ children }: { children: React.ReactNode }) {
  // State
  const [currentStep, setCurrentStep] = useState<OnboardingStep>(OnboardingStep.WELCOME);
  const [keyEnvelope, setKeyEnvelope] = useState<KeyEnvelope | null>(null);
  const [recoveryShares, setRecoveryShares] = useState<string[]>([]);
  const [recoveryThreshold, setRecoveryThreshold] = useState<number>(3);
  const [error, setError] = useState<Error | null>(null);

  // Use the onboarding flow hooks
  const { 
    signup, 
    generateAndStoreKey, 
    createRecoveryShares: createShares,
    isLoading 
  } = useOnboardingFlow();

  // Start the onboarding process
  const startOnboarding = async () => {
    try {
      setError(null);
      // Sign up the user
      const result = await signup();
      
      // If the user is not new, try to fetch their key
      if (!result.is_new) {
        // In a real app, we would fetch the user's key here
        // For now, we'll just proceed to the next step
      }
      
      // Move to the next step
      setCurrentStep(OnboardingStep.GENERATING_KEYS);
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Failed to start onboarding'));
    }
  };

  // Generate keys for the user
  const generateKeys = async (password?: string) => {
    try {
      setError(null);
      
      // Generate a new key pair
      const envelope = await crypto.generateKeyPair(password);
      
      // Store the key in the database
      await generateAndStoreKey({
        algorithm: envelope.algorithm,
        public_key: envelope.public_key,
        encrypted_private_key: envelope.encrypted_private_key,
      });
      
      // Save the key envelope in state
      setKeyEnvelope(envelope);
      
      // Move to the next step
      setCurrentStep(OnboardingStep.CREATE_RECOVERY);
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Failed to generate keys'));
    }
  };

  // Create recovery shares for the user
  const createRecoveryShares = async (threshold: number, numShares: number) => {
    try {
      setError(null);
      
      // Create recovery shares
      const result = await createShares({
        threshold,
        num_shares: numShares,
      });
      
      // Save the shares and threshold in state
      setRecoveryShares(result.shares);
      setRecoveryThreshold(result.threshold);
      
      // Move to the next step
      setCurrentStep(OnboardingStep.SAVE_RECOVERY);
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Failed to create recovery shares'));
    }
  };

  // Complete the onboarding process
  const completeOnboarding = () => {
    setCurrentStep(OnboardingStep.COMPLETE);
  };

  // Go to a specific step
  const goToStep = (step: OnboardingStep) => {
    setCurrentStep(step);
  };

  // Context value
  const value: OnboardingContextState = {
    currentStep,
    keyEnvelope,
    recoveryShares,
    recoveryThreshold,
    isLoading,
    error,
    startOnboarding,
    generateKeys,
    createRecoveryShares,
    completeOnboarding,
    goToStep,
  };

  return (
    <OnboardingContext.Provider value={value}>
      {children}
    </OnboardingContext.Provider>
  );
}

// Hook for using the onboarding context
export function useOnboarding() {
  const context = useContext(OnboardingContext);
  if (context === undefined) {
    throw new Error('useOnboarding must be used within an OnboardingProvider');
  }
  return context;
}
