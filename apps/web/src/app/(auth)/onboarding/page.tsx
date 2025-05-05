"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { Fingerprint, Download, Info, Loader2 } from "lucide-react"

import { Card, CardContent, CardFooter, CardHeader } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Alert, AlertDescription } from "@/components/ui/alert"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { ThemeToggle } from "@/components/theme-toggle"

export default function OnboardingPage() {
  const router = useRouter()
  const [currentStep, setCurrentStep] = useState(1)
  const [isGeneratingKeys, setIsGeneratingKeys] = useState(false)
  const [showRecoveryModal, setShowRecoveryModal] = useState(false)
  const [recoveryKey, setRecoveryKey] = useState("")
  const [error, setError] = useState("")
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [authMethod, setAuthMethod] = useState("passkey")

  const handleContinue = async () => {
    setError("")

    if (authMethod === "email" && (!email || !password)) {
      setError("Please fill in all required fields")
      return
    }

    // Simulate account creation
    setCurrentStep(2)
    await generateEncryptionKeys()
  }

  const generateEncryptionKeys = async () => {
    setIsGeneratingKeys(true)

    try {
      // Simulate key generation (in a real app, this would use WebCrypto API)
      await new Promise((resolve) => setTimeout(resolve, 2000))

      // Generate a mock recovery key
      const mockRecoveryKey = Array.from({ length: 12 }, () => Math.random().toString(36).substring(2, 7)).join("-")

      setRecoveryKey(mockRecoveryKey)
      setCurrentStep(3)
      setShowRecoveryModal(true)
      setIsGeneratingKeys(false)
    } catch (err) {
      setError("Failed to generate encryption keys. Please try again.")
      setIsGeneratingKeys(false)
    }
  }

  const handleDownloadRecoveryKey = () => {
    const element = document.createElement("a")
    const file = new Blob([recoveryKey], { type: "text/plain" })
    element.href = URL.createObjectURL(file)
    element.download = "proton-recovery-key.txt"
    document.body.appendChild(element)
    element.click()
    document.body.removeChild(element)
  }

  const completeOnboarding = () => {
    setShowRecoveryModal(false)
    setCurrentStep(4)

    // Redirect to inbox after a brief delay
    setTimeout(() => {
      router.push("/")
    }, 1500)
  }

  const handlePasskeySignup = async () => {
    try {
      // In a real implementation, this would use the WebAuthn API
      setCurrentStep(2)
      await generateEncryptionKeys()
    } catch (err) {
      setError("Passkey registration failed. Please try again or use email signup.")
    }
  }

  return (
    <div className="flex min-h-screen flex-col bg-neutral-50 dark:bg-neutral-950">
      <header className="container flex items-center justify-between p-4">
        <Logo />
        <ThemeToggle />
      </header>

      <main className="flex flex-1 items-center justify-center p-6">
        <Card className="w-full max-w-md rounded-2xl shadow-lg transition-transform hover:scale-[1.01] backdrop-blur-sm bg-white/90 dark:bg-neutral-900/90">
          <CardHeader>
            <div className="mb-2">
              <Steps currentStep={currentStep} />
            </div>
            <h1 className="text-2xl font-bold text-center text-neutral-900 dark:text-neutral-50">
              {currentStep === 1 && "Create your Proton account"}
              {currentStep === 2 && "Generating encryption keys"}
              {currentStep === 3 && "Save your recovery key"}
              {currentStep === 4 && "Setup complete!"}
            </h1>
            <p className="text-center text-neutral-500 dark:text-neutral-400">
              {currentStep === 1 && "Choose how you want to secure your account"}
              {currentStep === 2 && "We're generating encryption keys for your account"}
              {currentStep === 3 && "Store this key in a safe place to recover your account if needed"}
              {currentStep === 4 && "You're all set to start using Proton services"}
            </p>
          </CardHeader>

          <CardContent>
            {currentStep === 1 && (
              <Tabs defaultValue={authMethod} onValueChange={(value) => setAuthMethod(value)} className="w-full">
                <TabsList className="grid w-full grid-cols-2 mb-6">
                  <TabsTrigger value="passkey">Passkey</TabsTrigger>
                  <TabsTrigger value="email">Email & Password</TabsTrigger>
                </TabsList>

                <TabsContent value="passkey" className="space-y-4">
                  <div className="flex flex-col items-center justify-center space-y-4 py-6">
                    <div className="h-16 w-16 rounded-full bg-indigo-100 dark:bg-indigo-900/30 flex items-center justify-center">
                      <Fingerprint className="h-8 w-8 text-indigo-600 dark:text-indigo-400" />
                    </div>
                    <div className="text-center space-y-2">
                      <h3 className="font-medium">Use a passkey</h3>
                      <p className="text-sm text-neutral-500 dark:text-neutral-400">
                        Sign in with your fingerprint, face, or device PIN
                      </p>
                    </div>
                    <Button onClick={handlePasskeySignup} className="w-full">
                      Continue with passkey
                    </Button>
                  </div>
                </TabsContent>

                <TabsContent value="email" className="space-y-4">
                  {error && (
                    <Alert variant="destructive">
                      <AlertDescription>{error}</AlertDescription>
                    </Alert>
                  )}
                  <div className="space-y-2">
                    <label htmlFor="email" className="text-sm font-medium">
                      Email
                    </label>
                    <Input
                      id="email"
                      type="email"
                      placeholder="you@example.com"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <label htmlFor="password" className="text-sm font-medium">
                        Password
                      </label>
                      <TooltipProvider>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button variant="ghost" size="icon" className="h-5 w-5">
                              <Info className="h-3.5 w-3.5" />
                              <span className="sr-only">Password requirements</span>
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>
                            <p>Password must be at least 8 characters</p>
                          </TooltipContent>
                        </Tooltip>
                      </TooltipProvider>
                    </div>
                    <Input
                      id="password"
                      type="password"
                      placeholder="••••••••"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                    />
                  </div>
                </TabsContent>
              </Tabs>
            )}

            {currentStep === 2 && (
              <div className="flex flex-col items-center justify-center py-8 space-y-4">
                <div className="relative h-16 w-16">
                  <div className="absolute inset-0 flex items-center justify-center">
                    <div className="h-10 w-10 rounded-full bg-indigo-100 dark:bg-indigo-900/30 flex items-center justify-center">
                      <div className="h-5 w-5 rounded-full bg-indigo-600 dark:bg-indigo-400" />
                    </div>
                  </div>
                  <svg
                    className="animate-spin h-16 w-16 text-indigo-600/20 dark:text-indigo-400/20"
                    viewBox="0 0 100 100"
                    fill="none"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <circle
                      className="opacity-25"
                      cx="50"
                      cy="50"
                      r="45"
                      stroke="currentColor"
                      strokeWidth="10"
                    />
                    <path
                      className="opacity-75"
                      d="M50 10 A40 40 0 0 1 90 50"
                      stroke="currentColor"
                      strokeWidth="10"
                      strokeLinecap="round"
                    />
                  </svg>
                </div>
                <p className="text-center text-sm text-neutral-500 dark:text-neutral-400">
                  This may take a few moments. We're generating encryption keys to secure your data.
                </p>
              </div>
            )}

            {currentStep === 4 && (
              <div className="flex flex-col items-center justify-center py-8 space-y-4">
                <div className="h-16 w-16 rounded-full bg-green-100 dark:bg-green-900/30 flex items-center justify-center">
                  <svg
                    className="h-8 w-8 text-green-600 dark:text-green-400"
                    fill="none"
                    height="24"
                    stroke="currentColor"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    viewBox="0 0 24 24"
                    width="24"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <path d="M20 6 9 17l-5-5" />
                  </svg>
                </div>
                <h3 className="text-xl font-medium">Your account is ready!</h3>
                <p className="text-center text-neutral-600 dark:text-neutral-300">
                  You're all set to start using Proton services with end-to-end encryption
                </p>
              </div>
            )}
          </CardContent>

          <CardFooter>
            {currentStep === 1 && authMethod === "email" && (
              <Button className="w-full" onClick={handleContinue}>
                Continue
              </Button>
            )}
          </CardFooter>
        </Card>
      </main>

      <Dialog open={showRecoveryModal} onOpenChange={setShowRecoveryModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Save your recovery key</DialogTitle>
            <DialogDescription>
              This key is the only way to recover your account if you forget your password or lose your passkey.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <Alert>
              <AlertDescription className="text-amber-600 dark:text-amber-400 font-medium">
                Store this key in a secure location. It will only be shown once.
              </AlertDescription>
            </Alert>

            <Textarea readOnly value={recoveryKey} className="font-mono text-center" rows={3} />

            <Button variant="outline" className="w-full" onClick={handleDownloadRecoveryKey}>
              <Download className="mr-2 h-4 w-4" />
              Download as .txt file
            </Button>
          </div>

          <DialogFooter>
            <Button onClick={completeOnboarding}>I've saved my recovery key</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

function Steps({ currentStep }: { currentStep: number }) {
  return (
    <div className="flex items-center justify-center space-x-2">
      {[1, 2, 3, 4].map((step) => (
        <div key={step} className="flex items-center">
          <div
            className={`h-2.5 w-2.5 rounded-full ${
              step === currentStep
                ? "bg-indigo-600 ring-2 ring-indigo-600/30 dark:bg-indigo-500 dark:ring-indigo-500/30"
                : step < currentStep
                  ? "bg-indigo-600 dark:bg-indigo-500"
                  : "bg-neutral-200 dark:bg-neutral-700"
            }`}
          />
          {step < 4 && (
            <div
              className={`h-0.5 w-6 ${
                step < currentStep ? "bg-indigo-600 dark:bg-indigo-500" : "bg-neutral-200 dark:bg-neutral-700"
              }`}
            />
          )}
        </div>
      ))}
    </div>
  )
}

function Logo() {
  return (
    <div className="flex items-center space-x-2">
      <div className="h-8 w-8 rounded-full bg-indigo-600 flex items-center justify-center">
        <span className="text-white font-bold">P</span>
      </div>
      <span className="font-bold text-lg">Proton-Next</span>
    </div>
  )
}
