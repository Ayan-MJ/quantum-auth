declare module 'crystals-kyber' {
  /**
   * Generates a Kyber512 key pair
   * @returns An array where [0] is the public key and [1] is the secret key
   */
  export function KeyGen512(): [Uint8Array, Uint8Array];

  /**
   * Encapsulates a shared secret using a Kyber512 public key
   * @param pk The public key to encapsulate with
   * @returns An array where [0] is the ciphertext and [1] is the shared secret
   */
  export function Encrypt512(pk: Uint8Array): [Uint8Array, Uint8Array];

  /**
   * Decapsulates a shared secret using a Kyber512 secret key
   * @param c The ciphertext to decapsulate
   * @param sk The secret key to use for decapsulation
   * @returns The shared secret
   */
  export function Decrypt512(c: Uint8Array, sk: Uint8Array): Uint8Array;

  /**
   * Generates a Kyber768 key pair
   * @returns An array where [0] is the public key and [1] is the secret key
   */
  export function KeyGen768(): [Uint8Array, Uint8Array];

  /**
   * Encapsulates a shared secret using a Kyber768 public key
   * @param pk The public key to encapsulate with
   * @returns An array where [0] is the ciphertext and [1] is the shared secret
   */
  export function Encrypt768(pk: Uint8Array): [Uint8Array, Uint8Array];

  /**
   * Decapsulates a shared secret using a Kyber768 secret key
   * @param c The ciphertext to decapsulate
   * @param sk The secret key to use for decapsulation
   * @returns The shared secret
   */
  export function Decrypt768(c: Uint8Array, sk: Uint8Array): Uint8Array;

  /**
   * Generates a Kyber1024 key pair
   * @returns An array where [0] is the public key and [1] is the secret key
   */
  export function KeyGen1024(): [Uint8Array, Uint8Array];

  /**
   * Encapsulates a shared secret using a Kyber1024 public key
   * @param pk The public key to encapsulate with
   * @returns An array where [0] is the ciphertext and [1] is the shared secret
   */
  export function Encrypt1024(pk: Uint8Array): [Uint8Array, Uint8Array];

  /**
   * Decapsulates a shared secret using a Kyber1024 secret key
   * @param c The ciphertext to decapsulate
   * @param sk The secret key to use for decapsulation
   * @returns The shared secret
   */
  export function Decrypt1024(c: Uint8Array, sk: Uint8Array): Uint8Array;

  /**
   * Tests Kyber512 implementation
   */
  export function Test512(): void;

  /**
   * Tests Kyber768 implementation
   */
  export function Test768(): void;

  /**
   * Tests Kyber1024 implementation
   */
  export function Test1024(): void;
}
