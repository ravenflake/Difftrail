export interface BootstrapReadGate {
  begin(): number;
  isCurrent(generation: number): boolean;
  invalidate(): void;
}

/** Prevent an older bootstrap response from replacing a newer local mutation. */
export function createBootstrapReadGate(): BootstrapReadGate {
  let currentGeneration = 0;

  return {
    begin: () => ++currentGeneration,
    isCurrent: (generation) => generation === currentGeneration,
    invalidate: () => {
      currentGeneration += 1;
    },
  };
}
