export interface MaximizeReadGate {
  begin(): number;
  isCurrent(generation: number): boolean;
  invalidate(): void;
}

export function createMaximizeReadGate(): MaximizeReadGate {
  let currentGeneration = 0;

  return {
    begin: () => ++currentGeneration,
    isCurrent: (generation) => generation === currentGeneration,
    invalidate: () => {
      currentGeneration += 1;
    },
  };
}
