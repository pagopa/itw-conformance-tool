// vitest.setup.ts
import process from 'node:process';

// Aumenta il limite di listener per evitare il falso positivo
process.setMaxListeners(30);
