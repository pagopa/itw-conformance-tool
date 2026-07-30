import type { ProtocolObservedScenarioDefinition, ScenarioStimulus } from '../scenarios/definitions.js';

export interface ScenarioPromptModel {
  id: string;
  title: string;
  goal: string;
  expectedBehavior: string;
  prerequisites: string[];
  steps: string[];
  stimulus: ScenarioStimulus;
}

export function createScenarioPromptModel(
  definition: ProtocolObservedScenarioDefinition,
  stimulus: ScenarioStimulus
): ScenarioPromptModel {
  return {
    id: definition.id,
    title: definition.title,
    goal: definition.instructions.goal,
    expectedBehavior: definition.instructions.expectedBehavior,
    prerequisites: definition.instructions.prerequisites ?? [],
    steps: definition.instructions.steps ?? [],
    stimulus
  };
}
