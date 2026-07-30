import type { ScenarioEventStore } from '../events/event-store.js';

export async function closeScenarioEventStore(eventStore: ScenarioEventStore): Promise<void> {
  eventStore.close();
}
