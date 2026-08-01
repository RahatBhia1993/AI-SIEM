class EventOrdering:
    """
    Maintains ordered event streams per entity.

    Each entity (currently IP address) has its own
    event buffer. When enough events arrive, they are
    sorted chronologically and released.

    Remaining events can be released using flush().
    """

    def __init__(self, buffer_size=10):

        # Event buffer for every entity
        self.buffers = {}

        # Number of events before automatic release
        self.buffer_size = buffer_size

    def process_event(self, event):

        # -----------------------------
        # Identify entity
        # -----------------------------

        entity = event.get("ip", "unknown")

        # -----------------------------
        # Create entity buffer
        # -----------------------------

        if entity not in self.buffers:
            self.buffers[entity] = []

        # -----------------------------
        # Store event
        # -----------------------------

        self.buffers[entity].append(event)

        # -----------------------------
        # Release ordered events
        # -----------------------------

        if len(self.buffers[entity]) >= self.buffer_size:

            self.buffers[entity].sort(
                key=lambda e: e["timestamp"]
            )

            ordered_events = self.buffers[entity].copy()

            self.buffers[entity] = []

            return ordered_events

        return None

    def flush(self):
        """
        Releases all remaining buffered events.

        Called when the pipeline finishes processing.
        """

        remaining = {}

        for entity, events in self.buffers.items():

            events.sort(
                key=lambda e: e["timestamp"]
            )

            remaining[entity] = events

        self.buffers = {}

        return remaining

    def reset(self):
        """
        Clears all buffers.

        Useful for testing.
        """

        self.buffers = {}