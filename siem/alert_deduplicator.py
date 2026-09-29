class AlertDeduplicator:
    
    def __init__(self, window_seconds=300):
         self.alerts={}
         self.window_seconds=window_seconds
  
    def find_existing_alert(self, deduplication_key, current_time):

         if deduplication_key not in self.alerts:
            return None

         existing_alert = self.alerts[deduplication_key]

         last_seen = existing_alert["last_seen"]

         elapsed_time = current_time - last_seen

         elapsed_seconds = elapsed_time.total_seconds()

         if elapsed_seconds <= self.window_seconds:
             existing_alert["last_seen"]= current_time
             return existing_alert
        
         return None
        

    def add_alert(self, alert):
        key = alert["deduplication_key"]
        self.alerts[key] = alert

