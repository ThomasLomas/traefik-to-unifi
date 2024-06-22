import schedule
import time
import subprocess

def call_app():
  subprocess.run(["python3", "app.py"])

call_app()

# Schedule the call to app.py every 5 minutes
schedule.every(5).minutes.do(call_app)

# Keep the script running indefinitely
while True:
  schedule.run_pending()
  time.sleep(1)
