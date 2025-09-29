import schedule
import time

from traefiktounifi import app

traefikToUnifi = app.TraefikToUnifi()
traefikToUnifi.sync()
schedule.every(1).minutes.do(traefikToUnifi.sync)

# Keep the script running indefinitely
while True:
    schedule.run_pending()
    time.sleep(1)
