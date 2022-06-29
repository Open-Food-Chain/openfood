import math
import time

KOMODO_ENDOFERA = 7777777
LOCKTIME_THRESHOLD = 500000000

def calcInterest(locktime, value, height):
    if value < 10 * 100000000:
        return 0
    else:
        timestampDiff = int(time.time()) - locktime - 777
        hoursPassed = math.floor(timestampDiff / 3600)
        minutesPassed = math.floor((timestampDiff - (hoursPassed * 3600)) / 60)
        secondsPassed = timestampDiff - (hoursPassed * 3600) - (minutesPassed * 60)
        timestampDiffMinutes = timestampDiff / 60
        interest = 0

        if height < KOMODO_ENDOFERA and locktime >= LOCKTIME_THRESHOLD:
            if timestampDiffMinutes >= 60:
                if height >= 1000000 and timestampDiffMinutes > 31 * 24 * 60:
                    timestampDiffMinutes = 31 * 24 * 60
                else:
                    if timestampDiffMinutes > 365 * 24 * 60:
                        timestampDiffMinutes = 365 * 24 * 60

            timestampDiffMinutes -= 59
            interest = int(math.floor(value / 10512000) * timestampDiffMinutes)

        if interest < 0:
            interest = 0

        return interest
