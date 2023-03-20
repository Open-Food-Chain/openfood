import os
import sentry_sdk
from sentry_sdk import set_level

SENTRY_SDK_DSN = os.getenv('SENTRY_DSN')
#ENVIRONMENT = str(os.environ['ENVIRONMENT'])
#LOGGER_LEVEL = str(os.environ['LOGGER_LEVEL'])

#SENTRY_SDK_DSN = "https://198cbc30e54d4fdf85eb5e94fe670450@o4503918670249984.ingest.sentry.io/4503918673985537"
#SENTRY_SDK_DSN = "https://f275ccd8f45f42c9af7337c626a6d495@o237067.ingest.sentry.io/4503917202046976"
#SENTRY_SDK_DSN = ""
#ENVIRONMENT="production"
#LOGGER_LEVEL="info"

if SENTRY_SDK_DSN:
    sentry_sdk.init(
        dsn=SENTRY_SDK_DSN,
        traces_sample_rate=1.0,
        environment=str(os.environ['ENVIRONMENT'])
    )

    logger_level = LOGGER_LEVEL if LOGGER_LEVEL else "debug"
    
    set_level(logger_level)
