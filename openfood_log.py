import os
import sentry_sdk

SENTRY_SDK_DSN = str(os.environ['SENTRY_SDK_DSN'])

sentry_sdk.init(
    dsn=SENTRY_SDK_DSN,

    # Set traces_sample_rate to 1.0 to capture 100%
    # of transactions for performance monitoring.
    # We recommend adjusting this value in production.
    traces_sample_rate=1.0
)
