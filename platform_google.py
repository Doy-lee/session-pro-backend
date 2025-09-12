from google.cloud import pubsub_v1

def callback(message: pubsub_v1.subscriber.message.Message):
    print(message.data)
    message.ack()

with pubsub_v1.SubscriberClient() as sub_client:
    sub_path: str                                              = sub_client.subscription_path(project='loki-5a81e', subscription='session-pro-sub')
    future:   pubsub_v1.subscriber.futures.StreamingPullFuture = sub_client.subscribe(subscription=sub_path, callback=callback)
    try:
        future.result()
    except KeyboardInterrupt:
        future.cancel()  # Trigger the shutdown.
        future.result()  # Block until the shutdown is complete.
