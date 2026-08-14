# Feature Spec: feat: sync.Pool buffer allocation for TCP streams

## Summary
Eliminates heap allocation per connection by recycling 32KB copy buffers.
