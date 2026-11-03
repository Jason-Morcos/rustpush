# Rustpush

Rustpush is a portable library for interplatform communication.
### Activation feature

Activation and its FairPlay certificate inputs are enabled by default. Consumers using `default-features = false` that need device activation must explicitly enable the `activation` feature. Without it, `activate` returns `PushError::DeviceNotFound` before accessing device metadata, the keystore, or the network. The fixture-dependent APS proxy unit test is also excluded without this feature.

### Targeted existing-key reads

`CuttlefishEncItem::decrypt_with_keys` decrypts one explicitly identified item
from caller-supplied recovered shares, without a global keystore or I/O.
`PCSZoneConfig::from_existing_private_zone` constructs a configuration from an
already-fetched private zone and a plaintext, narrowly selected PCS snapshot.
It requires existing authorized signatures for the PCS chain and zone/record
protections, and never syncs, creates or saves a peer, key, zone or record.
Missing material is an error. Existing permissive convenience methods retain
their behavior; they are not substitutes for this read-only path.

Override `OSConfig::get_http_response_limit` to opt in to a per-response byte
limit before CloudKit, escrow and delegate parsing. The default is `None` for
existing clients. A configured limit applies to streamed/decompressed responses
and CloudKit frame sizes/counts. Consumers must also bound decoded records and
session lifetime. These helpers do not implement account enrollment, establish
compatibility with real account material, or remove all existing malformed-input
parser panics. A disposable process boundary remains appropriate for enrollment.
No real account, activation, private certificates or accessory data were used by
the synthetic tests. Default-feature activation builds were not verified.
