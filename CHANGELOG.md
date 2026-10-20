# Changelog

## [0.1.0-beta.1](https://github.com/tenbri/tenbri/compare/v0.1.0-alpha.2...v0.1.0-beta.1) (2026-10-20)


### Features

* **adapters:** Claude Agent SDK adapter for Python and TypeScript ([#42](https://github.com/tenbri/tenbri/issues/42)) ([af23ddd](https://github.com/tenbri/tenbri/commit/af23dddb97351cbfec2bc1d9d3e763f58b1a7488))
* **adapters:** LangGraph and LangChain adapter for Python and TypeScript ([#44](https://github.com/tenbri/tenbri/issues/44)) ([8598018](https://github.com/tenbri/tenbri/commit/8598018a353672893bde0aaae8b60e13099d501e))
* **adapters:** OpenAI Agents SDK adapter for Python and TypeScript ([#43](https://github.com/tenbri/tenbri/issues/43)) ([d183079](https://github.com/tenbri/tenbri/commit/d1830790365633484d5c592b7dc45d210feb7101))
* **crypt:** encrypted body blobs, keyed digests and erasure ([#36](https://github.com/tenbri/tenbri/issues/36)) ([9ae88c9](https://github.com/tenbri/tenbri/commit/9ae88c9de709279c2b6858804748966e1e2090d4))
* index and query for 0.1.0-beta.1 ([#40](https://github.com/tenbri/tenbri/issues/40)) ([fc90a69](https://github.com/tenbri/tenbri/commit/fc90a69dadfe28ae1c69d5d68622c4c63695a900))
* **index:** erasure reaches the query index ([#41](https://github.com/tenbri/tenbri/issues/41)) ([5c2545f](https://github.com/tenbri/tenbri/commit/5c2545f1a82675b12651d155d9b60774cd50d22a))
* Python, Node and WASM bindings for 0.1.0-beta.1 ([#39](https://github.com/tenbri/tenbri/issues/39)) ([975023a](https://github.com/tenbri/tenbri/commit/975023a204befcd2768dc2845aaeb9706aa3379a))
* receipts and RFC 3161 timestamps of checkpoints ([#38](https://github.com/tenbri/tenbri/issues/38)) ([98a39bd](https://github.com/tenbri/tenbri/commit/98a39bd0f2b8573828114ee8681a193e65da2d9a))
* test kit and OpenTelemetry correlation for 0.1.0-beta.1 ([#37](https://github.com/tenbri/tenbri/issues/37)) ([f866919](https://github.com/tenbri/tenbri/commit/f866919b6c3b759e734d4b22281f20c36fe29bc5))


### Documentation

* add fleet and liveness to the README roadmap ([#33](https://github.com/tenbri/tenbri/issues/33)) ([2bf1755](https://github.com/tenbri/tenbri/commit/2bf17552ca84a15f258b507434e59f2a90dbc5f3))


### CI

* publish the framework adapters, and start 0.1.0-beta.1 ([#45](https://github.com/tenbri/tenbri/issues/45)) ([d2b0ed1](https://github.com/tenbri/tenbri/commit/d2b0ed15d4aa9acadf619264dbeee32ce793ac6d))

## [0.1.0-alpha.2](https://github.com/tenbri/tenbri/compare/v0.1.0-alpha.1...v0.1.0-alpha.2) (2026-10-20)


### Features

* connect checkpoints, the object-store writer and tenbrid for 0.1.0-alpha.2 ([#27](https://github.com/tenbri/tenbri/issues/27)) ([22db72c](https://github.com/tenbri/tenbri/commit/22db72c1d8beec9b41ae00363dedf0b122c775d4))
* Merkle checkpoints for 0.1.0-alpha.2 ([#19](https://github.com/tenbri/tenbri/issues/19)) ([dd34607](https://github.com/tenbri/tenbri/commit/dd34607d457271ff2fa3fdc4bcc5a9933f513eb7))
* object storage, group commit and backpressure for 0.1.0-alpha.2 ([#20](https://github.com/tenbri/tenbri/issues/20)) ([baaf22b](https://github.com/tenbri/tenbri/commit/baaf22b012dae4161386c0ef74b2d4dfccd1f0f7))
* tenbrid REST and gRPC API and action schemas for 0.1.0-alpha.2 ([#21](https://github.com/tenbri/tenbri/issues/21)) ([e8a1aae](https://github.com/tenbri/tenbri/commit/e8a1aae08a2312598b90b20594ac1bffad00cbf3))


### Fixes

* **merkle:** rename the vectors example so Windows can link it ([#26](https://github.com/tenbri/tenbri/issues/26)) ([8414f75](https://github.com/tenbri/tenbri/commit/8414f7589f543004156b3192755d5eb30bff2c8e))
* **server:** define every schema the OpenAPI contract refers to ([#24](https://github.com/tenbri/tenbri/issues/24)) ([4002984](https://github.com/tenbri/tenbri/commit/400298451f7999f9e51386d0f3342c1757de5605))


### Documentation

* call Tenbri a record, and link the regulations it helps with ([#28](https://github.com/tenbri/tenbri/issues/28)) ([734c85a](https://github.com/tenbri/tenbri/commit/734c85a11dda712fc4b930663f6911f2444fe2e1))
* keep AWS S3 in progress until it is tested on AWS ([#30](https://github.com/tenbri/tenbri/issues/30)) ([11a329b](https://github.com/tenbri/tenbri/commit/11a329b4a2adb0833f9faac7cd11bee87aea933c))
* mark object storage, checkpoint and tenbrid done in the README ([#29](https://github.com/tenbri/tenbri/issues/29)) ([83985a7](https://github.com/tenbri/tenbri/commit/83985a741976a8fb2afa2c5ac6d58ad79fd5ace7))
* show feature status in the README ([#17](https://github.com/tenbri/tenbri/issues/17)) ([972519a](https://github.com/tenbri/tenbri/commit/972519a8fad69e80618ae29f2fc1b7673c40b18c))
* update the pangolin mascot ([#23](https://github.com/tenbri/tenbri/issues/23)) ([10f9977](https://github.com/tenbri/tenbri/commit/10f9977d2f15e8b93394d723e58feba6a3c04f5f))

## 0.1.0-alpha.1 (2026-10-19)


### Features

* format v1, core, keys, local writer and CLI for 0.1.0-alpha.1 ([#12](https://github.com/tenbri/tenbri/issues/12)) ([cc8228e](https://github.com/tenbri/tenbri/commit/cc8228ee63f7836194daaf3f0895174e0d28798a))


### Documentation

* add the pangolin mascot to the README ([#8](https://github.com/tenbri/tenbri/issues/8)) ([1cdce3f](https://github.com/tenbri/tenbri/commit/1cdce3f7962a7fc5bd8bb2c9375df1fa19d2f490))
* explain the problem and the difference from logs ([#11](https://github.com/tenbri/tenbri/issues/11)) ([bf5e26d](https://github.com/tenbri/tenbri/commit/bf5e26d15067ee41da385e50197fe373dac03d2f))
