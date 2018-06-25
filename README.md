# PARSEC - Protocol for Asynchronous, Reliable, Secure and Efficient Consensus

|Crate|Documentation|Linux/OS X|Windows|Issues|
|:---:|:-----------:|:--------:|:-----:|:----:|
|[![](http://meritbadge.herokuapp.com/parsec)](https://crates.io/crates/parsec)|[![Documentation](https://docs.rs/parsec/badge.svg)](https://docs.rs/parsec)|[![Build Status](https://travis-ci.org/maidsafe/parsec.svg?branch=master)](https://travis-ci.org/maidsafe/parsec)|[![Build status](https://ci.appveyor.com/api/projects/status/1wmc7pj8fx77lywy/branch/master?svg=true)](https://ci.appveyor.com/project/MaidSafe-QA/parsec/branch/master)|[![Stories in Ready](https://badge.waffle.io/maidsafe/parsec.png?label=ready&title=Ready)](https://waffle.io/maidsafe/parsec)|

| [MaidSafe website](https://maidsafe.net) | [SAFE Dev Forum](https://forum.safedev.org) | [SAFE Network Forum](https://safenetforum.org) |
|:----------------------------------------:|:-------------------------------------------:|:----------------------------------------------:|

There is a basic example available in the examples folder.  This allows you to simulate a network of peers each running the Parsec protocol to reach consensus on a number of random network events.  There is also the ability to dump each peer's gossip graph in dot format to a file in your system temp dir.  This can be enabled via the feature `dump-graphs`.  So, e.g. to run the example for a network of five peers and ten network events:

```
cargo run --example=basic --features=dump-graphs -- --peers=5 --events=10
```

To generate SVG graphs from the resulting dot files:

```
dot -Tsvg *.dot -O
```

## License

Licensed under the General Public License (GPL), version 3 ([LICENSE](LICENSE) http://www.gnu.org/licenses/gpl-3.0.en.html).

### Linking exception

Parsec is licensed under GPLv3 with linking exception. This means you can link to and use the library from any program, proprietary or open source; paid or gratis. However, if you modify parsec, you must distribute the source to your modified version under the terms of the GPLv3.

See the [LICENSE](LICENSE) file for more details.
