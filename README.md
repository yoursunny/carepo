# Content Addressable NDN Repository

## Idea

NDN universal caching detects duplicate Data packets only if they have same Name.
If multiple Data packets have same payload but different Names, routers will process them separately.

This project enhances NDN repository to identify same payload using hashes, so that duplicate file segments could be downloaded from nearby repositories instead of crossing the slow network, in order to shorten download completion time.

**Producer**

* publish file segments as Data packets
* publish a metadata that lists hashes of file segments

**Repository**

* index Data packets by Name
* index Data packets by payload of hash

**Consumer**

* fetch metadata, and search local and nearby repositories for Data packets with same payload
* download unfulfilled segments from remote repository

## Build and Usage

Tested platform: Ubuntu 12.04

1. add NDN project PPA <https://launchpad.net/~named-data/+archive/ppa>
2. install necessary packages ``sudo apt-get install build-essential ndn-platform ndnx-dev libcunit1-dev pandoc``
3. obtain NDNx 0.2 source code ``apt-get source ndnx``
4. configure carepo ``./waf configure --unit --markdown --ndnxsrc=/where/is/ndnx-0.2``
5. build carepo ``./waf``

**caput** is the publisher program.
It chunks a file according to Rabin fingerprints, and publishes file segments and metadata into local repository.

**car** is the repository program.
It is an enhanced version of ndnr, and should be used in place of ndnr.
It listens to ``/%C1.R.SHA256`` namespace, and answers hash requests.

**caget** is the consumer program.
Metadata should be fetched and verified using another tool (such as ndngetfile) before invoking caget.
It issues hash requests to find identical segments in nearby repositories, and downloads unfulfilled segments from remote repository.

* Nodes on local area network should run car repository program, so that hash requests could be served.
* Prefix ``/%C1.R.SHA256`` should be forwarded to a multicase group, so that neighbor nodes could receive hash requests.
* Downloaded files should be published into local repository with caput, to be used in serving hash requests.

## Project Reports

**Proposal**: [document](docs/proposal.pdf) [presentation](docs/proposal.pptx)  
**Checkpoint**: [presentation](docs/checkpoint.pptx)  
**Final**: [report](docs/report.pdf) [presentation](docs/final.pptx)
