# OpenRelay: Community-built, Privacy-first VPN
OpenRelay is building the future of VPNs.   

[Join our waitlist](https://openrelay.typedream.app/#first-cta) to get notified when our beta launches, help us test and prioritize features, and contribute to open source development. 

## What
OpenRelay is an experiment in open source, community privacy. 

What would a VPN look like if it was built in the open, created with the community, and designed with strong, verifiable privacy guarantees?

## Why
VPN's are exploding in popularity, with [over 750M mobile downloads in 2021](https://atlasvpn.com/blog/global-vpn-downloads-surge-3x-surpassing-780-million-in-2021). People use them to circumvent government blockades, protect their privacy, and engage in democratic speech online.

Yet most VPN providers use misleading marketing, offer a "just trust us" story on not keeping logs, and don't take privacy seriously. The world doesn't need just another VPN provider. We need a whole new approach to privacy.

## Vision
*Our vision: build the world's largest decentralized network of privacy-enhancing servers.*

We're starting with the VPN use-case. It's a real need that effects a large and growing fraction of humanity who is willing to pay for a solution. We'll use this to bootstrap our community and fund our growth. As we scale, we'll nurture a technical and social community that can organize the internet commons for greater privacy for all.

## How it works
OpenRelay is an attested, two-hop, decentralized routing service. 
- Attested - Servers run open sourced images within trusted execution environments (TEE's) that are third-party attested and independently validated by clients using reproducible builds, validating that IP's are not logged
- Two-hop - Ingress and Egress relays ensure user information (including IP's) stays hidden. Destination information and client information are not on the same machine, providing an extra backstop against malicious hosts
- Decentralized - Servers can be run by community collectives, who are financially rewarded for their contributions. Operator diversity makes it harder to force servers to collude and deanonymize users, while increasing network resiliency

In conjunction with other proven techniques, like diskless (all RAM) operation, in our opinion this design offers the strongest privacy guarantees of any consumer VPN while still remaining performant for real-world use by everyday people. 

<details>
  <summary> Technical Limitations</summary>
  
  As with any real-world solution there are technical limitations. A more complete [threat model is work in progress](#draft-threat-model). Some specific limitations with the attested two-hop design are that the TEE must be trusted, and attestation and reproducible builds only guarantee the TEE packet path is logless, it does not guarantee a malicious host is not performing logging outside of the TEE. However, the two-hop design mitigates the threat of host-level logging. Together with financially incentivized community-run hops, we expect operator diversity to increase which increases the strength of our logging mitigations. Unlike traditional consumer VPN's, as the number of servers and network coverage increases, so does privacy - because of the intrinsically decentralizing incentive strucutre.
  </details>

## How we'll build it
Tactically, we envision splitting the VPN work into three immediate phases. These may adjust as we learn more.

**v1: Attested Enclave**
We'll launch an attested, enclave-based solution with client-driven reproducible builds of server images. This allows us to test enclave performance, attestation, build reproducibility, and the client's ability to validate the server image.

**v2: Attested Two-Hop**
In this phase we add a second hop, allowing us to test enclave-to-enclave network I/O, measure and stabilize the VPN network performance end-to-end, and set out software cut-points for metering and accounting Egress-hop contributions. Support finished for one TEE (likely SGX), other TEE's under investigation (ARM TrustZone, AMD SEV).

**v3: BYOS**
We open up Egress hops to community-run servers. Contribution metering is functional and adversarially resistant. Performance profiling gives community operators a clear answer on acceptable server perf to join the swarm. User privacy benefits from disjoint operation of Ingress and Egress servers.

Far Future: OpenRelay has a network of tens of thousands of distributed servers, unblocking internet access and protecting freedom of speech globally. Future use-cases, like cryptographically attested document-based CDN's (e.g. for OS or game updates, end-to-end encrypted cloud storage, and possibly for distributed-web use-cases), are beginning to be explored. Hybrid approaches between storage and networking unlock new privacy opportunities.

## Principles
Make it fast.
Make it work.
Make it private.

## Contributing
[Think like Grug](https://grugbrain.dev/).

## Who
My name is Bobo, and I'm a [longtime privacy and human rights defender and technologist](https://openrelay.typedream.app/#fndr-intro). I spent the last four years at Facebook, where I worked as a Researcher helping extend internet access to people without connectivity, and on [mass violence prevention from social media abuse](https://about.fb.com/news/2019/06/social-media-and-conflict/). Later, I led Product to extend end-to-end encryption (already on WhatsApp) to an additional ~2B people on Messenger and Instagram Direct. I was directly responsible for privacy assurances from the bottom to the top of the stack, spanning datacenter hardware decisions to adapting product experiences around identity and history.

My work has taken me to Africa and Asia, where I have participated in field research with some of the highest-risk user groups on the internet, including journalists and political dissidents. I have a deep appreciation for privacy and human security, and it is core to what I hope to build at OpenRelay.

*This work is not endorsed by any employer, past or future.*

## FAQ 
<details>
  <summary> Q. Why not just use Tor?</summary>

  
  Tor offers less packet-level flexibility. It does not support UDP, [which increases overhead](https://cypherpunks.ca/~iang/pubs/TorTP.pdf) (TCP over TCP) and makes support for latency-sensitive protocols like VoIP challenging. While [research is ongoing](https://support.torproject.org/alternate-designs/transport-all-ip-packets/), this is a fundamental change that is harder for Tor to experiment with. 
  
  
  Tor also faces unique challenges in supporting [financially incentivized routing](https://blog.torproject.org/two-incentive-designs-tor/). Socially, Tor relay operators organize around a volunteer model, which creates a structure with certain advantages and purity of commitment, but also risks lowering the threshold for nation-state observability, both in terms of low [total number of relays](https://metrics.torproject.org/networksize.html) (~7k) and lack of robust controls for [evicting suspicious nodes (KAX-17)](https://nusenu.medium.com/is-kax17-performing-de-anonymization-attacks-against-tor-users-42e566defce8). Shifting from this model is much more complicated than a technical experiment, as it concerns the motivations and anonymity of relay operators. 

  
  
  This project is free from these constraints. Financial incentivization for contributing bandwidth to the VPN can increase router diversity, total number of servers, and provide sustainability for operations that were previously on a volunteer basis. Notably, identifiable (even pseudonomyously) relay operators, a likely necessity for financial reward, may provide increased security for end-users, and is a direction this project is free to pursue. 

  
  
  Tor is an excellent open source project, and the Tor Browser Bundle and Tails, along with the network, are invaluable assets for privacy protection of the most at-risk users. Tor also sponsors and publishes useful research, including [on incentivized routing](https://blog.torproject.org/tor-incentives-research-roundup-goldstar-par-braids-lira-tears-and-torcoin/), which new projects like this one benefit from. 

  
  
  However, everyday users are overwhelmingly choosing VPN's. In 2021 users made [780 million mobile downloads](https://atlasvpn.com/blog/global-vpn-downloads-surge-3x-surpassing-780-million-in-2021) of VPN apps, while Tor's estimated usage hovers [around 2-3M](https://metrics.torproject.org/userstats-relay-country.html?start=2021-01-01&end=2022-06-30&country=all&events=points). When two orders of magnitude more people are choosing an alternative with questionable privacy properties, it is incumbent on technologists to serve them better. 
  </details>

## Draft Threat Model
This is a work in progress!  
<details>
  <summary> Goals & Non-Goals </summary>
  
  Non-Goal: hide your use of OpenRelay
  
Goal: increase your privacy & freedom

Privacy & Freedom mean you should be able to browse the internet without restriction and without ISP's, advertisers, or Destinations (websites you're accessing) knowing who you are. 

Importantly, OpenRelay should *also* not be able to link you to your Destinations, and should not have any sensitive data on you.

These goals are subject to technical and practical constraints, and OpenRelay makes a number of trade-offs, discussed below.
</details>

<details>
  <summary> High-Level Motivation </summary>
  
  There's three main options to protect your online privacy today:
1. Do nothing  
2. Use a VPN  
3. Use Tor  

Do nothing is the default choice and gives bad privacy. A few people use Tor. Many hundreds of millions choose VPN's for faster speed and easier use. 

But VPN's don't actually solve privacy problems, they just shift them. Instead of trusting your ISP, you trust your VPN.

OpenRelay aims to give the convenience and speed of a VPN solution, while minimizing the trust component. 

It achieves this goal through the use of secure enclaves and remote attestation on the one hand, and financially incentivized routing with a two-hop server design on the other.

Beyond the code and economics, we also nurture a culture that is privacy-respecting, inclusive, and open by design. As a founder I am [fully doxxed](https://openrelay.typedream.app/#fndr-intro) and accountable. 

To give just one reason why this is important, a woman seeking healthcare options without fear of criminal prosecution deserves to know who she's placing her trust in. 
</details>

<details>
  <summary> Q. Does OpenRelay solve all privacy online? </summary>
  
  No, and anybody who tells you they have an "all-in-one" solution is probably untruthful.  
  
  However, in combination with [smart browser settings](https://github.com/arkenfox/user.js/), which are free, OpenRelay significantly increases your privacy.
</details>

<details>
  <summary> Q. Who should use OpenRelay? </summary>
  
  General people who are interested in more privacy online.  

If you believe your name is personally on an authoritarian regime's list, you should consider stronger options like Tor + TorBrowser in combination with Whonix or Qubes. 

iPhone's Lockdown mode is also a good idea, and always use an end-to-end encrypted messenger with disappearing messages turned on (like Signal or WhatsApp).
</details>

<details>
  <summary> Q. What data does OpenRelay have access to? </summary>
  
  _OpenRelay vs VPN's_
  
|         | OpenRelay           | Regular VPN | Description | 
| ------------- |-------------| --- | --- |
| Your IP address      | no* | yes | Provably discarded by OpenRelay. "Just trust us" promise by VPN's. |
| Destination IP address | no* | yes | Provably discarded by OpenRelay. "Just trust us" promise by VPN's. |
| Destination Name | no* | yes | Provably discarded by OpenRelay. "Just trust us" promise by VPN's. |
| Your Email | never | usually | No email required for OpenRelay. |
| Your Password | never | usually | Zero-knowledge authentication with OpenRelay. |
| Your Name | never | usually | Cryptocurrency payments accepted for OpenRelay. |

  What does this asterisk mean? - 
*OpenRelay observes but provably discards this information. Users independently validate that the server provably discards this data given remote attestation and reproducible builds. 

However, since the server *host* runs outside the enclave and cannot be remotely attested, we have to guard against the host maliciously or accidentally logging. We mitigate the threat of a malicious host with the two-hop server design.
  
</details>

<details>
  <summary> Q. How does the two-hop design guard user privacy? </summary>
  
  The first line of defense is the user-verifiable, remotely attested server images. By validating these images with the open source code, users can provably and independently verify that OpenRelay is not logging User IP's or the Destinations users are accessing.  

However, there is always the possibility that a malicious server host - the cloud-server running the OpenRelay software - _does_ try to attack user privacy. For this reason, we use a two-hop server design that splits server jobs into _Ingress_ and _Egress._ It does this to ensure that even a malicious host cannot compromise user privacy.  

The two-hop design separates the User IP from the Destination IP. Ingress servers only see the User IP but not the Destination. Egress servers only see the Destination but not the User IP.  

So long as the Ingress and Egress servers do not collude, the User's privacy is safe. To mitigate collusion, financial incentives for community relay operators increase the number and diversity of relays for Users to choose from. Rotation of relay servers can also help mitigate collusion by minimizing the duration of any possible traffic exposure.
</details>

<details>
  <summary> Q. Why use a TEE like SGX instead of just two-hop TLS? </summary>
  
  Two reasons.

1. There's more data than the packet headers the NIC sees that's important to protect
   - User registration and auth flows: NIC/host don't see this if it goes into the SGX
   - Any data logging (e.g. for perf or diagnostics) is declaratively transparent in the attested code. Users can see exactly what summary statistics really are being collected

2. The cloud provider can get hacked, [as happened with NordVPN and others](https://techcrunch.com/2019/10/21/nordvpn-confirms-it-was-hacked/). Using a TEE provides defense in depth against this scenario.
  </details>

<details>
  <summary> Q. What about relay selection? - Can this be gamed to hurt the client?</summary>
  Egress selection is client-powered and sourced from a trustless, distributed public entity not controlled by OpenRelay or any server operator.  

Egress servers advertise a pubkey on a Blockchain. The Client requires that the handshake with the Egress server authenticates to the pubkey on the Blockchain. This way a malicious Ingress server cannot easily direct a user to a purpose-built colluding Egress node (since all node id's are public).  

Of course, a colluding or malicious Egress node could also advertise on the Blockchain, or even spam lots of Sybil-style advertisements (different pubkeys, same malicious owner) on the Blockchain to increase its odds of being selected.  

To protect against Sybil attacks, we require community operators to stake proportional to the bandwidth they advertise. This imposes a dollar cost on advertising a relay, which helps mitigate Sybil attacks. Additionally, some percentage of stake is used to pay Validators, who perform useful checks on the integrity of the system.  

Advertised bandwidth is tested. If the relay fails to provide it, stake is burnt. This way a relay can't advertise a bunch of non-existent bandwidth to get more clients (as happens in Tor) without losing money.  
</details>

<details>
  <summary> Q. What about backdoors in the software?</summary>
  
  There are two pieces of software that must be validated: server images and client images. Validators test both.  

The strategy is the same in both cases: Validators reproducibly build the target image and check the hash of the resulting binary against the signed hash OpenRelay publishes. Publication takes place on a Blockchain, to provide tamper-proofness and irrepudiation. If OpenRelay attempts to maliciously publish a backdoored server or client image, a Validator can point to the signature on-chain as proof.  

In the server case, a Validator checks the hash of the binary in the SGX-signed and Intel-validated attestation report (this report is called a `quote`) against the hash of the binary they arrive at by following the reproducible build plan.  

If the hashes match, the Validator votes to approve the binary. To vote, Validators must stake a minimal amount of money. Validators who vote with the majority are entitled to rewards garnished from the Relay operators' stakes. Validators who vote against the majority lose their stakes.  

In reality, we may choose a higher percentage than a simple majority. Otherwise, an attacker need only control 50% + 1 vote to win the financial rewards or otherwise harm users (e.g., by falsely marking a good binary as bad, or by falsely marking a bad binary as good).  

This decision carries a tradeoff. Too low a percentage makes attacks easier, while too high a percentage requires a higher bar for flawless Validator operation. A centralized, Community-provided image for Validator nodes may help Validators run more smoothly, but also raises the question of *Quis custodiet ipsos custodes* ("who watches the watchers?"). One possible solution is to have multiple language implementations of the Validator image, maintained by different people with no shared ability to sign releases.  

In the case where the majority of Validators agree that a binary is bad, clients may perform their own reproducible build checks (difficult, especially on thin clients like mobile), request an older known-good image, or fail closed and reject all connections.  

At the end of a voting session, the hash of a validated software image is published to a Blockchain. Users can now poll the chain to validate the SGX-attested code matches the open sourced server image published online (and consumed by the Validators).  

The same process is undertaken for client software and its updates.  

_N.B.: How Validators coordinate a vote and publish the results on-chain is still TBD._
</details>

<details>
  <summary> Q. Do Users have to trust Validators?</summary>
  
  No. Clients can always run their own proofs, and this may be a good option to expose for advanced users.  

Random checking by Users, particularly on thick clients like Desktops, may also help keep the Validator consensus honest.  

At first glance, relying solely on your own proof check may seem dangerous. A client running a check must source the build inputs from somewhere, and if those are served by a malicious OpenRelay server, that malicious server could identify the user's IP as a target and provide compromised input libraries that dutifully enable a reproduced build of a malicious server image.  

Two safeguards mitigate this. First, server (and client) images are signed by OpenRelay and published on-chain. Second, build inputs are hashed and those hashes published on-chain as well. This makes it impossible for a malicious OpenRelay server to target a specific user for backdoor delivery.
</details>

<details>
  <summary> Q. Do Users have to trust OpenRelay?</summary>
  
  No. Users can run their own VPN courtesy of the images provided by OpenRelay.  
  
  This requires self-hosting an OpenRelay server instance with a cloud provider. Users still benefit from the SGX assurances against malicious host actions (tampering with the code) that an untrusted cloud provider (or someone hacking them, [as happened with NordVPN](https://techcrunch.com/2019/10/21/nordvpn-confirms-it-was-hacked/)) may attempt.  

In this case, the self-hosting User acts as their own Validator, similar to a User running in paranoid mode, and performs the reproducible build check for server and client software independently.
</details>
  
<details>
  <summary> Q. What about passwords and login?</summary>
  
  OpenRelay uses OPAQUE authentication to ensure a zero-knowledge authentication of the User's password. This means the User proves they know their password and authenticates without OpenRelay ever seeing the User's password. This makes it impossible for an OpenRelay server to impersonate a User, even under threat of compulsion.  

Additionally, blinded signatures are used to complete authentication. Together with OPAQUE these techniques remove the password as a possible tracking mechanism against the User.  
</details>
    
## References
Lots of interesting work is happening in this area! Here are some cool projects we're learning from that you might be interested in checking out. Pull requests welcome!

---
  
### Production Systems
  
  
**Infra**
  
[Wireguard](https://www.wireguard.com/papers/wireguard.pdf), a kernel virtual network interface intending to replace IPSec and OpenVPN with a more secure, performant solution. Encapsulates in UDP. By Jason A. Donenfeld. [Code here](https://www.wireguard.com/repositories/).
  
[sigstore](https://www.sigstore.dev/), an open source software supply chain security solution. Can be used to validate dependencies or for signing your own software so someone else can validate it as a dependency. 

[tea](https://tea.xyz/), from the maker of `brew`, a blockhain-based system for maintaining package provenance and compensating open source developers. Still in development. 
  
  
**Circumvention VPN's**
  
[Lantern](https://getlantern.org/en_US/index.html), a hybrid p2p + server VPN for unblocking internet access. Servers have [lots of information](https://docs.google.com/spreadsheets/d/1kkmavBvzivKRodlGtCAGgoaS0gcYU8k9fGU0kWACenI/pub?single=true&gid=0&output=html) (email, IP address, name, online/offline status, friends' emails, your geo, shares IP address with Google, etc.). General [Privacy Policy](https://github.com/getlantern/lantern/wiki/Privacy). Does not hide User IP from Destination ("When a website is not blocked, Lantern gets you there faster by directing you to that website directly, without going through Lantern servers" *[Source](https://github.com/getlantern/lantern/wiki/Questions-and-Answers)*). Uses domain fronting and a user-driven trust network of proxies to bridge censorship divides. [Threat Model](https://github.com/getlantern/lantern/wiki/Threat-Model) (incomplete). [Code](https://github.com/getlantern).

[Wireleap Libre Network](https://wireleap.com/blog/libre-launch/), a compensated relay network that is a cross between [a VPN and Tor](https://wireleap.com/), with a focus on net neutrality. Libre is their free, community-run network, launched in 2022. The software can also be used to form paid networks.
  
[Psiphon](https://www.psiphon.ca/), another VPN for unblocking internet access. Employs "some measures" to prevent an adversary from posing as a client to enumerate all access servers. Requires trust in Psiphon server who sees all traffic data. [Code](https://github.com/Psiphon-Inc/psiphon). Started as a [CitizenLab](https://citizenlab.ca/) project.
  
[uProxy](https://github.com/UWNetworksLab/uProxy-p2p), a defunct p2p VPN through webRTC by University of Washington and seeded by Google Jigsaw. [Design Doc](https://docs.google.com/document/d/1t_30vX7RcrEGuWwcg0Jub-HiNI0Ko3kBOyqXgrQN3Kw/edit#). Some of the devs (Brave New Software) went on to work on [Lantern](https://getlantern.org/en_US/index.html).
 
**Privacy VPN's**
  
[VPN⁰](https://brave.com/vpn0-a-privacy-preserving-distributed-virtual-private-network/), a distributed VPN in which all clients are also routers, by Brave and ProtonVPN.

[Nym](https://github.com/nymtech/nym#readme), a mixnet approach to replace Tor around a novel cryptocurrency and associated network.

[Lokinet](https://github.com/oxen-io/lokinet/tree/dev/docs), a distributed onion-router with a cryptocurrency scheme, running on [Oxen](https://oxen.io/who-are-we), a cryptocurrency stack similar to Nym in privacy ambition.

[Orchid Marketplace](https://www.orchid.com/), a multi-hop VPN with a spot marketplace for real-time bandwidth pricing.

[Apple Private Relay](https://support.apple.com/en-us/HT212614), a closed-source, two-hop proxy by Apple for iCloud+ users.
  
[VPN by Google One](https://one.google.com/about/vpn/howitworks), an open-source, IPSec based VPN by Google for Google One users. Primarily targeting security against misconfigured TLS (which remains vulnerable to the "public wifi" problem) as its use-case. Uses blinded signatures to separate authentication from data tunnel session establishment. [Reference code here](https://github.com/google/vpn-libraries).
 
[Bitmask VPN](https://bitmask.net/), an open source VPN client that tries to use SRP to hide passwords from the server

[Tor](https://www.torproject.org/), the "OG" anonymity solution (see also [current work on threat modeling](https://gitlab.torproject.org/tpo/applications/vpn/-/issues/10), both for the browser and an Android VPN client).
  
[Whonix](https://www.whonix.org/), a privacy-focused Linux distribution that uses Tor. Implements [tirdad](https://github.com/Kicksecure/tirdad) TCP ISN randomization, among other hardening procedures. A table comparing Whonix to Tails and Qubes [is available here](https://www.whonix.org/wiki/Comparison_with_Others).

[i2p](https://geti2p.net/en/), "the invisible internet project," a Tor alternative in which all clients are also routers.
  
---
  
### Academic Works
  
**SSL/TLS**
  
[SSL Threat Model](https://www.ssllabs.com/projects/ssl-threat-model/index.html) (no date given), Qualys SSL Labs.
  
[SSL Pulse](https://www.ssllabs.com/ssl-pulse/), Qualys SSL Labs - a monthly scan of security issues in SSL implementations across the top 150k Alexa sites. As of July 2022, only 55% of sites have secure SSL implementations (configuration errors and renegotiation vulnerabilities seem to drive the 45% who are insecure). [Methodology](https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide).

**SGX**
  
[Intel SGX Explained](https://eprint.iacr.org/2016/086) (2016), Costan and Devadas - foundational initial work on SGX.
  
[Security-Enhanced Cloud VPN with SGX and Enclave Migration](https://koasas.kaist.ac.kr/handle/10203/283330) (2019), Park, Jaemin, Dissertation at KAIST - perf of SGX in cloud

[Everything You Should Know about Intel SGX Performance on Virtualized Systems](https://hal.archives-ouvertes.fr/hal-02947792) (2019), Tu et al., SIGMETRICS - optimization strategies (shadow paging)
  
[A Touch of Evil: High-Assurance Cryptographic Hardware from Untrusted Components](https://arxiv.org/abs/1709.03817) (2017), Mavroudis et al., SIGSAC - overcoming malicious hardware suuply-chains by aggregating commercial, off-the-shelf hardware
  
**Anonymous Credentials**
  
[Let's talk about PAKE](https://blog.cryptographyengineering.com/2018/10/19/lets-talk-about-pake/) (2018), Matthew Green - great overview of PAKEs and OPAQUE, a login method that lets servers zero-knowledge verify a user's password
  
[Anon-Pass: Practical Anonymous Subscriptions](https://ieeexplore.ieee.org/document/6547118) (2013), Lee et al., IEEE Symposium on Security and Privacy (S&P)
  
[Nym: Practical Pseudonymity for Anonymous Networks](https://isrl.byu.edu/pubs/isrl-techreport-2006-4.pdf) (2006), Holt and Seamons, Internet Security Research Lab, Brigham Young University - a blinded signature approach to abuse moderation over anonymous networks (no relation to the Nym mixnet, as far as i can tell).
  
**Formal Verification**
  
[Who Builds a House without Drawing Blueprints First?](https://cacm.acm.org/magazines/2015/4/184705-who-builds-a-house-without-drawing-blueprints/fulltext) (2015), Leslie Lamport, Communications of ACM. - Framing of why specification matters for the below article.
  
[How AWS Uses Formal Methods](https://cacm.acm.org/magazines/2015/4/184701-how-amazon-web-services-uses-formal-methods/fulltext) (2015), Newcombe et al, Communications of ACM - Overview of TLA+ use in AWS and its benefits, including design exploration and aggressive perf optimizations that otherwise would be believed unsafe.
  
[Formally Verifying Industry Cryptography](https://www.computer.org/csdl/magazine/sp/2022/03/09733177/1BENJJewLKw) (2022), Mike Dodds, IEEE Security & Privacy. - Engineering approaches to practical use of formal verification methods.
  
[Exploring TLA+ with two-phase commit](https://brooker.co.za/blog/2013/01/20/two-phase.html) (2013), Marc Brooker. - gentle intro to TLA+ via modeling two-phase commit.
  
[Formal Methods Only Solve Half My Problems](https://brooker.co.za/blog/2022/06/02/formal.html) (2022), Marc Brooker. - on the gap between formal verification tools and simulation tools for quantitative distributed systems metrics like network latency and its impact on end-user latency.
  
[Simple Simulations for Model Builders](https://brooker.co.za/blog/2022/04/11/simulation.html) (2022), Marc Brooker. - example of simple simulations to answer distributed network questions.
  

  
**Mixnet Anonymity**
  
[The Loopix Anonymity System](https://arxiv.org/abs/1703.00536) (2017), Piotrowska et al., USENIX - Poisson mixing with server-mediated network access, cover traffic, and self-injected traffic loops to detect active attacks. Message latency is O(seconds).
  
[Anonymity Trilemma: Strong Anonymity, Low Bandwidth Overhead, Low Latency-Choose Two](https://eprint.iacr.org/2017/954.pdf) (2018), Das et al., IEEE Symposium on Security and Privacy (S&P)
  
[Studying the anonymity trilemma with a discrete-event mix network simulator](https://arxiv.org/abs/2107.12172) (2021), Piotrowska, Ania, Workshop on Privacy in the Electronic Society (WPES '21)
  
**Misc but important**
  
[Browser Fingerprinting: An Introduction and the Challenges Ahead](https://blog.torproject.org/browser-fingerprinting-introduction-and-challenges-ahead/) (2019), Laperdix, Pierre., Tor Blog - Introduction with additional references.
