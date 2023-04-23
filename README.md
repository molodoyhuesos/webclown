# WebClown
This is python implementation of "WebClown" P2P decentralized trust-web protocol.

You can see *"webclown-trust-web-explained.png"* to understand what WebClown is purposed for.



### Protocol visualisation ###
![webclown-trust-web-explained](https://user-images.githubusercontent.com/118081853/233843374-577b5545-771c-4940-9468-74786a421cf9.png)

#### Node IDs are composed from generated public key with SHAKE256 ####
##### TODO: Individual nodes will have "trust factor", which indicates how many nodes know this node and if it's human ran. #####

***

### Connection between nodes visualised ###
![p2p-con](https://user-images.githubusercontent.com/118081853/233844235-c47f0a0b-e9da-4e1b-8307-b57a93472f79.png)

***

# What is it for? #
For me it is just experience. Although SSL and Tox protocols exists, I wanted to create my own, and SSL relies on independent certificate suppliers, and Tox is limited,
WebClown will be universal and secure. The only way to compromise this network is intercepting connection between *"localhost <-> router"*

### Purposes ###
Any kind of things: P2P chats, custom torrent trackers, secure proxies and so on

TODO:
0) Finish README.md with tutorials and docs
1) Build up protocol's networking structure
2) Write WebClown() main class
3) Make docs
4) Run tests
