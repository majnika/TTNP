# The Thing Networking Protocol

## The Handshake
### The Handshake describes the process of Establishing a `Connection` between the `Client` and the `Server`

 0 | C-- | S-- |                                   |                                                                    | 
---|-----|-----|-----------------------------------|--------------------------------------------------------------------|
 1 | CHI | S-- |  CHI = Client Handshake Innit     |   - Client initiates conversation 
 2 | C-- | SHI |  SHI = Server Handshake Innit     |   - Server begins the synchronisiation process
 3 | C-- | SDH |  SDH = Server Diffie-Hellman      |   - Server Begins the Diffie-Hellman exhcnage by sending its private key
 4 | CDH | S-- |  CDH = Client Diffie-Hellman      |   - Client responds to the SDH by sending its own private key
 5 | C-- | SCC |  SCC = Server Crypto Check        |   - Server sends encrypted message with the newly generated hash from Diffie-Hellman 
 5 |     |     |                                   |     `TODO` Contents of the message, Maybe a math problem
 6 | CCC | S-- |  CCC = Client Crypto Check        |   - Client responds to the encrypted message \
 6 |     |     |                                   |     `TODO` Contents of the message
 7 | C-- | SHF |  SHF = Server Handshake Finalize  |   - Server ends the synchronisiation process
### __`Connection` is Established__

________________________________________________________________________________________________________________________________________

## The Heartbeat
### The Heartbeat describes the process of keeping the `Connection` active. If the `Server` doesn't recieve a Heartbeat every ${TTL} seconds the connection is Terminated
 0 | C-- | S-- |                                   |                                                                    |
---|-----|-----|-----------------------------------|--------------------------------------------------------------------|           
 1 | CHB | S-- | CHB = Client Heart Beat           | - Client sends Heartbeat packages to renew its connection TTL      |
 2 | C-- | SUU | SUU = Server Understands U        | - Server Understands the Heartbeat, ACK equivalent                 |
### __`Connection` is Renewed__

________________________________________________________________________________________________________________________________________

## The Client Initiated Connection Termination(CICT)
### The CICT describes the process of `Termination` of the `Connection` by the `Client`

 0 | C-- | S-- |                                   |                                                                   |
---|-----|-----|-----------------------------------|-------------------------------------------------------------------|
 1 | CGB | S-- | CGB = Client Good Bye             | - The Client initiates the Connection Termination                 |
 2 | C-- | SGB | SGB = Server Good Bye             | - Server Understands the Good Bye, ACK equivalent                 |
 3 | CFL | S-- | CFL = Client Flat Line            | - Client end the Connection                                       | 
### __`Connection` is `Terminated`__

________________________________________________________________________________________________________________________________________

## The Server Initiated Connection Termination(SICT)
### The SICT describes the process of Terminated of the Connection by the Client. This only occures if the Server does not recieve a Heartbeat on time

 0 | C-- | S-- |                                   |                                                                                     |
---|-----|-----|-----------------------------------|-------------------------------------------------------------------------------------|
 1 | C-- | SFL | SFL = Server Flat Line            | - The Server immediately Terminates the Connection without the need for a Response  |
 1 |     |     |                                   | `TODO` Evaluate if this can be exploited                                        |
### __`Connection` is `Terminated`__
