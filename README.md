# io
Welcome to IO protocol !

This is an Internet Disruptive innovation 

![IO-protocol Main Diagram](./io_diagram.pdf?raw=true)

## Principles 

This protocol works over UDP/IP (datagrams) Port 7800
One can encapsulate it under HTTP(S)

This is a full complete worldwide digital protocol for enonomics exchanges.
It enable to use the new defined **leaf** money between humans only.

The **leaf** is the first free money supply crypto spring.

At any time, the sum of all balances of all registered human is always null.

Any balance if always bounded, like a spring, in a symetric interval [-MAX, +MAX]

The balance is null at registration (birth or adult age) and at death.

No compagny nor administration, nor foundation can have an account, only alive human can.

There is no interest of any kind. You can stay all your life at -10.000 leafs if it is allowed by MAX value.

**Leaf** is a pure money, enabling delay in the past of in the future for dissynchronised exchanges of goods or services between humans. This is not a store of value. **Leaf** really facilitate exchange without side effects like other moneys or crypto-money.

A human being can only have one account. This is verified by a shared public (web) neural network that discriminates people. This is under developpement.

Each account is reachable with a smartphone that store the private cryptographic key. Certifications and transactions are based on crypto-signature (ECDSA or EdDSA) enabled with a strong authentication using three criteria:
- something you carry (smartphone, watch,...)
- something of your body (face analysis, fingerprint,...)
- something you know (PIN, password)

Nobody can pay with your account, even the NSA, unless you give him your phone, your finger and your password ;-)
Nobody can prevent you to pay to the person of your choice

The IO protocal also manages incomes produced by objects/robots.
Those objects may be offline. Give them localy a proof with your phone and you can access to the resource protected by the object. 

This is the protocol for mecanical slavery. Objetcs are working for you directly if you own them.

This solves the problem of capital bad distribution among people in the world, because anyone can invest in robots to get an income from produce wealth.

## Usage

Launch the server in background after checking the port 7800 is open for UDP
```
>python3 ioprotocol.py &
```
The server ip address is returned

On one or several another PCs or smartphones, launch a client with the server address; for instance :

```
>python3 ioprotocol.py 192.168.25.20
```
Then you can generate keys, request for certificate and pay

To simulate a communication with an object, just add the -o option to create this object
```
>python3 ioprotocol.py -o 192.168.25.18
```
The object will automatically send invoices to the phone, that will forward to the server to make the object image.


## Contact

Please, contact me for any question or suggestion on the IO Protocol

You can also try to hack this protocol, you will be rewarded ;-)

